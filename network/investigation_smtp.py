"""
investigation_smtp.py

SMTP-related helpers for PCAP exfiltration triage.
Parses SMTP packets (and simple MIME attachments) and attempts to extract attachments
from messages seen in cleartext. Provides an export helper using tshark.
"""

import re
import subprocess
from pathlib import Path
from helpers import decode_hex_string_field, sha256_bytes, ensure_unique_filename


# MIME boundary and filename patterns (simple heuristics)
_boundary_re = re.compile(rb'boundary="?([^";\r\n]+)"?', flags=re.IGNORECASE)
_filename_re = re.compile(r'filename\*?=(?:UTF-8\'\')?"?(?P<f>[^";\r\n]+)"?', flags=re.IGNORECASE)
_content_disp_re = re.compile(rb'Content-Disposition:\s*.*filename', flags=re.IGNORECASE)

try:
    import magic
except Exception:
    magic = None


def get_smtp_raw_data(pkt):
    """Try multiple strategies to obtain raw SMTP message bytes from a pyshark packet."""
    try:
        smtp = pkt.smtp
    except Exception:
        return None

    # 1) look for smtp.data or data-like fields exposed by pyshark
    try:
        for attr in dir(smtp):
            if 'data' in attr or 'line' in attr or 'payload' in attr:
                val = getattr(smtp, attr, None)
                if isinstance(val, str) and val:
                    b = decode_hex_string_field(val)
                    if b:
                        return b
                    # if it's already ascii text
                    try:
                        return val.encode('utf-8', errors='ignore')
                    except Exception:
                        pass
    except Exception:
        pass

    # 2) tcp.payload fallback (many times SMTP content is in TCP payload)
    try:
        if hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload') and getattr(pkt.tcp, 'payload'):
            b = decode_hex_string_field(pkt.tcp.payload)
            if b:
                return b
    except Exception:
        pass

    # 3) highest-layer raw
    try:
        if hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
            b = decode_hex_string_field(pkt.data.data)
            if b:
                return b
    except Exception:
        pass

    return None


def _find_mime_boundary_from_headers(headers_bytes):
    """Try to extract a MIME boundary token from headers bytes."""
    m = _boundary_re.search(headers_bytes)
    if m:
        return m.group(1)
    return None


def split_mime_parts(msg_bytes, boundary):
    """Split a MIME multipart by the boundary token (boundary is bytes, may be with or without leading --)."""
    if not boundary:
        return []
    sep = b'--' + boundary if not boundary.startswith(b'--') else boundary
    parts = msg_bytes.split(sep)
    cleaned = []
    for p in parts:
        p = p.lstrip(b'\r\n')
        if not p or p == b'--':
            continue
        cleaned.append(p)
    return cleaned


def parse_part_headers_and_body(part_bytes):
    """Similar to HTTP helper: return (headers_dict, body_bytes) for a MIME part."""
    sep = b'\r\n\r\n'
    idx = part_bytes.find(sep)
    if idx == -1:
        # fallback to LF-only
        sep2 = b'\n\n'
        idx = part_bytes.find(sep2)
        if idx == -1:
            return {}, part_bytes
        hdr_raw = part_bytes[:idx]
        body = part_bytes[idx + 2:]
    else:
        hdr_raw = part_bytes[:idx]
        body = part_bytes[idx + 4:]
    headers = {}
    try:
        hdr_text = hdr_raw.decode('utf-8', errors='ignore')
        for line in hdr_text.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                headers[k.strip().lower()] = v.strip()
    except Exception:
        pass
    # Trim trailing CRLF
    if body.endswith(b'\r\n'):
        body = body[:-2]
    return headers, body


def extract_attachments_from_smtp_message(msg_bytes, outdir: Path, pkt_info: dict):
    """
    Heuristic extraction of attachments from a raw SMTP message bytes.
    Returns list of saved file dicts (filename, original_filename, size, sha256, filetype, saved_path, pkt).
    """
    saved = []

    if not msg_bytes:
        return saved

    # Try to find overall headers end
    hdr_end = msg_bytes.find(b'\r\n\r\n')
    if hdr_end == -1:
        # maybe no headers => try to search for Content-Disposition patterns
        if _content_disp_re.search(msg_bytes):
            # fallback: attempt to find filename pattern in the whole blob
            try:
                txt = msg_bytes.decode('utf-8', errors='ignore')
                m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";\r\n]+)"?', txt, flags=re.IGNORECASE)
                if m:
                    fname = m.group(1)
                    # attempt to find the chunk after header
                    # naive: take last \r\n\r\n and treat remainder as file
                    tail = msg_bytes.split(b'\r\n\r\n')[-1]
                    target = ensure_unique_filename(outdir, fname)
                    try:
                        target.write_bytes(tail)
                        sha = sha256_bytes(tail)
                        ftype = magic.from_buffer(tail) if magic else None
                        saved.append({
                            "filename": target.name,
                            "original_filename": fname,
                            "size": len(tail),
                            "sha256": sha,
                            "filetype": ftype,
                            "saved_path": str(target),
                            "pkt": pkt_info
                        })
                    except Exception:
                        pass
            except Exception:
                pass
        return saved

    headers = msg_bytes[:hdr_end]
    body = msg_bytes[hdr_end + 4:]

    # Try to detect boundary in headers
    boundary = _find_mime_boundary_from_headers(headers)
    if boundary:
        # ensure bytes
        if isinstance(boundary, str):
            boundary = boundary.encode('utf-8', errors='ignore')
        parts = split_mime_parts(body, boundary)
        for part in parts:
            phdrs, pbody = parse_part_headers_and_body(part)
            # check for filename in Content-Disposition or content-type name param
            fname = None
            cd = phdrs.get('content-disposition') or phdrs.get('content-disposition'.lower())
            if cd:
                try:
                    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";\r\n]+)"?', cd, flags=re.IGNORECASE)
                    if m:
                        fname = m.group(1)
                except Exception:
                    pass
            if not fname:
                ctype = phdrs.get('content-type') or phdrs.get('content-type'.lower())
                if ctype:
                    try:
                        m2 = re.search(r'name="?([^";\r\n]+)"?', ctype)
                        if m2:
                            fname = m2.group(1)
                    except Exception:
                        pass

            # If part looks like an attached file (has filename or binary-ish), save it
            if fname or (b'Content-Transfer-Encoding:' in part and b'base64' in part.lower()):
                # If base64-encoded, attempt to decode; otherwise save raw bytes
                payload = pbody
                # try to trim possible boundary trailer
                payload = payload.strip(b'\r\n')
                # If it contains many ASCII base64 chars and '=' padding, decode
                try:
                    txt = payload.decode('utf-8', errors='ignore').strip()
                    # heuristic: base64 characters and padding
                    if re.fullmatch(r'[A-Za-z0-9+/=\s\r\n]+', txt) and len(txt) > 100:
                        import base64
                        try:
                            decoded = base64.b64decode(''.join(txt.splitlines()), validate=False)
                            if decoded:
                                payload = decoded
                        except Exception:
                            pass
                except Exception:
                    pass

                if not fname:
                    # fallback filename
                    fname = f"smtp_attach_{sha256_bytes(payload)[:8]}.bin"

                target = ensure_unique_filename(outdir, fname)
                try:
                    target.write_bytes(payload)
                    sha = sha256_bytes(payload)
                    ftype = None
                    if magic:
                        try:
                            ftype = magic.from_buffer(payload)
                        except Exception:
                            ftype = None
                    rec = {
                        "filename": target.name,
                        "original_filename": fname,
                        "size": len(payload),
                        "sha256": sha,
                        "filetype": ftype,
                        "saved_path": str(target),
                        "pkt": pkt_info
                    }
                    saved.append(rec)
                except Exception:
                    pass
    else:
        # No boundary — attempt to detect inline attachments via filename in overall body
        try:
            txt = msg_bytes.decode('utf-8', errors='ignore')
            m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";\r\n]+)"?', txt, flags=re.IGNORECASE)
            if m:
                fname = m.group(1)
                # try to get trailing bytes after the filename header
                tail = msg_bytes.split(m.group(0).encode('utf-8'))[-1]
                tail = tail.strip(b'\r\n')
                if tail:
                    target = ensure_unique_filename(outdir, fname)
                    try:
                        target.write_bytes(tail)
                        sha = sha256_bytes(tail)
                        ftype = magic.from_buffer(tail) if magic else None
                        saved.append({
                            "filename": target.name,
                            "original_filename": fname,
                            "size": len(tail),
                            "sha256": sha,
                            "filetype": ftype,
                            "saved_path": str(target),
                            "pkt": pkt_info
                        })
                    except Exception:
                        pass
        except Exception:
            pass

    return saved


def process_smtp_packet(pkt, host: str, smtp_objects_outdir: Path, report: dict, totals: dict, saved_files: list):
    """
    Process a single packet with SMTP layer:
     - Try to detect MAIL/RCPT sequence and message sizes.
     - Attempt to extract attachments from message data and save to smtp_objects_outdir.
     - Update totals and append to report['suspicious_requests'] where heuristics match.
    """
    try:
        smtp = pkt.smtp
    except Exception:
        return

    # Collect simple meta
    ip_layer = None
    if hasattr(pkt, 'ip'):
        ip_layer = pkt.ip
    elif hasattr(pkt, 'ipv6'):
        ip_layer = pkt.ipv6

    try:
        src = ip_layer.src if ip_layer else None
        dst = ip_layer.dst if ip_layer else None
    except Exception:
        src = None
        dst = None

    # Count SMTP frames
    totals["smtp_frames"] = totals.get("smtp_frames", 0) + 1

    # attempt to detect a DATA block (end with CRLF.CRLF or \r\n.\r\n)
    msg_bytes = None
    try:
        msg_bytes = get_smtp_raw_data(pkt)
    except Exception:
        msg_bytes = None

    # Heuristic: detect MAIL FROM/RCPT TO in textual SMTP lines (pyshark may expose command fields)
    try:
        if hasattr(smtp, 'command'):
            cmd = str(getattr(smtp, 'command') or '').upper()
            if cmd.startswith('MAIL') and src == host:
                totals["smtp_mail_from"] = totals.get("smtp_mail_from", 0) + 1
            if cmd.startswith('RCPT') and src == host:
                totals["smtp_rcpt_to"] = totals.get("smtp_rcpt_to", 0) + 1
    except Exception:
        pass

    # If we have a message payload, try to extract attachments
    try:
        if msg_bytes:
            pkt_info = {"src": src, "dst": dst, "proto": "SMTP"}
            new_saved = extract_attachments_from_smtp_message(msg_bytes, smtp_objects_outdir, pkt_info)
            if new_saved:
                saved_files.extend(new_saved)
                totals["smtp_attachments_saved"] = totals.get("smtp_attachments_saved", 0) + len(new_saved)
                for rec in new_saved:
                    report.setdefault("suspicious_requests", []).append({
                        "proto": "SMTP",
                        "src": src,
                        "dst": dst,
                        "filename": rec.get("original_filename") or rec.get("filename"),
                        "saved_as": rec.get("filename"),
                        "note": "Saved attachment extracted from SMTP message"
                    })
            else:
                # Detect large message body (heuristic)
                try:
                    if src == host and len(msg_bytes) > 5 * 1024 * 1024:
                        report.setdefault("suspicious_requests", []).append({
                            "proto": "SMTP",
                            "src": src,
                            "dst": dst,
                            "size": len(msg_bytes),
                            "note": "Large SMTP message body from host"
                        })
                except Exception:
                    pass
    except Exception:
        pass


def export_smtp_objects_from_pcap(pcap_path, outdir):
    """Use tshark to export SMTP objects (if supported)."""
    cmd = ["tshark", "-r", pcap_path, "--export-objects", f"smtp,{outdir}", '-q']
    subprocess.run(cmd, check=True)
