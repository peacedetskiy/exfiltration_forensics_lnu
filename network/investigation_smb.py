import subprocess

try:
    import magic
except Exception as e:
    print("SMB: Exception while importing magic library: ", e)
    pass


def process_smb_packet(pkt, host, report, totals, large_upload_threshold_bytes):
    """ Process a single packet that has an SMB or SMB2 layer.
    - Detects CREATE/WRITE commands from the host, potentially indicating uploads.
    - Updates "totals", report in place.
    - Note: File extraction is handled by tshark. Here only suspicious commands are flagged. """
    try:
        ip_layer = pkt.ip if hasattr(pkt, 'ip') else (pkt.ipv6 if hasattr(pkt, 'ipv6') else None)
        src = getattr(ip_layer, 'src', None)
        dst = getattr(ip_layer, 'dst', None)
    except Exception as exc:
        print('SMB: Exception while getting source and destination IP addresses: ', exc)
        src = None
        dst = None

    if src != host:
        return  # Only interested in uploads from host

    fname = None
    command = None
    proto = None
    data_len = 0

    try:
        if hasattr(pkt, 'smb'):
            proto = 'SMB'
            smb = pkt.smb
            cmd = getattr(smb, 'cmd', None)
            if cmd == '0xa2':  # NT_CREATE_ANDX
                command = 'NT_CREATE_ANDX'
                if hasattr(smb, 'nt_create_andx_filename'):
                    fname = str(smb.nt_create_andx_filename).strip()
            elif cmd == '0x2f':  # WRITE_ANDX
                command = 'WRITE_ANDX'
                if hasattr(smb, 'file_name'):
                    fname = str(smb.file_name).strip()
                if hasattr(smb, 'data_len'):
                    data_len = int(getattr(smb, 'data_len', 0))

        elif hasattr(pkt, 'smb2'):
            proto = 'SMB2'
            smb2 = pkt.smb2
            cmd = getattr(smb2, 'cmd', None)
            if cmd == '5':  # Create
                command = 'CREATE'
                if hasattr(smb2, 'filename'):
                    fname = str(smb2.filename).strip()
            elif cmd == '9':  # Write
                command = 'WRITE'
                if hasattr(smb2, 'write_length'):
                    data_len = int(getattr(smb2, 'write_length', 0))

        if command:
            totals['smb_write_create'] = totals.get('smb_write_create', 0) + 1
            note = f'{proto} file upload command ({command}) from host'
            if fname:
                note += f' filename: {fname}'
            rec = {
                'proto': proto,
                'command': command,
                'src': src,
                'dst': dst,
                'filename': fname,
                'note': note
            }
            if data_len >= large_upload_threshold_bytes:
                rec['content_length'] = data_len
                rec['note'] += '; Large write'
            report['suspicious_requests'].append(rec)

    except Exception as exc:
        print('SMB: Exception while processing SMB packet: ', exc)
        pass


def export_smb_objects_from_pcap(pcap_path, output_directory):
    """ Export SMB/SMB2 objects using tshark's internal extraction mechanism. """
    cmd = ['tshark', '-r', pcap_path, '--export-objects', f'smb,{output_directory}', '-q']
    subprocess.run(cmd, check=True, capture_output=True)
