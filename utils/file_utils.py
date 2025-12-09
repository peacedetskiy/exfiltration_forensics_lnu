import hashlib
import magic
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from utils.logger import setup_logger
import pytsk3

try:
    import pyssdeep
except ImportError:
    pyssdeep = None

try:
    import tlsh
except ImportError:
    tlsh = None

logger = setup_logger(log_file="logs/disk.log")

try:
    MAGIC = magic.Magic(mime=True)
except Exception:
    MAGIC = None

_FS_CACHE = {}
MAGIC_DISABLED = False


def hash_file(entry, chunk_size=4 * 1024 * 1024):
    sha256, md5 = hashlib.sha256(), hashlib.md5()
    size = getattr(entry.info.meta, "size", 0) or 0
    offset = 0

    while offset < size:
        to_read = min(chunk_size, size - offset)
        try:
            data = entry.read_random(offset, to_read)
        except Exception:
            break
        if not data:
            break
        sha256.update(data)
        md5.update(data)
        offset += len(data)

    return sha256.hexdigest(), md5.hexdigest()


def _fallback_heuristics(data):
    if data.startswith(b'%PDF'):
        return "application/pdf"
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return "image/png"
    if data.startswith(b'\xff\xd8\xff'):
        return "image/jpeg"
    if data.startswith(b'PK\x03\x04'):
        return "application/zip"
    if data.startswith(b"MZ"):
        return "application/x-dosexec"
    return "application/octet-stream"


def detect_type(entry):
    global MAGIC_DISABLED

    size = getattr(entry.info.meta, "size", 0) or 0
    if size == 0:
        return "inode/x-empty"

    try:
        header = entry.read_random(0, min(4096, size))
    except Exception:
        return "application/octet-stream"

    if not header:
        return "application/octet-stream"

    ntfs = ("$MFT", "$I30", "$SDS", "$Secure", "$Extend", "$ObjId")
    name = entry.info.name.name.decode(errors="ignore")
    for s in ntfs:
        if s in name:
            return "filesystem/ntfs-meta"

    if header.startswith(b"MZ"):
        return "application/x-dosexec"

    if MAGIC_DISABLED or not MAGIC or size > 10 * 1024 * 1024:
        return _fallback_heuristics(header)

    try:
        mime = MAGIC.from_buffer(header)
        if mime:
            return mime
        return _fallback_heuristics(header)
    except Exception:
        MAGIC_DISABLED = True
        return _fallback_heuristics(header)


def _fuzzy_hash_bytes(data):
    if not data:
        return None, None

    ssdeep_val, tlsh_val = None, None
    l = len(data)

    if pyssdeep and l >= 4096:
        try:
            if hasattr(pyssdeep, "get_hash_buffer"):
                ssdeep_val = pyssdeep.get_hash_buffer(data)
            else:
                ssdeep_val = pyssdeep.hash(data)
        except Exception:
            ssdeep_val = None

    if tlsh and l >= 256:
        try:
            if hasattr(tlsh, "Tlsh"):
                h = tlsh.Tlsh()
                h.update(data)
                h.final()
                try:
                    tlsh_val = h.hexdigest()
                except Exception:
                    tlsh_val = h.hash()
            else:
                tlsh_val = tlsh.hash(data)
        except Exception:
            tlsh_val = None

    return ssdeep_val, tlsh_val


def _get_fs_for_worker(image_path, partition_offset):
    key = (image_path, partition_offset)
    if key in _FS_CACHE:
        return _FS_CACHE[key]
    try:
        img = pytsk3.Img_Info(str(image_path))
        fs = pytsk3.FS_Info(img, offset=partition_offset)
        _FS_CACHE[key] = fs
        return fs
    except Exception:
        _FS_CACHE[key] = None
        return None


def hash_file_worker(meta):
    image_path = meta.get("image_path")
    off = meta.get("partition_offset")
    path = meta.get("path")
    size = meta.get("size", 0)
    ftype = meta.get("ftype")

    fs = _get_fs_for_worker(image_path, off)
    if not fs:
        return None

    try:
        entry = fs.open(path)
    except Exception:
        return None

    try:
        sha256, md5 = hash_file(entry)
    except Exception:
        sha256, md5 = None, None

    if not meta.get("fuzzy_required", False):
        return {
            "path": path,
            "size": size,
            "ftype": ftype,
            "sha256": sha256,
            "md5": md5,
            "ssdeep": None,
            "tlsh": None,
            "deleted": meta.get("deleted", False),
            "partition_offset": off,
            "mode": "exact"
        }

    try:
        data = entry.read_random(0, size)
    except Exception:
        data = None

    ssdeep_val, tlsh_val = _fuzzy_hash_bytes(data)

    return {
        "path": path,
        "size": size,
        "ftype": ftype,
        "sha256": sha256,
        "md5": md5,
        "ssdeep": ssdeep_val,
        "tlsh": tlsh_val,
        "deleted": meta.get("deleted", False),
        "partition_offset": off,
        "mode": "full"
    }


def hash_files_parallel(lst, max_workers=4, show_progress=True):
    res = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(hash_file_worker, f): f for f in lst}
        it = tqdm(as_completed(futures), total=len(futures)) if show_progress else as_completed(futures)
        for fut in it:
            try:
                r = fut.result()
                if r:
                    res.append(r)
            except Exception:
                pass
    return res


def extract_matched_files(df, out):
    with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        for _, row in df.iterrows():
            d = row.get('data')
            if d:
                z.writestr(row['path'].lstrip("/"), d)
