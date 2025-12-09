import json
import pytsk3
import pandas as pd
from utils.file_utils import detect_type, _fuzzy_hash_bytes
from disk.registry_parser import extract_usb_artifacts
from tqdm import tqdm
from utils.logger import setup_logger
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = setup_logger(log_file="logs/disk.log")


def open_image(image_path):
    try:
        image = pytsk3.Img_Info(str(image_path))
        volume = pytsk3.Volume_Info(image)
    except Exception as e:
        logger.error(f"Failed to open image {image_path}: {e}")
        raise

    supported_fs = ["NTFS", "FAT", "exFAT", "Linux"]
    partitions = []

    for part in volume:
        try:
            desc_str = part.desc.decode(errors="ignore").strip()
        except Exception:
            continue
        if any(fs in desc_str for fs in supported_fs):
            partitions.append({
                "desc": desc_str,
                "start": part.start,
                "length": part.len,
                "offset": part.start * volume.info.block_size
            })
    return image, partitions


def walk_and_collect(image_path, allowed_types, out_csv, registry_json, fuzzy_required, max_workers=4):
    image, partitions = open_image(image_path)

    files_to_hash = []
    registries, usb_history = [], []

    def walk_files(directory, parent="/", include_deleted=False):
        try:
            entries = list(directory)
        except Exception:
            return
        for entry in entries:
            try:
                name = entry.info.name.name.decode(errors="ignore")
                if name in (".", ".."):
                    continue
                meta = getattr(entry.info, "meta", None)
                if not meta:
                    continue
                is_deleted = bool(meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)
                if include_deleted != is_deleted:
                    continue
                full_path = f"{parent.rstrip('/')}/{name}"
                if is_deleted:
                    full_path += " (deleted)"
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    walk_files(entry.as_directory(), full_path, include_deleted)
                    continue
                if meta.type != pytsk3.TSK_FS_META_TYPE_REG or meta.size <= 0:
                    continue
                fs_type = current_partition["desc"].lower()
                try:
                    usb_devices = extract_usb_artifacts(entry, full_path, fs_type)
                except Exception:
                    usb_devices = []
                if usb_devices:
                    usb_history.extend(usb_devices)
                    registries.append({
                        "path": full_path,
                        "size": meta.size,
                        "filesystem": current_partition["desc"]
                    })
                    continue
                try:
                    file_type = detect_type(entry)
                except Exception:
                    file_type = "application/octet-stream"
                if allowed_types and not any(file_type.startswith(t) for t in allowed_types):
                    continue
                try:
                    data = entry.read_random(0, meta.size) if meta.size > 0 else b""
                except Exception:
                    data = None
                files_to_hash.append({
                    "path": full_path,
                    "size": meta.size,
                    "deleted": is_deleted,
                    "partition_offset": current_partition["offset"],
                    "ftype": file_type,
                    "data": data
                })
            except Exception:
                continue

    for current_partition in partitions:
        try:
            fs = pytsk3.FS_Info(image, offset=current_partition["offset"])
            root = fs.open_dir(path="/")
            walk_files(root, include_deleted=False)
            walk_files(root, include_deleted=True)
        except Exception:
            continue

    logger.info(f"Total files queued for hashing: {len(files_to_hash)}")

    rows = []

    if files_to_hash:
        logger.info(f"Hashing {len(files_to_hash)} files (fuzzy={fuzzy_required})")

        def hash_worker(file_meta):
            data = file_meta["data"]
            sha256_val = hashlib.sha256(data).hexdigest() if data else None
            md5_val = hashlib.md5(data).hexdigest() if data else None
            ssdeep_val, tlsh_val = (None, None)
            if fuzzy_required and data:
                ssdeep_val, tlsh_val = _fuzzy_hash_bytes(data)
            return {
                "path": file_meta["path"],
                "size": file_meta["size"],
                "ftype": file_meta["ftype"],
                "sha256": sha256_val,
                "md5": md5_val,
                "ssdeep": ssdeep_val,
                "tlsh": tlsh_val,
                "deleted": file_meta["deleted"],
                "partition_offset": file_meta["partition_offset"]
            }

        # Generator wrapper for tqdm
        def progress_wrapper(file_list):
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(hash_worker, f): f for f in file_list}
                for future in tqdm(as_completed(futures), total=len(futures), desc="Hashing", unit="files"):
                    try:
                        yield future.result()
                    except Exception:
                        # produce minimal row if hash fails
                        f_meta = futures[future]
                        yield {
                            "path": f_meta["path"],
                            "size": f_meta["size"],
                            "ftype": f_meta["ftype"],
                            "sha256": None,
                            "md5": None,
                            "ssdeep": None,
                            "tlsh": None,
                            "deleted": f_meta["deleted"],
                            "partition_offset": f_meta["partition_offset"]
                        }

        rows = list(progress_wrapper(files_to_hash))

    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)
    with open(registry_json, "w") as f:
        json.dump({"usb_history": usb_history, "registries": registries}, f, indent=2)

    logger.info(f"Hashed {len(rows)} files, saved to {out_csv}")
    return df, registries, usb_history
