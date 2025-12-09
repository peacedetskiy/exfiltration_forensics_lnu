import os
import hashlib
import pandas as pd
from tqdm import tqdm
import zipfile
import shutil
from utils.logger import setup_logger

# Fuzzy hash libraries
try:
    import pyssdeep
except Exception:
    pyssdeep = None

try:
    import tlsh
except Exception:
    tlsh = None

from utils.file_utils import detect_type

logger = setup_logger(log_file="logs/disk.log")


def _sha256_md5_from_bytes(data: bytes):
    """Compute SHA256 and MD5 for a bytes buffer."""
    h256 = hashlib.sha256()
    m5 = hashlib.md5()
    h256.update(data)
    m5.update(data)
    return h256.hexdigest(), m5.hexdigest()


def generate_input_from_directory(directory_path):
    """
    Recursively scans a directory, computes SHA256, MD5, and fuzzy hashes (ssdeep, tlsh),
    and returns a DataFrame compatible with read_input_file().
    """
    rows = []
    all_files = []

    # Collect file paths
    for root, _, files in os.walk(directory_path):
        for f in files:
            full_path = os.path.join(root, f)
            all_files.append(full_path)

    logger.info(f"Found {len(all_files)} files in {directory_path}")

    for full_path in tqdm(all_files, desc="Processing files", unit="file", ncols=100):
        try:
            with open(full_path, "rb") as file_obj:
                data = file_obj.read()
        except Exception as e:
            logger.warning(f"Failed to read file {full_path}: {e}")
            continue

        # SHA256 + MD5 (from buffer)
        try:
            sha256, md5 = _sha256_md5_from_bytes(data)
        except Exception as e:
            logger.warning(f"Failed to compute SHA256/MD5 for {full_path}: {e}")
            sha256, md5 = None, None

        # Fuzzy hashes (use robust pyssdeep API)
        ssdeep_val = None
        if pyssdeep and data:
            try:
                # recommended: get_hash_buffer for bytes
                ssdeep_val = pyssdeep.get_hash_buffer(data)
            except Exception as e:
                # try fallback to higher-level wrapper if available
                try:
                    ssdeep_val = pyssdeep.get_hash_buffer(data, "utf-8")
                except Exception:
                    logger.warning(f"Failed to compute SSDEEP for {full_path}: {e}")
                    ssdeep_val = None

        # TLSH
        tlsh_val = None
        if tlsh and data:
            try:
                tlsh_val = tlsh.hash(data)
            except Exception as e:
                logger.warning(f"Failed to compute TLSH for {full_path}: {e}")
                tlsh_val = None

        # File type detection (detect_type should support paths)
        try:
            ftype = detect_type(full_path)
        except Exception:
            ftype = None

        rows.append({
            "path": full_path,
            "sha256": sha256,
            "md5": md5,
            "ssdeep": ssdeep_val,
            "tlsh": tlsh_val,
            "ftype": ftype
        })

        logger.debug(f"Processed file: {full_path}")

    df = pd.DataFrame(rows)
    logger.info(f"Completed hashing {len(df)} files from directory {directory_path}")
    return df


def generate_input_from_zip(zip_path, extract_dir=None):
    """
    Extracts a zip file and computes hashes on its contents.
    """
    if extract_dir is None:
        import tempfile
        extract_dir = tempfile.mkdtemp(prefix="pre_input_extract_")

    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)
    os.makedirs(extract_dir, exist_ok=True)

    logger.info(f"Extracting zip file {zip_path} to {extract_dir}")
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
    except Exception as e:
        logger.error(f"Failed to extract zip {zip_path}: {e}")
        raise

    df = generate_input_from_directory(extract_dir)
    logger.info(f"Generated input DataFrame from zip: {len(df)} files")
    return df

'''exact = generate_input_from_directory('../tests/fulltest/sample_source')
modified = generate_input_from_directory('../tests/fulltest/modified_files')

with open("../tests/fulltest/input.csv", "w") as f:
    # Combine exact and modified DataFrames
    combined_df = pd.concat([exact, modified], ignore_index=True)

    # Remove duplicates if any (based on file path)
    combined_df = combined_df.drop_duplicates(subset=["path"])

    # Save to CSV
    output_csv_path = "../tests/fulltest/input.csv"
    combined_df.to_csv(output_csv_path, index=False, encoding="utf-8")

    logger.info(f"Input CSV generated at {output_csv_path} with {len(combined_df)} files")
'''