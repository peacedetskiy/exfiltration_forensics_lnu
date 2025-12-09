from disk.image_handler import walk_and_collect
from utils.io_utils import read_input_file
from tqdm import tqdm
from utils.logger import setup_logger

logger = setup_logger(log_file="logs/disk.log")


def run_analysis(image_path, file_list_csv, metadata_csv, registry_json, max_workers=8):
    """
    Run disk analysis on the given image using the provided file list.
    Returns:
        - result_df: DataFrame of all scanned files with hashes
        - registries: list of registry artifacts found
        - input_df: original input DataFrame
        - usb_history: list of USB artifacts
        - fuzzy: dict of fuzzy signatures
    """
    try:
        input_df, types, hashes, fuzzy = read_input_file(file_list_csv)
        logger.info(f"Loaded {len(types)} unique file types from input list")
        logger.info(f"Imported {sum(len(v) for v in fuzzy.values())} fuzzy signatures")
    except Exception as e:
        logger.error(f"Failed to read input CSV {file_list_csv}: {e}")
        raise

    # Determine if fuzzy should run
    fuzzy_required = any(len(v) > 0 for v in fuzzy.values())
    if not fuzzy_required:
        logger.info("No fuzzy hashes in input. Fuzzy matching disabled")

    # Walk image and collect metadata + compute hashes
    try:
        result_df, registries, usb_history = walk_and_collect(
            image_path=image_path,
            allowed_types=types,
            fuzzy_required=fuzzy_required,
            out_csv=metadata_csv,
            registry_json=registry_json,
            max_workers=max_workers
        )
        logger.info(f"Completed disk analysis. Metadata saved to {metadata_csv}")
        logger.info(f"Found {len(registries)} registry artifacts")
        logger.info(f"USB artifacts detected: {len(usb_history)}")
    except Exception as e:
        logger.error(f"Failed during disk analysis on image {image_path}: {e}")
        raise

    return result_df, registries, input_df, usb_history, fuzzy
