import argparse
import subprocess
import time
import tempfile
import os
import sys
import pandas as pd

from disk.input_handler import run_analysis, read_input_file
from disk.pre_input_handler import generate_input_from_directory, generate_input_from_zip
from disk.network_handler import analyze_pcap
from disk.hash_matcher import match_hashes
from disk.report_generator import generate_report
from utils.file_utils import extract_matched_files
from utils.logger import setup_logger
import config  # <-- import config.py


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Detect potential data exfiltration from disk image and network capture."
    )
    parser.add_argument("-i", "--image", default=config.IMAGE_PATH, help="Path to the disk image (.dd or .img)")
    parser.add_argument("-f", "--file-list", default=config.FILE_LIST, help="Path to CSV file containing target file list")
    parser.add_argument("-m", "--metadata-csv", default=config.METADATA_CSV, help="Output path for file metadata CSV")
    parser.add_argument("-r", "--registry-json", default=config.REGISTRY_JSON, help="Output path for registry JSON file")
    parser.add_argument("-p", "--pcap", default=config.PCAP_PATH, help="Path to network traffic capture (.pcapng)")
    parser.add_argument("-n", "--network-report-dir", default=config.NETWORK_REPORT_DIR, help="Directory for network analysis output")
    parser.add_argument("-s", "--src-ip", default=config.SRC_IP, help="Source IP address of the suspected machine")
    parser.add_argument("-o", "--report-path", default=config.REPORT_PATH, help="Path to final text report")
    parser.add_argument("-d", "--matches-dir", default=config.MATCHES_DIR, help="Directory to store hash match results")
    parser.add_argument("-z", "--extracted-zip", default=config.EXTRACTED_ZIP, help="Path of zipped extracted files")
    parser.add_argument("--pre-input-dir", default=config.PRE_INPUT_DIR, help="Directory containing files to compute hashes for pre-input")
    parser.add_argument("--pre-input-zip", default=config.PRE_INPUT_ZIP, help="Zip file containing files to compute hashes for pre-input")
    return parser.parse_args()


def main():
    logger = setup_logger(log_file="logs/disk.log")
    args = parse_arguments()
    start_time = time.time()
    temp_csv_path = None

    try:
        # Prepare input_df
        if args.pre_input_dir:
            logger.info(f"Generating pre-input from directory: {args.pre_input_dir}")
            input_df = generate_input_from_directory(args.pre_input_dir)
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
            temp_csv_path = tf.name
            tf.close()
            input_df.to_csv(temp_csv_path, index=False)
            file_list_path = temp_csv_path

        elif args.pre_input_zip:
            logger.info(f"Generating pre-input from zip: {args.pre_input_zip}")
            input_df = generate_input_from_zip(args.pre_input_zip)
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
            temp_csv_path = tf.name
            tf.close()
            input_df.to_csv(temp_csv_path, index=False)
            file_list_path = temp_csv_path

        else:
            file_list_path = args.file_list
            try:
                input_df, _, _, _ = read_input_file(file_list_path)
            except Exception as e:
                logger.error(f"Failed to read input CSV {file_list_path}: {e}")
                sys.exit(1)

        fuzzy = {
            k: input_df[k].dropna().tolist() if k in input_df.columns else []
            for k in ["ssdeep", "tlsh"]
        }

        logger.info(f"Loaded input CSV with {len(input_df)} files")
        logger.info(f"Found {sum(len(v) for v in fuzzy.values())} fuzzy signatures")

        # Disk image analysis
        logger.info("Analyzing disk image...")
        t0 = time.time()
        result_df, registries, input_df_from_run, usb_history, fuzzy_from_run = run_analysis(
            args.image,
            file_list_path,
            args.metadata_csv,
            args.registry_json
        )
        t1 = time.time()
        logger.info(f"Disk analysis completed in {t1 - t0:.2f}s: {len(result_df)} files, {len(registries)} registry hives")

        if fuzzy_from_run:
            fuzzy = fuzzy_from_run

        # Prepare target hashes for network analysis
        target_hashes = set()
        for col in ["sha256", "md5"]:
            if col in input_df.columns:
                target_hashes.update(input_df[col].dropna())
        for values in fuzzy.values():
            target_hashes.update(values)

        # Network analysis
        network_matches = []
        if args.pcap and os.path.exists(args.pcap):
            logger.info("Performing network analysis...")
            t2 = time.time()
            subprocess.run([
                "python",
                "../network/network_exfiltration/pcap_exfiltration.py",
                "-p", args.pcap,
                "-t", args.src_ip,
                "-o", args.network_report_dir
            ], capture_output=True, text=True)

            network_matches = analyze_pcap(args.network_report_dir, target_hashes)
            t3 = time.time()
            logger.info(f"Network analysis completed in {t3 - t2:.2f}s: {len(network_matches)} matches found")
        else:
            logger.info("No network traffic provided or file not found. Skipping network analysis.")

        # Hash matching
        logger.info("Matching hashes...")
        t4 = time.time()
        if not result_df.empty:
            matches = match_hashes(input_df, result_df, args.matches_dir, fuzzy)
        else:
            logger.warning("No files collected from disk image. Skipping hash matching.")
            matches = pd.DataFrame(columns=["path", "sha256", "md5", "ssdeep", "tlsh", "sdhash", "match_type",
                                            "ftype", "size", "deleted"])
        t5 = time.time()

        exact_matches = matches["match_type"].isin(["sha256", "md5"]).sum()
        fuzzy_matches = len(matches) - exact_matches
        logger.info(f"Hash matching completed in {t5 - t4:.2f}s: {exact_matches} exact, {fuzzy_matches} fuzzy")

        # Report
        generate_report(matches, usb_history, network_matches, args.report_path)
        logger.info(f"Report generated: {args.report_path}")

        # Extract matched files
        if args.extracted_zip:
            extract_matched_files(matches, args.extracted_zip)
            logger.info(f"Extracted {len(matches)} files to {args.extracted_zip}")

        logger.info(f"Total analysis time: {time.time() - start_time:.2f}s")

    finally:
        if temp_csv_path and os.path.exists(temp_csv_path):
            try:
                os.remove(temp_csv_path)
            except Exception as e:
                logger.warning(f"Failed to remove temporary CSV {temp_csv_path}: {e}")


if __name__ == "__main__":
    main()
