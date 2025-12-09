import re
import csv
import os
from utils.logger import setup_logger

logger = setup_logger(log_file="logs/disk.log")


def analyze_pcap(pcap_dir, target_hashes):
    """
    Parses the pcap_exfiltration.py output CSV and returns a list of entries
    that match the target hashes.
    """
    matches = []
    results = []

    pcap_file = os.path.join(pcap_dir, "exfil_report.csv")
    if not os.path.exists(pcap_file):
        logger.warning(f"PCAP report file not found: {pcap_file}")
        return matches

    logger.info(f"Analyzing PCAP report: {pcap_file} for {len(target_hashes)} target hashes")

    try:
        with open(pcap_file, "r", encoding="utf-8") as file:
            reader = csv.reader(file)
            for row in reader:
                if not row or len(row) < 3 or row[0] != "ParsedFile":
                    continue

                filename = row[1].strip()
                metadata = row[2]

                sha_match = re.search(r"sha256=([a-fA-F0-9]{64})", metadata)
                size_match = re.search(r"(\d+)\s+bytes", metadata)
                type_match = re.search(r"type=([\w\d\-_.]+)", metadata)

                sha256 = sha_match.group(1) if sha_match else None
                size = int(size_match.group(1)) if size_match else None
                ftype = type_match.group(1) if type_match and type_match.group(1) != "None" else None

                entry = {
                    "name": filename,
                    "size": size,
                    "sha256": sha256,
                    "md5": None,
                    "ftype": ftype
                }

                results.append(entry)

                if sha256 and sha256 in target_hashes:
                    matches.append(entry)
                    logger.info(f"Network match found: {filename} ({sha256})")

    except Exception as e:
        logger.error(f"Failed to analyze PCAP report {pcap_file}: {e}")

    logger.info(f"Finished network analysis. {len(matches)} matches found out of {len(results)} parsed entries")
    return matches
