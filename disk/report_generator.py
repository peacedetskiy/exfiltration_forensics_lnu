import pandas as pd
from tqdm import tqdm
from utils.logger import setup_logger

logger = setup_logger(log_file="logs/disk.log")


def generate_report(matches, usb_history, network_events, output_path="report.txt"):
    try:
        allocated = matches[~matches["deleted"]] if not matches.empty else pd.DataFrame()
        deleted = matches[matches["deleted"]] if not matches.empty else pd.DataFrame()
        num_allocated = len(allocated)
        num_deleted = len(deleted)
        num_network = len(network_events) if network_events else 0
        num_usb = len(usb_history) if usb_history else 0

        logger.info(f"Generating report: {output_path}")
        logger.info(f"Allocated file matches: {num_allocated}, Deleted file matches: {num_deleted}")
        logger.info(f"Network events: {num_network}, USB entries: {num_usb}")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("╔════════════════════════════════════════════════╗\n")
            f.write("║              FORENSIC ANALYSIS REPORT          ║\n")
            f.write("╚════════════════════════════════════════════════╝\n\n")

            # Summary
            f.write("SUMMARY\n")
            f.write("───────────────────────────────\n")
            f.write(f"Matching allocated files : {num_allocated}\n")
            f.write(f"Matching deleted files   : {num_deleted}\n")
            f.write(f"Suspicious network events: {num_network}\n")
            f.write(f"USB history entries      : {num_usb}\n")
            f.write("───────────────────────────────\n\n")

            def write_file_section(df, title):
                f.write(f"{title}\n")
                f.write("───────────────────────────────\n")
                if df.empty:
                    f.write(f"No matching {title.lower()} found.\n\n")
                    logger.debug(f"No entries to report for section: {title}")
                    return
                for _, row in tqdm(df.iterrows(), total=len(df), desc=title, leave=False, colour="green"):
                    try:
                        f.write(f"Path       : {row['path']}\n")
                        f.write(f"Size       : {row['size']} bytes\n")
                        f.write(f"Modified   : {row.get('mtime', 'N/A')}\n")
                        f.write(f"Type       : {row.get('ftype', 'N/A')}\n")
                        f.write(f"SHA256     : {row.get('sha256', 'N/A')}\n")
                        f.write(f"MD5        : {row.get('md5', 'N/A')}\n")
                        if "ssdeep" in row and row["ssdeep"]:
                            f.write(f"SSDEEP     : {row['ssdeep']}\n")
                        if "tlsh" in row and row["tlsh"]:
                            f.write(f"TLSH       : {row['tlsh']}\n")
                        f.write(f"Match Type : {row.get('match_type', 'N/A')}\n")
                        f.write("───────────────────────────────\n")
                    except Exception as e:
                        logger.warning(f"Error writing file entry {row.get('path', 'unknown')}: {e}")
                f.write("\n")

            # Allocated files
            write_file_section(allocated, "ALLOCATED FILE MATCHES")
            # Deleted files
            write_file_section(deleted, "DELETED FILE MATCHES")

            # Network events
            f.write("NETWORK EXFILTRATION MATCHES\n")
            f.write("───────────────────────────────\n")
            if not network_events:
                f.write("No suspicious network events found.\n\n")
                logger.debug("No network events to report")
            else:
                for event in tqdm(network_events, desc="Network events", leave=False, colour="green"):
                    try:
                        f.write(f"Name       : {event.get('name')}\n")
                        f.write(f"Size       : {event.get('size', 'N/A')}\n")
                        f.write(f"SHA256     : {event.get('sha256', 'N/A')}\n")
                        f.write(f"File Type  : {event.get('ftype', 'N/A')}\n")
                        f.write("───────────────────────────────\n")
                    except Exception as e:
                        logger.warning(f"Error writing network event: {e}")
                f.write("\n")

            # USB history
            f.write("USB HISTORY\n")
            f.write("───────────────────────────────\n")
            if not usb_history:
                f.write("No USB activity detected.\n")
                logger.debug("No USB history entries to report")
            else:
                for usb in tqdm(usb_history, desc="USB history", leave=False, colour="green"):
                    try:
                        f.write(f"Device     : {usb.get('device_name')}\n")
                        f.write(f"Instance   : {usb.get('instance')}\n")
                        for k, v in usb.get("values", {}).items():
                            f.write(f"  {k:<20}: {v}\n")
                        f.write("───────────────────────────────\n")
                    except Exception as e:
                        logger.warning(f"Error writing USB entry {usb.get('device_name', 'unknown')}: {e}")

        logger.info(f"Report successfully written to {output_path}")

    except Exception as e:
        logger.error(f"Failed to generate report at {output_path}: {e}")
