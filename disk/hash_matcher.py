import pandas as pd
import os
from tqdm import tqdm
from utils.logger import setup_logger

logger = setup_logger(log_file="logs/disk.log")


def match_hashes(input_df, result_df, output_dir, fuzzy=None,
                 ssdeep_threshold=90, tlsh_threshold=50):
    """
    Matches exact and fuzzy hashes between input_df and result_df,
    saves results to CSV, and logs progress.
    """

    # --- Validate required columns ---
    required_cols = {"path", "sha256", "md5"}
    if not required_cols.issubset(result_df.columns) or not required_cols.issubset(input_df.columns):
        logger.error(f"Missing required columns in input or result DataFrames: {required_cols}")
        raise KeyError(f"Missing required columns: {required_cols}")

    # ----------------------------------------------------------------------
    # EXACT HASH MATCHING
    # ----------------------------------------------------------------------
    logger.info("Starting exact hash matching...")

    matches_sha = result_df[result_df["sha256"].isin(input_df["sha256"].dropna())].copy()
    matches_sha["match_type"] = "sha256"

    matches_md5 = result_df[result_df["md5"].isin(input_df["md5"].dropna())].copy()
    matches_md5["match_type"] = "md5"

    matches = pd.concat([matches_sha, matches_md5], ignore_index=True)
    logger.info(f"Exact hash matches found: {len(matches)}")

    # ----------------------------------------------------------------------
    # FUZZY HASH MATCHING
    # ----------------------------------------------------------------------
    fuzzy_results = []

    if fuzzy:

        # =======================
        # SSDEEP MATCHING
        # =======================
        if "ssdeep" in fuzzy and "ssdeep" in result_df.columns:
            try:
                import pyssdeep
                logger.info("Starting SSDEEP fuzzy matching...")

                df_ssdeep = result_df.dropna(subset=["ssdeep"])
                for idx, row in tqdm(df_ssdeep.iterrows(),
                                     total=df_ssdeep.shape[0],
                                     desc="Matching SSDEEP"):
                    for target in fuzzy["ssdeep"]:
                        try:
                            score = pyssdeep.compare(str(row["ssdeep"]), str(target))
                            if score >= ssdeep_threshold:
                                hit = row.copy()
                                hit["match_type"] = f"ssdeep ({score}%)"
                                fuzzy_results.append(hit)
                                logger.debug(f"SSDEEP match: {row['path']} score={score}%")
                        except Exception as e:
                            logger.debug(f"SSDEEP compare error for {row['path']}: {e}")

            except Exception as e:
                logger.warning(f"SSDEEP module error: {e}")

        # =======================
        # TLSH MATCHING
        # =======================
        if "tlsh" in fuzzy and "tlsh" in result_df.columns:
            try:
                import tlsh
                logger.info("Starting TLSH fuzzy matching...")

                df_tlsh = result_df.dropna(subset=["tlsh"])
                for idx, row in tqdm(df_tlsh.iterrows(),
                                     total=df_tlsh.shape[0],
                                     desc="Matching TLSH"):
                    for target in fuzzy["tlsh"]:
                        try:
                            diff = tlsh.diff(str(row["tlsh"]), str(target))
                            if diff != -1 and diff <= tlsh_threshold:
                                hit = row.copy()
                                hit["match_type"] = f"tlsh (diff={diff})"
                                fuzzy_results.append(hit)
                                logger.debug(f"TLSH match: {row['path']} diff={diff}")
                        except Exception as e:
                            logger.debug(f"TLSH compare error for {row['path']}: {e}")

            except Exception as e:
                logger.warning(f"TLSH module error: {e}")

    # ----------------------------------------------------------------------
    # FINAL OUTPUT
    # ----------------------------------------------------------------------
    logger.info(f"Fuzzy matches found: {len(fuzzy_results)}")

    if fuzzy_results:
        matches = pd.concat([matches, pd.DataFrame(fuzzy_results)], ignore_index=True)

    matches = matches.drop_duplicates(subset=["path"])

    os.makedirs(output_dir, exist_ok=True)
    matches_path = os.path.join(output_dir, "matches.csv")

    try:
        matches.to_csv(matches_path, index=False)
        logger.info(f"Saved all matches to {matches_path}")
    except Exception as e:
        logger.error(f"Failed to save matches CSV: {e}")

    return matches
