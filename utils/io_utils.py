import pandas as pd


def read_input_file(file_list_csv):
    """
    Reads a CSV containing file hashes, types, and optional fuzzy hashes.
    Returns:
        - df: full DataFrame
        - types: list of unique file types (ftype column)
        - hashes: list of dicts with sha256/md5 for exact matching
        - fuzzy: dict of lists for fuzzy hashes (ssdeep, tlsh)
    """
    df = pd.read_csv(file_list_csv)

    # classical hashes
    hashes = df[["sha256", "md5"]].dropna().to_dict(orient="records") if "sha256" in df.columns else []

    # file types (used for filtering scan results)
    types = df["ftype"].dropna().unique().tolist() if "ftype" in df.columns else []

    # fuzzy hashes
    fuzzy = {}
    if "ssdeep" in df.columns:
        fuzzy["ssdeep"] = df["ssdeep"].dropna().tolist()
    if "tlsh" in df.columns:
        fuzzy["tlsh"] = df["tlsh"].dropna().tolist()

    return df, types, hashes, fuzzy
