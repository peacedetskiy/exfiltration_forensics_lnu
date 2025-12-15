"""
investigation_dns.py

DNS-related helpers for PCAP exfiltration triage.
Uses ML/DL models to detect exfiltration attempts via DNS tunneling.
"""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from tensorflow.keras.models import load_model

from feature_extractor import features_extraction

# Paths to models (adjust if necessary to full paths or config)
LSTM_MODEL_PATH = Path("models/lstm_model.h5")
LGBM_MODEL_PATH = Path("models/lgbm_model.joblib")
PREPROCESSOR_STATELESS_PATH = Path("models/preprocessor_stateless.joblib")
PREPROCESSOR_STATEFUL_PATH = Path("models/preprocessor_stateful.joblib")
LSTM_THRESHOLD_PATH = Path("models/lstm_threshold.joblib")
LGBM_THRESHOLD_PATH = Path("models/lgbm_threshold.joblib")
SUSPICIOUS_MARGIN = 0.15  # ±0.15

# Load models & preprocessors
lstm_model = load_model(LSTM_MODEL_PATH)
with open(LGBM_MODEL_PATH, "rb") as f:
    lgbm_model = joblib.load(f)
with open(PREPROCESSOR_STATELESS_PATH, "rb") as f:
    preproc_stateless = joblib.load(f)
with open(PREPROCESSOR_STATEFUL_PATH, "rb") as f:
    preproc_stateful = joblib.load(f)
with open(LSTM_THRESHOLD_PATH, "rb") as f:
    lstm_threshold = joblib.load(f)
with open(LGBM_THRESHOLD_PATH, "rb") as f:
    lgbm_threshold = joblib.load(f)


def process_dns_packet(pkt, host: str, report: dict, totals: dict):
    """ Process a single packet that has a DNS layer.
    - Basic counting and simple heuristics (e.g., long qname).
    - Updates totals and report in place.
    - ML detection happens in postprocess_dns.
    """
    try:
        dns = pkt.dns
        ip_layer = pkt.ip if hasattr(pkt, "ip") else (pkt.ipv6 if hasattr(pkt, "ipv6") else None)
        src = getattr(ip_layer, "src", None) if ip_layer else None

        if hasattr(dns, "qr") and int(dns.qr) == 0:  # query
            totals["dns_queries"] = totals.get("dns_queries", 0) + 1

            # Simple heuristic for potential tunneling: long qname
            if hasattr(dns, "qname"):
                try:
                    qname = dns.qname.decode('utf-8', errors='ignore').rstrip('.')
                    if len(qname) > 50:  # Adjustable threshold
                        totals["dns_suspected_tunnel"] = totals.get("dns_suspected_tunnel", 0) + 1
                        report.setdefault("suspicious_requests", []).append({
                            "proto": "DNS",
                            "src": src,
                            "dst": getattr(ip_layer, "dst", None),
                            "qname": qname,
                            "note": "Long DNS query name (simple heuristic)"
                        })
                except Exception:
                    pass
    except Exception:
        pass


def encode_timestamp_cyclic(df, timestamp_col='timestamp'):
    def parse_ts(ts_str):
        ts_str = str(ts_str)
        try:
            if '.' in ts_str:
                return pd.to_datetime(ts_str, format='%Y-%m-%d %H:%M:%S.%f')
            else:
                # Add microseconds if missing
                ts_str += '.000000'
                return pd.to_datetime(ts_str, format='%Y-%m-%d %H:%M:%S.%f')
        except Exception as e:
            raise ValueError(f"Failed to parse timestamp '{ts_str}': {e}")

    df[timestamp_col] = df[timestamp_col].apply(parse_ts)
    ts = pd.to_datetime(df[timestamp_col])

    time_features = pd.DataFrame({
        'hour_sin': np.sin(2 * np.pi * ts.dt.hour / 24),
        'hour_cos': np.cos(2 * np.pi * ts.dt.hour / 24),
        'minute_sin': np.sin(2 * np.pi * ts.dt.minute / 60),
        'minute_cos': np.cos(2 * np.pi * ts.dt.minute / 60),
        'second_sin': np.sin(2 * np.pi * ts.dt.second / 60),
        'second_cos': np.cos(2 * np.pi * ts.dt.second / 60),
        'ms_sin': np.sin(2 * np.pi * ts.dt.microsecond / 1_000_000),
        'ms_cos': np.cos(2 * np.pi * ts.dt.microsecond / 1_000_000),
        'dow_sin': np.sin(2 * np.pi * ts.dt.dayofweek / 7),
        'dow_cos': np.cos(2 * np.pi * ts.dt.dayofweek / 7),
        'month_sin': np.sin(2 * np.pi * (ts.dt.month - 1) / 12),
        'month_cos': np.cos(2 * np.pi * (ts.dt.month - 1) / 12),
    })

    df_encoded = df.drop(columns=[timestamp_col])
    df_encoded = pd.concat([df_encoded, time_features], axis=1)

    return df_encoded


def postprocess_dns(original_pcap_path: str, filtered_pcap_path: str, host: str, report: dict, totals: dict):
    print("[*] Running DNS ML-based exfiltration detection (summary only)...")

    # 1. Run feature extraction on the original pcap
    try:
        features_extraction(original_pcap_path)
    except Exception as e:
        report.setdefault("errors", []).append(f"DNS feature extraction failed: {e}")
        return

    pcap_path = Path(original_pcap_path)
    stateless_csv = pcap_path.with_name(f"{pcap_path.stem}_stateless.csv")
    stateful_csv = pcap_path.with_name(f"{pcap_path.stem}_stateful.csv")

    print(f"[DEBUG] Looking for stateless CSV: {stateless_csv}")
    print(f"[DEBUG] Exists? {stateless_csv.exists()}")

    if not stateless_csv.exists():
        print(f"[!] Stateless CSV not found at expected location: {stateless_csv}")
        return

    if not Path(stateless_csv).exists():
        print(f"[!] {stateless_csv} not found")
        return

    df_stateless = pd.read_csv(stateless_csv)
    df_stateful = pd.read_csv(stateful_csv) if Path(stateful_csv).exists() else pd.DataFrame()

    # CRITICAL FIX: longest_word must be string for TargetEncoder / OrdinalEncoder
    if 'longest_word' in df_stateless.columns:
        df_stateless['longest_word'] = df_stateless['longest_word'].astype(str)

    stateful_categorical_features = [
        'rr_type', 'distinct_ip', 'unique_country', 'unique_asn',
        'distinct_domains', 'reverse_dns', 'unique_ttl'
    ]
    for col in stateful_categorical_features:
        if col in df_stateful.columns:
            df_stateful[col] = df_stateful[col].astype(str)
    print(f"[DEBUG] Fixed categorical columns in stateful DF → shape: {df_stateful.shape}")

    # Now do timestamp encoding
    df_stateless = df_stateless.sort_values('timestamp').reset_index(drop=True)
    df_stateless = encode_timestamp_cyclic(df_stateless, 'timestamp')

    if df_stateless.empty:
        print("No stateless features → nothing to analyse")
        return

    print(f"[DEBUG] df_stateless shape: {df_stateless.shape}")
    print(f"[DEBUG] Columns: {list(df_stateless.columns)}")
    print(f"[DEBUG] Any NaN: {df_stateless.isna().any().any()}")
    print(f"[DEBUG] Any inf: {np.isinf(df_stateless.select_dtypes(include=[np.number])).any().any()}")

    # 2. LSTM on stateless features
    try:
        print("[DEBUG] Starting preproc_stateless.transform() ...")
        X_stateless = preproc_stateless.transform(df_stateless)
        print(f"[DEBUG] Transform successful → X_stateless shape: {X_stateless.shape}")
    except Exception as e:
        print(f"[!] preproc_stateless.transform() FAILED: {e}")
        import traceback
        traceback.print_exc()
        return

    try:
        print("[DEBUG] Starting LSTM predict ...")
        lstm_probs = lstm_model.predict(X_stateless, batch_size=64, verbose=0).flatten()
        print(f"[DEBUG] LSTM predict OK → {len(lstm_probs)} probabilities")
    except Exception as e:
        print(f"[!] LSTM predict FAILED: {e}")
        import traceback
        traceback.print_exc()
        return

    # 3. LightGBM on stateful features (if any)
    lgbm_probs = np.array([])
    if not df_stateful.empty:
        print('[DEBUG] Stateful DF is not empty...')

        try:
            print("[DEBUG] Starting preproc_stateful.transform() ...")
            X_stateful = preproc_stateful.transform(df_stateful)
            print(f"[DEBUG] Transform successful → X_stateful shape: {X_stateful.shape}")
        except Exception as e:
            print(f"[!] preproc_stateful.transform() FAILED: {e}")
            import traceback
            traceback.print_exc()
            return

        try:
            print("[DEBUG] Starting LGBM predict ...")
            lgbm_probs = lgbm_model.predict(X_stateful)
            print(f"[DEBUG] LGBM predict OK → {len(lstm_probs)} probabilities")
        except Exception as e:
            print(f"[!] LGBM predict FAILED: {e}")
            import traceback
            traceback.print_exc()
            return

    print(
        f"LSTM probabilities (min/max/mean): {lstm_probs.min():.4f} / {lstm_probs.max():.4f} / {lstm_probs.mean():.4f}")
    print(f"LSTM threshold: {lstm_threshold}")
    print(f"Suspicious range: {lstm_threshold - SUSPICIOUS_MARGIN:.4f} to {lstm_threshold + SUSPICIOUS_MARGIN:.4f}")

    if len(lgbm_probs) > 0:
        print(
            f"LGBM probabilities (min/max/mean): {lgbm_probs.min():.4f} / {lgbm_probs.max():.4f} / {lgbm_probs.mean():.4f}")
        print(f"LGBM threshold: {lgbm_threshold}")

    # 4. Final decision + reporting
    detected = 0
    for i, lstm_prob in enumerate(lstm_probs):
        row = df_stateless.iloc[i]

        # Default values
        classification = "benign"
        in_margin = abs(lstm_prob - lstm_threshold) <= SUSPICIOUS_MARGIN

        if in_margin:
            if len(lgbm_probs) > i:
                final_prob = lgbm_probs[i]
                if final_prob >= lgbm_threshold:
                    classification = "exfiltration"
            else:
                # No LGBM, fall back to LSTM
                if lstm_prob >= lstm_threshold:
                    classification = "exfiltration"
        else:
            if lstm_prob >= lstm_threshold:
                classification = "exfiltration"

        if classification == "exfiltration":
            detected += 1
            record = {
                "proto": "DNS",
                "classification": classification,
                "lstm_probability": round(float(lstm_prob), 4),
                "lgbm_probability": round(float(lgbm_probs[i]), 4) if len(lgbm_probs) > i else None,
                "note": "ML-based DNS exfiltration detection (no packet details)",
                "row_index_in_csv": i
            }
            # Add whatever columns you find useful from the CSV
            for col in ["domain", "src_ip", "subdomain", "entropy", "query_length"]:
                if col in row:
                    record[col] = row[col]

            report.setdefault("suspicious_requests", []).append(record)

    totals["dns_suspected_tunnel"] = detected
    print(f"[+] DNS ML detection finished → {detected} exfiltration flow(s) flagged")
