import pandas as pd
import glob
import os


def load_and_label(files, label_value):
    dataframes = []

    for file in files:
        print(f"\nLoading file: {file}")
        try:
            df = pd.read_csv(file)

            if df.empty:
                print(" ⚠️ Warning: file is EMPTY, skipping.")
                continue

            # Якщо колонки 'class' немає, додаємо
            if 'class' not in df.columns:
                df['class'] = label_value
            else:
                # Заповнюємо NaN
                df['class'] = df['class'].fillna(label_value)

            print(df.head())  # diagnostic check
            print(f"Rows loaded: {len(df)}")
            dataframes.append(df)

        except Exception as e:
            print(f" ❌ Error loading file {file}: {e}")

    if not dataframes:
        return pd.DataFrame()

    combined_df = pd.concat(dataframes, ignore_index=True)
    return combined_df


def load_category(path_benign, path_malicious):
    print(f"\n=== Loading benign from: {path_benign} ===")
    benign_files = glob.glob(path_benign)
    print("Matched benign:", benign_files)

    print(f"\n=== Loading malicious from: {path_malicious} ===")
    malicious_files = glob.glob(path_malicious)
    print("Matched malicious:", malicious_files)

    benign_df = load_and_label(benign_files, "benign")
    malicious_df = load_and_label(malicious_files, "malicious")

    # Combine only if both not empty
    combined = pd.concat([df for df in [benign_df, malicious_df] if not df.empty], ignore_index=True)

    print("\nCombined set label counts:")
    if 'class' in combined.columns:
        print(combined['class'].value_counts(dropna=False))
    else:
        print("No class column found!")

    return combined


def check_classes(file_path_stateless, file_path_stateful):
    # Load and check stateless
    temp_stateless_df = pd.read_csv(file_path_stateless)
    print("\nStateless class counts:")
    print(temp_stateless_df['class'].value_counts(dropna=False))

    # Load and check stateful
    temp_stateful_df = pd.read_csv(file_path_stateful)
    print("\nStateful class counts:")
    print(temp_stateful_df['class'].value_counts(dropna=False))


stateless_df = load_category(
    "datasets/benign/stateless/*.csv",
    "datasets/malicious/stateless/*.csv"
)

stateful_df = load_category(
    "datasets/benign/stateful/*.csv",
    "datasets/malicious/stateful/*.csv"
)

os.makedirs("datasets/combined", exist_ok=True)

stateless_path = "datasets/combined/final_stateless.csv"
stateful_path = "datasets/combined/final_stateful.csv"

stateless_df.to_csv(stateless_path, index=False)
stateful_df.to_csv(stateful_path, index=False)

print("\n=== FINAL ROW COUNTS ===")
print("Stateless:", stateless_df["class"].value_counts(dropna=False))
print("Stateful:", stateful_df["class"].value_counts(dropna=False))

print("\nSaved:")
print(" →", stateless_path)
print(" →", stateful_path)
