import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.patches import Patch
from sklearn.preprocessing import StandardScaler, LabelEncoder, TargetEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score, roc_curve, accuracy_score
from keras import models, layers
import lightgbm as lgb
from ctgan import CTGAN


df_stateless = pd.read_csv('datasets/combined/final_stateless.csv')
df_stateful = pd.read_csv('datasets/combined/final_stateful.csv')

df_stateless = df_stateless.drop_duplicates()
df_stateful = df_stateful.drop_duplicates()

df_stateless.dropna()
df_stateful.dropna()


def plot_columns_numval_type(dataframe):
    """ Visualization: number of each column's values by type (color). """
    non_null_counts = dataframe.notnull().sum()
    # Determine colors based on dtype
    colors = []
    for col in dataframe.columns:
        dtype = dataframe[col].dtype
        if pd.api.types.is_numeric_dtype(dtype):
            colors.append('blue')
        elif isinstance(dtype, pd.CategoricalDtype) or dtype == 'object':
            colors.append('orange')
        else:
            colors.append('gray')  # Other types
    plt.figure(figsize=(12, 6))
    plt.bar(non_null_counts.index, non_null_counts.values, color=colors, edgecolor='black')
    plt.xticks(rotation=90)
    plt.title("Non-null Values per Column (Colored by Type)")
    plt.xlabel("Column")
    plt.ylabel("Count")
    # Add legend
    legend_elements = [
        Patch(facecolor='blue', edgecolor='black', label='Numeric'),
        Patch(facecolor='orange', edgecolor='black', label='Categorical'),
        Patch(facecolor='gray', edgecolor='black', label='Other'),
    ]
    plt.legend(handles=legend_elements)
    plt.tight_layout()
    plt.show()


plot_columns_numval_type(df_stateless)
plot_columns_numval_type(df_stateful)

# Defining features groups (stateless features)
stateless_numerical_features = [
    'FQDN_count', 'subdomain_length', 'upper', 'lower', 'numeric', 'entropy',
    'special', 'labels', 'labels_max', 'labels_average', 'len', 'subdomain'
]
stateless_categorical_features = ['longest_word', 'sld']

# Defining features groups (stateful features)
stateful_numerical_features = [
    'rr', 'A_frequency', 'NS_frequency', 'CNAME_frequency', 'SOA_frequency', 'NULL_frequency',
    'PTR_frequency', 'HINFO_frequency', 'MX_frequency', 'TXT_frequency', 'AAAA_frequency',
    'SRV_frequency', 'OPT_frequency', 'rr_count', 'rr_name_entropy', 'rr_name_length', 'distinct_ns',
    'a_records', 'ttl_mean', 'ttl_variance'
]
stateful_categorical_features = [
    'rr_type', 'distinct_ip', 'unique_country', 'unique_asn',
    'distinct_domains', 'reverse_dns', 'unique_ttl'
]


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


# Soring by time and time encoding in stateless dataset
df_stateless = df_stateless.sort_values('timestamp').reset_index(drop=True)
df_stateless = encode_timestamp_cyclic(df_stateless, 'timestamp')

# Encoding target "class" feature - Malicious=1, Benign=0 - for stateless
le_stateless = LabelEncoder()
df_stateless['class'] = le_stateless.fit_transform(df_stateless['class'])  # Malicious=1, Benign=0

# Encoding target "class" feature - Malicious=1, Benign=0 - for stateful
le_stateful = LabelEncoder()
df_stateful['class'] = le_stateful.fit_transform(df_stateful['class'])

# Drop target "class" feature
X_stateless = df_stateless.drop('class', axis=1)
y_stateless = df_stateless['class']

X_stateful = df_stateful.drop('class', axis=1)
y_stateful = df_stateful['class']

# Encoding categorical features and normalizing numerical features
preprocessor_stateless = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), stateless_numerical_features),
        ('cat', TargetEncoder(smooth=20), stateless_categorical_features)
    ],
    remainder='passthrough'  # in case you have any other numeric/binary features
)

preprocessor_stateful = ColumnTransformer(
    transformers=[
        ('num', StandardScaler(), stateful_numerical_features),
        ('cat', TargetEncoder(smooth=20), stateful_categorical_features)
    ],
    remainder='passthrough'
)

# Fit and transform features
X_stateless_scaled = preprocessor_stateless.fit_transform(X_stateless, y_stateless)
X_stateful_scaled = preprocessor_stateful.fit_transform(X_stateful, y_stateful)

# Split dataset (1/3 of 30% -> 10% test)
X_train_s, X_temp_s, y_train_s, y_temp_s = train_test_split(X_stateless_scaled, y_stateless,
                                    test_size=0.3, stratify=y_stateless)
X_val_s, X_test_s, y_val_s, y_test_s = train_test_split(X_temp_s, y_temp_s,
                                    test_size=1/3, stratify=y_temp_s)

X_train_f, X_temp_f, y_train_f, y_temp_f = train_test_split(X_stateful_scaled, y_stateful,
                                    test_size=0.4, random_state=42, shuffle=True, stratify=y_stateful)
X_val_f, X_test_f, y_val_f, y_test_f = train_test_split(X_temp_f, y_temp_f,
                                    test_size=1/2, random_state=42, shuffle=True, stratify=y_temp_f)

print("Stateless:")
print("Train:", np.bincount(y_train_s))
print("Val:", np.bincount(y_val_s))
print("Test:", np.bincount(y_test_s))

print("\nStateful:")
print("Train:", np.bincount(y_train_f))
print("Val:", np.bincount(y_val_f))
print("Test:", np.bincount(y_test_f))

# =========================================
# 1. LSTM on stateless features
# =========================================

# Reshape stateless features for LSTM
X_train_s = X_train_s.reshape((X_train_s.shape[0], X_train_s.shape[1], 1))
X_val_s   = X_val_s.reshape((X_val_s.shape[0], X_val_s.shape[1], 1))
X_test_s  = X_test_s.reshape((X_test_s.shape[0], X_test_s.shape[1], 1))

lstm_model = models.Sequential([
    layers.Input(shape=(X_train_s.shape[1], 1)),
    layers.LSTM(64, return_sequences=False),
    layers.Dropout(0.2),
    layers.Dense(32, activation='relu'),
    layers.Dense(1, activation='sigmoid')
])

lstm_model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Train LSTM
history = lstm_model.fit(
    X_train_s, y_train_s,
    validation_data=(X_val_s, y_val_s),
    epochs=10,
    batch_size=256,
    verbose=1
)

# LSTM model learning line-chart

# Loss
plt.subplot(1,2,1)
plt.plot(history.history['loss'], label='Train Loss')
plt.plot(history.history['val_loss'], label='Val Loss')
plt.title("LSTM Loss per Epoch")
plt.xlabel("Epoch")
plt.ylabel("Loss")
plt.grid(True, alpha=0.3)
plt.legend()

# Accuracy
plt.subplot(1,2,2)
plt.plot(history.history['accuracy'], label='Train Acc')
plt.plot(history.history['val_accuracy'], label='Val Acc')
plt.title("LSTM Accuracy per Epoch")
plt.xlabel("Epoch")
plt.ylabel("Accuracy")
plt.grid(True, alpha=0.3)
plt.legend()

plt.show()

# LSTM predictions
y_train_pred_lstm = lstm_model.predict(X_train_s).flatten()
y_val_pred_lstm = lstm_model.predict(X_val_s).flatten()
y_test_pred_lstm = lstm_model.predict(X_test_s).flatten()

# Youden's J threshold computation
fpr, tpr, thresholds = roc_curve(y_val_s, y_val_pred_lstm)
youden_j = tpr - fpr
best_idx = youden_j.argmax()
best_thr_lstm: float = thresholds[best_idx]

print(f"\nYouden's J threshold: {best_thr_lstm:.6f}")
print(f"TPR: {tpr[best_idx]:.6f}, FPR: {fpr[best_idx]:.6f}, J={youden_j[best_idx]:.6f}")

# Convert predictions to binary labels
y_test_bin = (y_test_pred_lstm >= best_thr_lstm).astype(int)

# LSTM Evaluation
test_loss, test_acc = lstm_model.evaluate(X_test_s, y_test_s, verbose=1)
print("Test Accuracy:", test_acc)
print("Test Loss:", test_loss)

# Classification report
print(classification_report(y_test_s, y_test_bin))

# ROC Curve + AUC
auc = roc_auc_score(y_test_s, y_test_pred_lstm)
print("ROC-AUC:", auc)

# Confusion matrix
cm = confusion_matrix(y_test_s, y_test_bin)
tn, fp, fn, tp = cm.ravel()

print("TP:", tp)
print("FP:", fp)
print("FN:", fn)
print("TN:", tn)

plt.figure(figsize=(6,4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Pred 0","Pred 1"],
            yticklabels=["True 0","True 1"])
plt.title("Confusion Matrix")
plt.show()

# ROC curve with Youden point
plt.figure(figsize=(6,6))
plt.plot(fpr, tpr, label=f"ROC (AUC={auc:.6f})")
plt.scatter(fpr[best_idx], tpr[best_idx], color="red",
            label=f"Youden Thr={best_thr_lstm:.4f}", zorder=10)
plt.plot([0,1],[0,1],"--", linewidth=0.7)
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve (Validation)")
plt.legend()
plt.grid(alpha=0.3)
plt.show()

# =========================================
# 2. CTGAN synthetic data for LightGBM
# =========================================

# Re-create the training DataFrame (with proper column names)
X_train_f = pd.DataFrame(X_train_f, columns=X_stateful.columns).reset_index(drop=True)
y_train_f_series = pd.Series(y_train_f, name='class').reset_index(drop=True)
df_train_full = pd.concat([X_train_f, y_train_f_series], axis=1)

# Train CTGAN only on REAL malicious samples (from training set)
malicious_df = df_train_full[df_train_full['class'] == 1].drop(columns=['class'])
print(f"\nReal malicious samples (used for CTGAN training): {len(malicious_df):,}")

ctgan = CTGAN(
    epochs=300,
    batch_size=500,
    generator_dim=(128, 128),
    discriminator_dim=(128, 128),
    verbose=False  # no epoch logs
)

ctgan.fit(malicious_df)

# Generate all synthetic malicious samples at once
N_SYNTH_TRAIN = 40_000   # for training
N_SYNTH_VAL   = 10_000   # for validation
N_SYNTH_TEST  = 10_000   # for test
TOTAL_SYNTH   = N_SYNTH_TRAIN + N_SYNTH_VAL + N_SYNTH_TEST

print(f"Generating {TOTAL_SYNTH:,} synthetic malicious samples...")
synthetic_all = ctgan.sample(TOTAL_SYNTH)
synthetic_all['class'] = 1
print(f"Generated {len(synthetic_all):,} synthetic samples")

# Split the synthetic data into three parts
synthetic_train = synthetic_all.iloc[:N_SYNTH_TRAIN].copy()
synthetic_val = synthetic_all.iloc[N_SYNTH_TRAIN:N_SYNTH_TRAIN + N_SYNTH_VAL].copy()
synthetic_test = synthetic_all.iloc[N_SYNTH_TRAIN + N_SYNTH_VAL:].copy()

# Prepare original splits as proper DataFrames

# Validation
X_val_f = pd.DataFrame(X_val_f,   columns=X_stateful.columns).reset_index(drop=True)
y_val_f = pd.Series(y_val_f,   name='class').reset_index(drop=True)
df_val = pd.concat([X_val_f, y_val_f], axis=1)

# Test
X_test_f = pd.DataFrame(X_test_f,  columns=X_stateful.columns).reset_index(drop=True)
y_test_f = pd.Series(y_test_f,  name='class').reset_index(drop=True)
df_test = pd.concat([X_test_f, y_test_f], axis=1)

# Training (original real data)
normal_df   = df_train_full[df_train_full['class'] == 0]
real_mal_df = df_train_full[df_train_full['class'] == 1]

# Build final augmented datasets

# Training set
df_train_aug = pd.concat([
    normal_df,          # all real benign
    real_mal_df,        # all real malicious (from train)
    synthetic_train     # +40k synthetic malicious
], ignore_index=True)

df_train_aug = df_train_aug.sample(frac=1, random_state=42).reset_index(drop=True)

# Validation set
df_val_aug = pd.concat([
    df_val,             # original validation (benign + malicious)
    synthetic_val       # +10k synthetic malicious
], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

# Test set
df_test_aug = pd.concat([
    df_test,            # original test
    synthetic_test      # +10k synthetic malicious
], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)

# Split X/y for LightGBM
X_train_aug = df_train_aug.drop(columns=['class'])
y_train_aug = df_train_aug['class']

X_val_aug   = df_val_aug.drop(columns=['class'])
y_val_aug   = df_val_aug['class']

X_test_aug  = df_test_aug.drop(columns=['class'])
y_test_aug  = df_test_aug['class']

# Quick sanity check
print("\n=== Final dataset sizes ===")
print(f"Training   : {len(X_train_aug):,} samples → class dist:\n{y_train_aug.value_counts().sort_index()}")
print(f"Validation : {len(X_val_aug):,} samples → class dist:\n{y_val_aug.value_counts().sort_index()}")
print(f"Test       : {len(X_test_aug):,} samples → class dist:\n{y_test_aug.value_counts().sort_index()}")

# =========================================
# 3. LightGBM on stateful features
# =========================================

lgb_train = lgb.Dataset(X_train_aug, label=y_train_aug)
lgb_val = lgb.Dataset(X_val_aug, label=y_val_aug, reference=lgb_train)

pos_count = y_train_aug.value_counts().get(1, 0)
neg_count = y_train_aug.value_counts().get(0, 0)

scale_pos_weight = neg_count / pos_count
print("scale_pos_weight =", scale_pos_weight)

params = {
    "objective": "binary",
    "metric": "auc",
    "boosting_type": "gbdt",

    # imbalance handling
    "is_unbalance": False,  # we manually set weights instead
    "scale_pos_weight": scale_pos_weight,  # <-- critical

    # tree parameters
    "num_leaves": 256,
    "max_depth": -1,
    "min_data_in_leaf": 50,
    "min_child_weight": 1e-3,

    # randomness & bagging
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 5,

    # regularization
    "lambda_l1": 0.8,
    "lambda_l2": 0.8,

    # optimization
    "learning_rate": 0.001,
    "num_boost_round": 2000,
    "force_row_wise": True,
    "min_gain_to_split": 0.01,

    "verbose": -1
}

evals_result = {}

lgb_model = lgb.train(
    params,
    lgb_train,
    valid_sets=[lgb_train, lgb_val],
    valid_names=['train', 'val'],
    num_boost_round=2000,
    callbacks=[
        lgb.early_stopping(stopping_rounds=100),
        lgb.log_evaluation(period=50),
        lgb.record_evaluation(evals_result)
    ]
)

# Extract recorded metrics
train_auc = evals_result['train']['auc']
val_auc = evals_result['val']['auc']

# Plot learning curves
plt.figure(figsize=(8,5))
plt.plot(train_auc, label='Train AUC')
plt.plot(val_auc, label='Validation AUC')
plt.xlabel('Boosting Iterations')
plt.ylabel('AUC')
plt.title('LightGBM Learning Curve (AUC per iteration)')
plt.legend()
plt.grid(True)
plt.show()

# LightGBM predictions
y_train_pred_lgb = lgb_model.predict(X_train_aug)
y_val_pred_lgb = lgb_model.predict(X_val_aug)
y_test_pred_lgb = lgb_model.predict(X_test_aug)

# Youden's J threshold computation
fpr_lgb, tpr_lgb, thr_lgb = roc_curve(y_val_aug, y_val_pred_lgb)
youden_j_lgb = tpr_lgb - fpr_lgb
best_idx_lgb = youden_j_lgb.argmax()
best_thr_lgb = thr_lgb[best_idx_lgb]

print(f"LightGBM Youden Threshold: {best_thr_lgb:.6f}")

# Convert predictions to binary labels
y_test_bin_lgb = (y_test_pred_lgb >= best_thr_lgb).astype(int)

# Accuracy
test_acc_lgb = accuracy_score(y_test_aug, y_test_bin_lgb)
print("LightGBM Test Accuracy:", test_acc_lgb)

# Classification report
print("\nLightGBM Classification Report:")
print(classification_report(y_test_aug, y_test_bin_lgb))

# ROC-AUC
auc_lgb = roc_auc_score(y_test_aug, y_test_pred_lgb)
print("LightGBM ROC-AUC:", auc_lgb)

# Confusion matrix
cm_lgb = confusion_matrix(y_test_aug, y_test_bin_lgb)
tn, fp, fn, tp = cm_lgb.ravel()

print("\nTP:", tp)
print("FP:", fp)
print("FN:", fn)
print("TN:", tn)

plt.figure(figsize=(6,4))
sns.heatmap(
    cm_lgb,
    annot=True,
    fmt="d",
    cmap="Greens",
    xticklabels=["Pred 0", "Pred 1"],
    yticklabels=["True 0", "True 1"]
)
plt.title("LightGBM Confusion Matrix (Youden Threshold)")
plt.show()

# ROC curve with Youden point
plt.figure(figsize=(6,6))
plt.plot(fpr_lgb, tpr_lgb, label=f"ROC (AUC={auc_lgb:.6f})")
plt.scatter(
    fpr_lgb[best_idx_lgb], tpr_lgb[best_idx_lgb],
    color="red", label=f"Youden Thr={best_thr_lgb:.4f}", zorder=10
)
plt.plot([0,1],[0,1],"--", color="gray")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("LightGBM ROC Curve")
plt.legend()
plt.grid(alpha=0.3)
plt.show()

# =========================================
# 4. Saving pretrained models and preprocessors
# =========================================

# Save LSTM model
lstm_model.save("models/lstm_model.h5")
# Save stateless preprocessor
joblib.dump(preprocessor_stateless, "models/preprocessor_stateless.joblib")
# Save LSTM threshold
joblib.dump(best_thr_lstm, "models/lstm_threshold.joblib")

# Save LightGBM model
joblib.dump(lgb_model, "models/lgbm_model.joblib")
# Save stateful preprocessor
joblib.dump(preprocessor_stateful, "models/preprocessor_stateful.joblib")
# Save LightGBM threshold
joblib.dump(best_thr_lgb, "models/lgbm_threshold.joblib")

# Save CTGAN
ctgan.save("models/ctgan_stateful.joblib")
