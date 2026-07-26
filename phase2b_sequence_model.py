# ==========================================
# PHASE 2B: SEQUENCE-AWARE ANOMALY DETECTION (GRU NEXT-STEP PREDICTOR)
# ==========================================
# OPTIONAL enhancement layer. Run this AFTER phase2_core_ml.py has produced
# data/scored_events.csv, iso_forest.joblib, xgboost.joblib.
#
# SAFETY GUARANTEE: this script does NOT modify or overwrite anything from
# phase1/phase2/phase3/phase4. It only ever writes NEW files, suffixed
# "_v2" or "sequence_*", and ONLY if the validation gate below passes.
# If the gate fails, nothing is written at all and your existing pipeline
# is left completely untouched.
#
# New dependency: pip install torch

import os
import sys
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
import xgboost as xgb

try:
    from google.colab import drive
    drive.mount('/content/drive')
    DATA_DIR = '/content/drive/MyDrive/Anomaly_Detection_Data'
except ImportError:
    DATA_DIR = './data'

# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
WINDOW = 9                  # context length (predict the 10th event)
BATCH_SIZE = 256
EPOCHS = 20
HIDDEN_DIM = 64
RES_EMBED_DIM = 8
AUTH_EMBED_DIM = 4
LEARNING_RATE = 1e-3
NUMERIC_LOSS_WEIGHT = 0.5    # keeps the categorical (ordering) signal from being drowned out
PASS_THRESHOLD_PCT = 3.0     # scrambled loss must exceed real loss by at least this % to pass
MIN_VAL_WINDOWS = 50         # below this, the gate result isn't statistically trustworthy

BASE_FEATURE_COLS = ['hour_deviation', 'session_duration_zscore', 'is_new_device', 'is_new_geo',
                     'geo_velocity', 'recent_failed_auth_count', 'has_privileged_command']

torch.manual_seed(42)
np.random.seed(42)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

# ------------------------------------------------------------------
# 1. Load Phase 2's output
# ------------------------------------------------------------------
print("Loading scored_events.csv (output of phase2_core_ml.py)...")
events_path = os.path.join(DATA_DIR, 'scored_events.csv')
events_df = pd.read_csv(events_path)
events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
events_df = events_df.sort_values(['entity_id', 'timestamp']).reset_index(drop=True)

events_df['resource_accessed'] = events_df['resource_accessed'].fillna('Unknown').astype(str)
events_df['auth_method'] = events_df['auth_method'].fillna('unknown').astype(str)

resource_encoder = LabelEncoder()
auth_encoder = LabelEncoder()
events_df['resource_idx'] = resource_encoder.fit_transform(events_df['resource_accessed'])
events_df['auth_idx'] = auth_encoder.fit_transform(events_df['auth_method'])

NUM_RESOURCES = len(resource_encoder.classes_)
NUM_AUTH = len(auth_encoder.classes_)
NUM_NUMERIC = len(BASE_FEATURE_COLS)

# ------------------------------------------------------------------
# 2. Entity-level split FIRST (so the numeric scaler + validation gate
#    never see val-entity data during "training" of any kind)
# ------------------------------------------------------------------
unique_entities = events_df['entity_id'].unique().tolist()
train_entities, val_entities = train_test_split(unique_entities, test_size=0.2, random_state=42)
train_entities, val_entities = set(train_entities), set(val_entities)

# Fit the numeric scaler ONLY on training-entity normal rows. This is purely
# an internal conditioning step for the GRU's numeric inputs/targets --
# it does NOT change the original feature_cols used by Isolation Forest/XGBoost.
scaler_fit_mask = (
    events_df['entity_id'].isin(train_entities) &
    events_df['label'].isin(['normal', 'insider_drift'])
)
scaler = StandardScaler()
scaler.fit(events_df.loc[scaler_fit_mask, BASE_FEATURE_COLS])

numeric_arr_full = scaler.transform(events_df[BASE_FEATURE_COLS]).astype(np.float32)
resource_arr_full = events_df['resource_idx'].to_numpy(dtype=np.int64)
auth_arr_full = events_df['auth_idx'].to_numpy(dtype=np.int64)
label_arr_full = events_df['label'].to_numpy()

# ------------------------------------------------------------------
# 3. Build sliding windows PER ENTITY (no cross-entity leakage)
# ------------------------------------------------------------------
def build_windows(df, window=WINDOW):
    windows = []
    for eid, group in df.groupby('entity_id', sort=False):
        group = group.sort_values('timestamp')
        idx = group.index.to_numpy()
        n = len(idx)
        if n <= window:
            continue
        for start in range(n - window):
            ctx_positions = idx[start:start + window]
            target_position = idx[start + window]

            is_normal = bool(
                np.all(np.isin(label_arr_full[ctx_positions], ['normal', 'insider_drift'])) and
                (label_arr_full[target_position] in ['normal', 'insider_drift'])
            )

            windows.append({
                'ctx_resource': resource_arr_full[ctx_positions],
                'ctx_auth': auth_arr_full[ctx_positions],
                'ctx_numeric': numeric_arr_full[ctx_positions],
                'target_resource': int(resource_arr_full[target_position]),
                'target_auth': int(auth_arr_full[target_position]),
                'target_numeric': numeric_arr_full[target_position],
                'entity_id': eid,
                'target_row_index': int(target_position),
                'is_normal_window': is_normal
            })
    return windows

print("Building sliding windows (this may take a moment)...")
all_windows = build_windows(events_df, WINDOW)
print(f"Total windows built: {len(all_windows)}")

normal_windows = [w for w in all_windows if w['is_normal_window']]
train_windows = [w for w in normal_windows if w['entity_id'] in train_entities]
val_windows = [w for w in normal_windows if w['entity_id'] in val_entities]
print(f"Normal-only windows -> Train: {len(train_windows)} | Validation: {len(val_windows)}")

if len(train_windows) < 500 or len(val_windows) < MIN_VAL_WINDOWS:
    print("\nNot enough normal windows to train/validate a sequence model reliably.")
    print("Aborting -- no files written. Your existing pipeline is untouched.")
    sys.exit(0)

# ------------------------------------------------------------------
# 4. Dataset / Model
# ------------------------------------------------------------------
class WindowDataset(Dataset):
    def __init__(self, windows):
        self.windows = windows

    def __len__(self):
        return len(self.windows)

    def __getitem__(self, i):
        w = self.windows[i]
        return (
            torch.tensor(w['ctx_resource'], dtype=torch.long),
            torch.tensor(w['ctx_auth'], dtype=torch.long),
            torch.tensor(w['ctx_numeric'], dtype=torch.float32),
            torch.tensor(w['target_resource'], dtype=torch.long),
            torch.tensor(w['target_auth'], dtype=torch.long),
            torch.tensor(w['target_numeric'], dtype=torch.float32),
        )


class SequencePredictor(nn.Module):
    """Predicts the NEXT event's resource, auth method, and numeric feature
    vector from the preceding WINDOW events. Next-step prediction (not
    reconstruction) is used deliberately: a reconstruction autoencoder can
    minimize its loss by copying magnitudes and ignoring order entirely --
    next-step prediction cannot, because the target is never in the input."""

    def __init__(self, num_resources, num_auth, num_numeric,
                 res_dim=RES_EMBED_DIM, auth_dim=AUTH_EMBED_DIM, hidden_dim=HIDDEN_DIM):
        super().__init__()
        self.resource_embed = nn.Embedding(num_resources, res_dim)
        self.auth_embed = nn.Embedding(num_auth, auth_dim)
        input_dim = res_dim + auth_dim + num_numeric
        self.gru = nn.GRU(input_dim, hidden_dim, batch_first=True)
        self.resource_head = nn.Linear(hidden_dim, num_resources)
        self.auth_head = nn.Linear(hidden_dim, num_auth)
        self.numeric_head = nn.Linear(hidden_dim, num_numeric)

    def forward(self, ctx_resource, ctx_auth, ctx_numeric):
        r_emb = self.resource_embed(ctx_resource)
        a_emb = self.auth_embed(ctx_auth)
        x = torch.cat([r_emb, a_emb, ctx_numeric], dim=-1)
        _, h_n = self.gru(x)
        h = h_n[-1]
        return self.resource_head(h), self.auth_head(h), self.numeric_head(h)


model = SequencePredictor(NUM_RESOURCES, NUM_AUTH, NUM_NUMERIC).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
ce_loss_mean = nn.CrossEntropyLoss()          # for training (batch-mean, needed for backward())
mse_loss_mean = nn.MSELoss()
ce_loss_none = nn.CrossEntropyLoss(reduction='none')   # for scoring (per-sample, for ae_error)
mse_loss_none = nn.MSELoss(reduction='none')

train_loader = DataLoader(WindowDataset(train_windows), batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(WindowDataset(val_windows), batch_size=BATCH_SIZE, shuffle=False)


def training_loss(ctx_resource, ctx_auth, ctx_numeric, target_resource, target_auth, target_numeric):
    res_logits, auth_logits, numeric_pred = model(ctx_resource, ctx_auth, ctx_numeric)
    loss_res = ce_loss_mean(res_logits, target_resource)
    loss_auth = ce_loss_mean(auth_logits, target_auth)
    loss_num = mse_loss_mean(numeric_pred, target_numeric)
    return loss_res + loss_auth + NUMERIC_LOSS_WEIGHT * loss_num


print(f"\nTraining GRU Next-Step Predictor for {EPOCHS} epochs on {device}...")
for epoch in range(1, EPOCHS + 1):
    model.train()
    running = 0.0
    for ctx_r, ctx_a, ctx_n, tgt_r, tgt_a, tgt_n in train_loader:
        ctx_r, ctx_a, ctx_n = ctx_r.to(device), ctx_a.to(device), ctx_n.to(device)
        tgt_r, tgt_a, tgt_n = tgt_r.to(device), tgt_a.to(device), tgt_n.to(device)

        optimizer.zero_grad()
        loss = training_loss(ctx_r, ctx_a, ctx_n, tgt_r, tgt_a, tgt_n)
        loss.backward()
        optimizer.step()
        running += loss.item() * ctx_r.size(0)
    train_epoch_loss = running / len(train_windows)

    model.eval()
    running = 0.0
    with torch.no_grad():
        for ctx_r, ctx_a, ctx_n, tgt_r, tgt_a, tgt_n in val_loader:
            ctx_r, ctx_a, ctx_n = ctx_r.to(device), ctx_a.to(device), ctx_n.to(device)
            tgt_r, tgt_a, tgt_n = tgt_r.to(device), tgt_a.to(device), tgt_n.to(device)
            loss = training_loss(ctx_r, ctx_a, ctx_n, tgt_r, tgt_a, tgt_n)
            running += loss.item() * ctx_r.size(0)
    val_epoch_loss = running / len(val_windows)

    print(f"Epoch {epoch:2d}/{EPOCHS} | Train Loss: {train_epoch_loss:.4f} | Val Loss: {val_epoch_loss:.4f}")

# ------------------------------------------------------------------
# 5. Per-sample scoring function (used by both the validation gate
#    and the full-dataset ae_error computation below)
# ------------------------------------------------------------------
def per_sample_loss(windows, scramble=False, seed=42, batch_size=256):
    """Returns one loss value per window. If scramble=True, the CONTEXT
    order (the 9 input steps) is independently shuffled per window before
    scoring -- the target is untouched. A model that ignores order will
    score scrambled windows about the same as real ones; a model that
    learned order will score them noticeably worse."""
    rng = np.random.RandomState(seed)
    model.eval()
    losses = np.zeros(len(windows), dtype=np.float64)

    with torch.no_grad():
        for start in range(0, len(windows), batch_size):
            batch = windows[start:start + batch_size]

            ctx_res_list, ctx_auth_list, ctx_num_list = [], [], []
            for w in batch:
                cr, ca, cn = w['ctx_resource'], w['ctx_auth'], w['ctx_numeric']
                if scramble:
                    perm = rng.permutation(len(cr))
                    cr, ca, cn = cr[perm], ca[perm], cn[perm]
                ctx_res_list.append(cr)
                ctx_auth_list.append(ca)
                ctx_num_list.append(cn)

            ctx_res = torch.tensor(np.stack(ctx_res_list), dtype=torch.long).to(device)
            ctx_auth = torch.tensor(np.stack(ctx_auth_list), dtype=torch.long).to(device)
            ctx_num = torch.tensor(np.stack(ctx_num_list), dtype=torch.float32).to(device)
            tgt_res = torch.tensor([w['target_resource'] for w in batch], dtype=torch.long).to(device)
            tgt_auth = torch.tensor([w['target_auth'] for w in batch], dtype=torch.long).to(device)
            tgt_num = torch.tensor(np.stack([w['target_numeric'] for w in batch]), dtype=torch.float32).to(device)

            res_logits, auth_logits, numeric_pred = model(ctx_res, ctx_auth, ctx_num)
            loss_res = ce_loss_none(res_logits, tgt_res)
            loss_auth = ce_loss_none(auth_logits, tgt_auth)
            loss_num = mse_loss_none(numeric_pred, tgt_num).mean(dim=1)
            total = (loss_res + loss_auth + NUMERIC_LOSS_WEIGHT * loss_num).cpu().numpy()

            losses[start:start + len(batch)] = total
    return losses

# ------------------------------------------------------------------
# 6. VALIDATION GATE: real vs. scrambled sequence test
# ------------------------------------------------------------------
print("\n--- Running Real-vs-Scrambled Validation Gate ---")

real_losses = per_sample_loss(val_windows, scramble=False)
scrambled_losses = per_sample_loss(val_windows, scramble=True)

real_mean, real_p95 = real_losses.mean(), np.percentile(real_losses, 95)
scrambled_mean, scrambled_p95 = scrambled_losses.mean(), np.percentile(scrambled_losses, 95)
pct_increase = ((scrambled_mean - real_mean) / real_mean) * 100 if real_mean > 0 else 0.0

print(f"Real sequences      -> Mean Loss: {real_mean:.4f} | 95th Percentile: {real_p95:.4f}")
print(f"Scrambled sequences -> Mean Loss: {scrambled_mean:.4f} | 95th Percentile: {scrambled_p95:.4f}")
print(f"Scrambling increased prediction error by {pct_increase:.1f}%")

if pct_increase < PASS_THRESHOLD_PCT:
    print(f"\n[FAIL] The model does not rely meaningfully on event order "
          f"(needed >= {PASS_THRESHOLD_PCT:.0f}% increase, got {pct_increase:.1f}%).")
    print("Aborting -- no files written. iso_forest.joblib, xgboost.joblib, and")
    print("scored_events.csv are completely untouched. Your existing pipeline still works exactly as before.")
    sys.exit(0)

print(f"\n[PASS] Scrambling degraded prediction accuracy by {pct_increase:.1f}%. "
      f"The model has learned genuine temporal ordering, not just feature magnitudes.")

# ------------------------------------------------------------------
# 7. Only reached if the gate passed. Compute ae_error for EVERY event
#    (all labels, not just normal -- this is the anomaly signal at inference).
# ------------------------------------------------------------------
print("\nComputing ae_error for all events (batched, this should take under a minute)...")

ae_error = np.full(len(events_df), np.nan, dtype=np.float64)
full_losses = per_sample_loss(all_windows, scramble=False)
for w, loss_val in zip(all_windows, full_losses):
    ae_error[w['target_row_index']] = loss_val

events_df['ae_error'] = ae_error

# Cold-start fallback for events with fewer than WINDOW prior events for
# their entity: use the peer-group (entity_type) mean, matching the same
# cold-start convention phase2_core_ml.py already uses for hour_deviation
# and session_duration_zscore.
peer_group_mean_ae = events_df.groupby('entity_type')['ae_error'].transform('mean')
events_df['ae_error'] = events_df['ae_error'].fillna(peer_group_mean_ae)
events_df['ae_error'] = events_df['ae_error'].fillna(events_df['ae_error'].mean()).fillna(0.0)

print(f"ae_error computed for all {len(events_df)} events "
      f"({int(events_df['ae_error'].isna().sum())} unresolved NaNs after fallback).")

# ------------------------------------------------------------------
# 8. Retrain Isolation Forest + XGBoost WITH ae_error stacked in.
#    Mirrors phase2_core_ml.py exactly, just with 8 features instead of 7.
#    Saved under NEW filenames -- originals are NOT touched.
# ------------------------------------------------------------------
STACKED_FEATURE_COLS = BASE_FEATURE_COLS + ['ae_error']
print(f"\nRetraining Isolation Forest + XGBoost with stacked features: {STACKED_FEATURE_COLS}")

X_baseline = events_df[events_df['label'].isin(['normal', 'insider_drift'])][STACKED_FEATURE_COLS]
iso_forest_v2 = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
iso_forest_v2.fit(X_baseline)
events_df['anomaly_score_v2'] = -iso_forest_v2.score_samples(events_df[STACKED_FEATURE_COLS])

# Treat insider_drift as 'normal' for the classifier
events_df['clf_label'] = events_df['label'].replace('insider_drift', 'normal')
label_encoder_v2 = LabelEncoder()
events_df['target_v2'] = label_encoder_v2.fit_transform(events_df['clf_label'])

X_clf = events_df[STACKED_FEATURE_COLS]
y_clf = events_df['target_v2']
X_train, X_test, y_train, y_test = train_test_split(X_clf, y_clf, test_size=0.2, stratify=y_clf, random_state=42)

base_xgb_v2 = xgb.XGBClassifier(
    objective='multi:softprob',
    num_class=len(label_encoder_v2.classes_),
    eval_metric='mlogloss',
    use_label_encoder=False,
    random_state=42
)
sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)
base_xgb_v2.fit(X_train, y_train, sample_weight=sample_weights)

xgb_model_v2 = CalibratedClassifierCV(FrozenEstimator(base_xgb_v2), method='sigmoid')
xgb_model_v2.fit(X_train, y_train)

print("\n--- XGBoost (Stacked, incl. ae_error) Test Set Evaluation ---")
y_pred_test = xgb_model_v2.predict(X_test)
print(classification_report(y_test, y_pred_test, target_names=label_encoder_v2.classes_))

probs = xgb_model_v2.predict_proba(X_clf)
events_df['predicted_attack_class_v2'] = label_encoder_v2.inverse_transform(np.argmax(probs, axis=1))
events_df['attack_confidence_v2'] = np.max(probs, axis=1)

# Same precision@top-1% report phase2_core_ml.py prints, for direct before/after comparison
top_1_threshold_v2 = np.percentile(events_df['anomaly_score_v2'], 99)
top_1_events_v2 = events_df[events_df['anomaly_score_v2'] >= top_1_threshold_v2]
false_positives_v2 = top_1_events_v2[top_1_events_v2['label'].isin(['normal', 'insider_drift'])]
true_positives_v2 = top_1_events_v2[~top_1_events_v2['label'].isin(['normal', 'insider_drift'])]
total_normal_v2 = len(events_df[events_df['label'].isin(['normal', 'insider_drift'])])
fpr_v2 = len(false_positives_v2) / total_normal_v2 if total_normal_v2 > 0 else 0
precision_v2 = len(true_positives_v2) / len(top_1_events_v2) if len(top_1_events_v2) > 0 else 0

print("\n--- STACKED MODEL: Analyst Alert Budget (Top 1%) ---")
print(f"Total events in top 1%: {len(top_1_events_v2)}")
print(f"True Positives: {len(true_positives_v2)}")
print(f"False Positives: {len(false_positives_v2)}")
print(f"Precision @ Top 1%: {precision_v2:.4f} ({precision_v2*100:.2f}%)")
print(f"False Positive Rate @ Top 1%: {fpr_v2:.6f} ({fpr_v2*100:.4f}%)")
print("\nCompare this to phase2_core_ml.py's printed Precision @ Top 1% (7-feature model)")
print("to see whether ae_error actually IMPROVED detection, not just whether it validated.")

# ------------------------------------------------------------------
# 9. Save everything under NEW filenames. Nothing from the existing
#    pipeline is overwritten.
# ------------------------------------------------------------------
print("\nSaving new artifacts...")
events_df.to_csv(os.path.join(DATA_DIR, 'scored_events_v2.csv'), index=False)
joblib.dump(iso_forest_v2, os.path.join(DATA_DIR, 'iso_forest_v2.joblib'))
joblib.dump(xgb_model_v2, os.path.join(DATA_DIR, 'xgboost_v2.joblib'))
joblib.dump(label_encoder_v2, os.path.join(DATA_DIR, 'label_encoder_v2.joblib'))
joblib.dump(STACKED_FEATURE_COLS, os.path.join(DATA_DIR, 'feature_cols_v2.joblib'))
joblib.dump(resource_encoder, os.path.join(DATA_DIR, 'resource_encoder.joblib'))
joblib.dump(auth_encoder, os.path.join(DATA_DIR, 'auth_encoder.joblib'))
joblib.dump(scaler, os.path.join(DATA_DIR, 'sequence_numeric_scaler.joblib'))
torch.save(model.state_dict(), os.path.join(DATA_DIR, 'sequence_model.pt'))

print("\n=== PHASE 2B COMPLETE ===")
print("New files written: scored_events_v2.csv, iso_forest_v2.joblib, xgboost_v2.joblib,")
print("label_encoder_v2.joblib, feature_cols_v2.joblib, resource_encoder.joblib,")
print("auth_encoder.joblib, sequence_numeric_scaler.joblib, sequence_model.pt")
print("\nYour original phase2/phase3/phase4 files and artifacts are completely untouched.")
