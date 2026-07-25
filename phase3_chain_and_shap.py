# ==========================================
# PHASE 3: CHAIN DETECTION & EXPLAINABILITY (SHAP)
# ==========================================
# Instructions: Copy and paste this into a new Google Colab cell.

# !pip install shap

import shap
import pandas as pd
import numpy as np
import joblib
import os

# 1. Mount Google Drive and Load Data
try:
    from google.colab import drive
    drive.mount('/content/drive')
    DATA_DIR = '/content/drive/MyDrive/Anomaly_Detection_Data'
except ImportError:
    print("Not in Colab. Using local directory.")
    DATA_DIR = './data'

print("Loading scored events and models...")
events_df = pd.read_csv(os.path.join(DATA_DIR, 'scored_events.csv'))
events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])

xgb_model = joblib.load(os.path.join(DATA_DIR, 'xgboost.joblib'))
le = joblib.load(os.path.join(DATA_DIR, 'label_encoder.joblib'))

# Define feature columns used in XGBoost
feature_cols = ['hour_deviation', 'session_duration_zscore', 'is_new_device', 'is_new_geo', 
                'geo_velocity', 'recent_failed_auth_count', 'has_privileged_command']

# 2. Rule-Based Chain Detection
print("Running Configurable Sliding-Window Attack Chain Linker...")

events_df['chain_involved'] = False
events_df['chain_type'] = None

CHAIN_PATTERNS = [
    {
        'name': 'chain_credential_compromise',
        'steps': [
            {'resource_accessed': 'VPN'},
            {'resource_accessed': 'Account_Settings'},
            {'resource_accessed': 'Payroll'}
        ],
        'max_gap_hours': 2.0
    },
    {
        'name': 'chain_stealth_exfiltration',
        'steps': [
            {'is_new_device': 1},
            {'has_privileged_command': 1},
            {'resource_accessed': 'Production_DB'}
        ],
        'max_gap_hours': 1.0
    },
    {
        'name': 'chain_brute_force_success',
        'steps': [
            {'recent_failed_auth_count': {'>': 3}},
            {'is_new_device': 1},
            {'resource_accessed': 'Production_DB'}
        ],
        'max_gap_hours': 1.5
    },
    {
        'name': 'chain_lateral_movement',
        'steps': [
            {'is_new_geo': 1},
            {'resource_accessed': 'Internal_Wiki'},
            {'has_privileged_command': 1}
        ],
        'max_gap_hours': 2.0
    }
]

def match_step(row, step_cond):
    for k, v in step_cond.items():
        if isinstance(v, dict):
            if '>' in v and not (row[k] > v['>']): return False
            if '<' in v and not (row[k] < v['<']): return False
        else:
            if row[k] != v:
                return False
    return True

grouped = events_df.groupby('entity_id')
chain_hits = 0
for eid, group in grouped:
    group = group.sort_values('timestamp')
    idx_list = group.index.tolist()
    
    for pattern in CHAIN_PATTERNS:
        steps = pattern['steps']
        n_steps = len(steps)
        max_gap = pattern['max_gap_hours']
        name = pattern['name']
        
        # Simple contiguous sliding window for POC
        for i in range(len(idx_list) - n_steps + 1):
            window_indices = idx_list[i : i + n_steps]
            window_rows = [events_df.loc[idx] for idx in window_indices]
            
            # Check if steps match
            matches = True
            for step_idx in range(n_steps):
                if not match_step(window_rows[step_idx], steps[step_idx]):
                    matches = False
                    break
            
            if not matches:
                continue
                
            # Check time gaps
            time_valid = True
            for step_idx in range(n_steps - 1):
                diff = (window_rows[step_idx+1]['timestamp'] - window_rows[step_idx]['timestamp']).total_seconds() / 3600.0
                if diff > max_gap:
                    time_valid = False
                    break
                    
            if time_valid:
                for idx in window_indices:
                    events_df.at[idx, 'chain_involved'] = True
                    events_df.at[idx, 'chain_type'] = name
                chain_hits += 1

print(f"Chain Linker detected {chain_hits} distinct multi-step attack chains.")

# 3. Filter to Alerts Only (Anomalous OR Chain Involved)
# We only want to run SHAP on the events we are actually going to flag to the analyst
threshold = np.percentile(events_df['anomaly_score'], 99) 
print(f"Applying strict 99th percentile anomaly threshold (score >= {threshold:.4f}) OR Chain OR High Confidence Attack...")

is_high_conf_attack = (~events_df['predicted_attack_class'].isin(['normal', 'insider_drift'])) & (events_df['attack_confidence'] > 0.85)
mask = (events_df['anomaly_score'] >= threshold) | (events_df['chain_involved'] == True) | is_high_conf_attack
alerts_df = events_df[mask].copy().reset_index(drop=True)

print(f"Generating Explanations for {len(alerts_df)} Alerts using SHAP...")

# 4. SHAP Integration
# We use TreeExplainer for XGBoost
explainer = shap.TreeExplainer(xgb_model)
shap_values = explainer.shap_values(alerts_df[feature_cols])

# Convert SHAP arrays to human-readable strings
reasons = []

# SHAP values for multiclass is a list of arrays (one for each class).
# To find feature importance, we can look at the SHAP values for the *predicted* class
for i in range(len(alerts_df)):
    pred_class_idx = np.where(le.classes_ == alerts_df.loc[i, 'predicted_attack_class'])[0][0]
    
    # SHAP values for this specific row and predicted class
    if isinstance(shap_values, list): # multi-class format (old SHAP)
        row_shap = shap_values[pred_class_idx][i]
    elif len(shap_values.shape) == 3: # multi-class format (new SHAP: samples, features, classes)
        row_shap = shap_values[i, :, pred_class_idx]
    else:
        row_shap = shap_values[i]
        
    # Get top 2 features driving this prediction (largest positive SHAP values)
    top_indices = np.argsort(row_shap)[-2:]
    top_indices = top_indices[::-1] # Reverse to get highest first
    
    row_reasons = []
    for idx in top_indices:
        feat = feature_cols[idx]
        val = alerts_df.loc[i, feat]
        
        # If SHAP determined this feature was a primary driver (positive impact on prediction)
        if row_shap[idx] > 0:
            if feat == 'hour_deviation':
                row_reasons.append(f"Login occurred {val:.1f} hours outside normal behavior")
            elif feat == 'is_new_device':
                row_reasons.append("Accessed from an unrecognized device")
            elif feat == 'is_new_geo':
                row_reasons.append("Accessed from a new geographic location")
            elif feat == 'session_duration_zscore':
                if val > 0:
                    row_reasons.append(f"Session duration unusually long (z-score: {val:.1f})")
                else:
                    row_reasons.append(f"Rapid automated-like session (z-score: {val:.1f})")
            elif feat == 'geo_velocity':
                if val > 800:
                    row_reasons.append(f"Physically impossible travel velocity ({val:.0f} km/h)")
                else:
                    row_reasons.append(f"Anomalous geographic velocity pattern")
            elif feat == 'recent_failed_auth_count':
                if val > 3:
                    row_reasons.append(f"High number of recent failed authentications ({val:.0f} attempts)")
                else:
                    row_reasons.append(f"Anomalous authentication pattern")
            elif feat == 'has_privileged_command':
                row_reasons.append("Execution of highly privileged commands detected")
            else:
                row_reasons.append(f"Highly anomalous behavior detected in {feat} (value: {val:.1f})")
            
    # Add chain context if applicable
    if alerts_df.loc[i, 'chain_involved']:
        chain_name = str(alerts_df.loc[i, 'chain_type']).replace('_', ' ').title()
        row_reasons.insert(0, f"CRITICAL: Event is part of a detected {chain_name} attack chain.")
        
    if not row_reasons:
        row_reasons.append("Anomalous baseline deviation detected.")
        
    reasons.append(" | ".join(row_reasons))

alerts_df['reasons'] = reasons

# 5. Save Final Alerts
print("Saving final alerts dataset...")
alerts_path = os.path.join(DATA_DIR, 'final_alerts.csv')
alerts_df.to_csv(alerts_path, index=False)

print("\n=== PHASE 3 COMPLETE ===")
print(f"Final Alerts saved to: {alerts_path}")
print("\nSample Explanations Generated:")
print(alerts_df[['predicted_attack_class', 'reasons']].head())
