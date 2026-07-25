# ==========================================
# PHASE 3: CHAIN DETECTION & EXPLAINABILITY (SHAP)
# ==========================================
# Instructions: Copy and paste this into a new Google Colab cell.

!pip install shap

import shap

# 1. Mount Google Drive and Load Data
try:
    from google.colab import drive
    drive.mount('/content/drive')
    DATA_DIR = '/content/drive/MyDrive/Anomaly_Detection_Data'
except ImportError:
    print("Not in Colab. Using local directory.")
    DATA_DIR = './Anomaly_Detection_Data'

print("Loading scored events and models...")
events_df = pd.read_csv(os.path.join(DATA_DIR, 'scored_events.csv'))
events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])

xgb_model = joblib.load(os.path.join(DATA_DIR, 'xgboost.joblib'))
le = joblib.load(os.path.join(DATA_DIR, 'label_encoder.joblib'))

# Define feature columns used in XGBoost
feature_cols = ['hour_deviation', 'session_duration_zscore', 'is_new_device', 'is_new_geo', 
                'geo_velocity', 'recent_failed_auth_count', 'has_privileged_command']

# 2. Rule-Based Chain Detection
print("Running Sliding-Window Attack Chain Linker...")
# We will flag the "Credential Compromise" chain: 
# (Login -> Account_Settings/Password Reset -> Payroll) within 2 hours

events_df['chain_involved'] = False
events_df['chain_type'] = None

# Group by entity to slide window
grouped = events_df.groupby('entity_id')

chain_hits = 0
for entity_id, group in grouped:
    # Sort by time
    group = group.sort_values('timestamp')
    
    # Simple state machine for the chain
    # State 0: looking for VPN login
    # State 1: looking for Account_Settings
    # State 2: looking for Payroll
    
    chain_events_buffer = []
    
    for idx, row in group.iterrows():
        if row['resource_accessed'] == 'VPN':
            chain_events_buffer = [idx]  # start/reset chain
        elif row['resource_accessed'] == 'Account_Settings' and len(chain_events_buffer) == 1:
            # Check time diff
            if (row['timestamp'] - events_df.loc[chain_events_buffer[-1], 'timestamp']) <= timedelta(hours=2):
                chain_events_buffer.append(idx)
        elif row['resource_accessed'] == 'Payroll' and len(chain_events_buffer) == 2:
            if (row['timestamp'] - events_df.loc[chain_events_buffer[-1], 'timestamp']) <= timedelta(hours=2):
                chain_events_buffer.append(idx)
                # Chain triggered! Flag all involved events
                events_df.loc[chain_events_buffer, 'chain_involved'] = True
                events_df.loc[chain_events_buffer, 'chain_type'] = 'credential_compromise'
                chain_hits += 1
                chain_events_buffer = [] # Reset

print(f"Chain Linker detected {chain_hits} distinct multi-step attack chains.")

# 3. Filter to Alerts Only (Anomalous OR Chain Involved)
# We only want to run SHAP on the events we are actually going to flag to the analyst
threshold = np.percentile(events_df['anomaly_score'], 95) # Top 5%
alerts_df = events_df[(events_df['anomaly_score'] > threshold) | (events_df['chain_involved'] == True)].copy()
alerts_df = alerts_df.reset_index(drop=True)

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
        
        # Rule-based text mapping for SHAP features
        if feat == 'hour_deviation' and val > 2:
            row_reasons.append(f"Login occurred {val:.1f} hours outside normal behavior")
        elif feat == 'is_new_device' and val == 1:
            row_reasons.append("Accessed from a completely unrecognized device")
        elif feat == 'is_new_geo' and val == 1:
            row_reasons.append("Accessed from a geographic location never seen before")
        elif feat == 'session_duration_zscore' and val > 2:
            row_reasons.append("Session duration was exceptionally long compared to baseline")
        elif feat == 'session_duration_zscore' and val < -1:
            row_reasons.append("Rapid automated-like session detected")
        elif feat == 'geo_velocity' and val > 800:
            row_reasons.append(f"Physically impossible travel velocity detected ({val:.0f} km/h)")
        elif feat == 'recent_failed_auth_count' and val > 3:
            row_reasons.append(f"High number of recent failed authentications ({val:.0f} attempts)")
        elif feat == 'has_privileged_command' and val == 1:
            row_reasons.append("Execution of highly privileged commands detected")
            
    # Add chain context if applicable
    if alerts_df.loc[i, 'chain_involved']:
        row_reasons.insert(0, "CRITICAL: Event is part of a detected Credential Compromise attack chain.")
        
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
