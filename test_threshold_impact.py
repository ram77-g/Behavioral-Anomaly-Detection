import pandas as pd
import numpy as np
import os
from sklearn.metrics import classification_report

DATA_DIR = './data'

print("Loading scored events...")
events_df = pd.read_csv(os.path.join(DATA_DIR, 'final_alerts.csv'))

# 95th Percentile
threshold_95 = np.percentile(events_df['anomaly_score'], 95)
alerts_95 = events_df[events_df['anomaly_score'] > threshold_95]

print(f"\n--- 95th Percentile Threshold ({len(alerts_95)} events) ---")
print(classification_report(alerts_95['label'], alerts_95['predicted_attack_class']))

# 99th Percentile
threshold_99 = np.percentile(events_df['anomaly_score'], 99)
mask_99 = (events_df['anomaly_score'] >= threshold_99) | ((events_df['predicted_attack_class'] != 'normal') & (events_df['attack_confidence'] > 0.85))
alerts_99 = events_df[mask_99]

print(f"\n--- 99th Percentile Threshold ({len(alerts_99)} events) ---")
print(classification_report(alerts_99['label'], alerts_99['predicted_attack_class']))

# Tiered Alert Evaluation
top_1_percent_threshold = np.percentile(events_df['anomaly_score'], 99)

# Tier 1 (Strict 1% Budget)
tier1_events = events_df[events_df['anomaly_score'] >= top_1_percent_threshold]
tier1_fp = tier1_events[tier1_events['label'].isin(['normal', 'insider_drift'])]
tier1_tp = tier1_events[~tier1_events['label'].isin(['normal', 'insider_drift'])]
tier1_precision = len(tier1_tp) / len(tier1_events) if len(tier1_events) > 0 else 0

# Tier 2 (Safety Net: Caught by supervised logic/chains but below the 99th percentile anomaly threshold)
tier2_mask = (events_df['anomaly_score'] < top_1_percent_threshold) & (
    ((events_df['predicted_attack_class'] != 'normal') & (events_df['attack_confidence'] > 0.85)) | 
    (events_df['chain_involved'] == True)
)
tier2_events = events_df[tier2_mask]
tier2_fp = tier2_events[tier2_events['label'].isin(['normal', 'insider_drift'])]
tier2_tp = tier2_events[~tier2_events['label'].isin(['normal', 'insider_drift'])]
tier2_precision = len(tier2_tp) / len(tier2_events) if len(tier2_events) > 0 else 0

print("\n--- TIER 1 ALERTS (Strict 1% Analyst Budget) ---")
print(f"Total events in Tier 1: {len(tier1_events)}")
print(f"True Positives: {len(tier1_tp)}")
print(f"False Positives: {len(tier1_fp)}")
print(f"Precision @ Tier 1: {tier1_precision:.4f} ({tier1_precision*100:.2f}%)")

print("\n--- TIER 2 ALERTS (Safety Net via Chains & Supervised XGBoost) ---")
print(f"Total events in Tier 2: {len(tier2_events)}")
print(f"True Positives: {len(tier2_tp)}")
print(f"False Positives: {len(tier2_fp)}")
print(f"Precision @ Tier 2: {tier2_precision:.4f} ({tier2_precision*100:.2f}%)")
