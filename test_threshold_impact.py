import pandas as pd
import numpy as np
import os
from sklearn.metrics import classification_report

DATA_DIR = './data'

print("Loading final alerts...")
events_df = pd.read_csv(os.path.join(DATA_DIR, 'final_alerts.csv'))

# Tiered Alert Evaluation
top_1_percent_threshold = np.percentile(events_df['anomaly_score'], 99) if len(events_df) > 0 else 0
# Wait, final_alerts.csv already contains only the top 1% and the chains.
# The true threshold was calculated on scored_events.csv. We need to accurately identify Tier 1 vs Tier 2.
# Luckily, the 'alert_tier' column doesn't exist in final_alerts.csv! It's added in backend init_db!
# But we can approximate the threshold by looking at the dataset, or better yet, just use the logical split:
# Actually, the user says:
# "apply the tiered alerting split we already implemented in phase3_chain_and_shap.py (Tier 1 = strict anomaly_score >= threshold_99 only, Tier 2 = everything else caught via chain_involved or attack_confidence > 0.85) to this test's output"
# Since final_alerts.csv doesn't have the original threshold saved, we can't do np.percentile on final_alerts.csv (it would find the 99th percentile of ALERTS, not of ALL EVENTS).
# Wait! In test_threshold_impact.py we can load scored_events.csv just to calculate the threshold, and load final_alerts.csv to get the actual alerts.

print("Calculating true 99th percentile threshold from scored_events.csv...")
full_df = pd.read_csv(os.path.join(DATA_DIR, 'scored_events.csv'))
top_1_percent_threshold = np.percentile(full_df['anomaly_score'], 99)

# Tier 1 (Strict 1% Budget)
tier1_events = events_df[events_df['anomaly_score'] >= top_1_percent_threshold]
tier1_fp = tier1_events[tier1_events['label'].isin(['normal', 'insider_drift'])]
tier1_tp = tier1_events[~tier1_events['label'].isin(['normal', 'insider_drift'])]
tier1_precision = len(tier1_tp) / len(tier1_events) if len(tier1_events) > 0 else 0

# Tier 2 (Safety Net)
tier2_mask = (events_df['anomaly_score'] < top_1_percent_threshold) & (
    ((events_df['predicted_attack_class'] != 'normal') & (events_df['attack_confidence'] > 0.85)) | 
    (events_df['chain_involved'] == True)
)
tier2_events = events_df[tier2_mask]
tier2_fp = tier2_events[tier2_events['label'].isin(['normal', 'insider_drift'])]
tier2_tp = tier2_events[~tier2_events['label'].isin(['normal', 'insider_drift'])]
tier2_precision = len(tier2_tp) / len(tier2_events) if len(tier2_events) > 0 else 0

# Tier 1 + Tier 2 Combined
combined_events = pd.concat([tier1_events, tier2_events])
combined_fp = combined_events[combined_events['label'].isin(['normal', 'insider_drift'])]
combined_tp = combined_events[~combined_events['label'].isin(['normal', 'insider_drift'])]
combined_precision = len(combined_tp) / len(combined_events) if len(combined_events) > 0 else 0

print("\n--- TIER 1 ALERTS (Strict 1% Analyst Budget) ---")
print(f"Total events in Tier 1: {len(tier1_events)}")
print(f"True Positives: {len(tier1_tp)}")
print(f"False Positives: {len(tier1_fp)}")
print(f"Precision @ Tier 1: {tier1_precision:.4f} ({tier1_precision*100:.2f}%)")

print("\n--- TIER 1 + TIER 2 COMBINED (Full Alert Queue) ---")
print(f"Total events: {len(combined_events)}")
print(f"True Positives: {len(combined_tp)}")
print(f"False Positives: {len(combined_fp)}")
print(f"Precision @ Combined: {combined_precision:.4f} ({combined_precision*100:.2f}%)")
