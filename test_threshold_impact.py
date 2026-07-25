import pandas as pd
import numpy as np
import os
from sklearn.metrics import classification_report

DATA_DIR = './data'

print("Loading scored events...")
events_df = pd.read_csv(os.path.join(DATA_DIR, 'scored_events.csv'))

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

# Strict 1% Alert Budget Evaluation (As requested by Evaluation Criteria)
# This calculates exactly what the eval asks for: Precision at Top-1%-Alert-Budget
top_1_percent_threshold = np.percentile(events_df['anomaly_score'], 99)
top_1_percent_events = events_df[events_df['anomaly_score'] >= top_1_percent_threshold]

false_positives = top_1_percent_events[top_1_percent_events['label'].isin(['normal', 'insider_drift'])]
true_positives = top_1_percent_events[~top_1_percent_events['label'].isin(['normal', 'insider_drift'])]

precision_at_1_percent = len(true_positives) / len(top_1_percent_events) if len(top_1_percent_events) > 0 else 0

print("\n--- EVALUATION CRITERIA: Analyst Alert Budget (Top 1%) ---")
print(f"Total events in top 1%: {len(top_1_percent_events)}")
print(f"True Positives (Attacks caught in top 1%): {len(true_positives)}")
print(f"False Positives (Normal events flagged in top 1%): {len(false_positives)}")
print(f"Precision @ Top 1% Alert Budget: {precision_at_1_percent:.4f} ({precision_at_1_percent*100:.2f}%)")
