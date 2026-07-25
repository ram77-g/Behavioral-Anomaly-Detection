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
