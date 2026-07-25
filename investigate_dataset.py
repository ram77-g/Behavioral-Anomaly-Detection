import pandas as pd
import numpy as np

df = pd.read_csv('data/scored_events.csv')
print(f"Total events in scored_events.csv: {len(df)}")

threshold_99 = np.percentile(df['anomaly_score'], 99)
mask_anomaly = df['anomaly_score'] >= threshold_99
print(f"Events passing 99th percentile anomaly score alone: {mask_anomaly.sum()}")

mask_xgboost = (df['predicted_attack_class'] != 'normal') & (df['attack_confidence'] > 0.85)
print(f"Events passing XGBoost high-confidence attack safety net alone: {mask_xgboost.sum()}")

print("\nBreakdown of predicted_attack_class for the XGBoost safety net events:")
print(df[mask_xgboost]['predicted_attack_class'].value_counts())

print("\nWait, let's check normal vs attack predictions with confidence > 0.85")
mask_normal_high_conf = (df['predicted_attack_class'] == 'normal') & (df['attack_confidence'] > 0.85)
print(f"Number of normal predictions with >0.85 confidence: {mask_normal_high_conf.sum()}")
