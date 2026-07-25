import pandas as pd
import numpy as np
import datetime
import os
import sys

# Import the feature engineering function
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from phase2_core_ml import compute_rolling_features

print("--- TESTING COLD START & CONCEPT DRIFT MECHANISMS ---\n")

# 1. Generate a small synthetic dataset for testing
now = pd.to_datetime("2026-01-01 12:00:00")

# Entity A: Existing entity with established baseline (30 days of data)
# Baseline: Usually logs in for 60 seconds (1 minute), always from same device/geo
entity_a_events = []
for i in range(30):
    entity_a_events.append({
        'timestamp': now - datetime.timedelta(days=30-i),
        'entity_id': 'user_a',
        'entity_type': 'Employee',
        'device_fingerprint': 'device_1',
        'geo_location': 'New York',
        'session_duration': 60.0,
        'command_sequence': 'ls',
        'resource_accessed': 'Jira',
        'auth_method': 'SSO'
    })

# Entity B: Brand new entity (Cold Start)
# Only 1 event
entity_b_events = [{
    'timestamp': now,
    'entity_id': 'user_b',
    'entity_type': 'Employee',
    'device_fingerprint': 'device_2',
    'geo_location': 'London',
    'session_duration': 3600.0, # 1 hour
    'command_sequence': 'ls',
    'resource_accessed': 'Jira',
    'auth_method': 'SSO'
}]

# Entity C: Concept Drift (User changes behavior over 30 days)
# Old Baseline: 60 seconds. New Baseline: 3600 seconds.
entity_c_events = []
for i in range(15): # First 15 days: 60s
    entity_c_events.append({
        'timestamp': now - datetime.timedelta(days=30-i),
        'entity_id': 'user_c',
        'entity_type': 'Employee',
        'device_fingerprint': 'device_3',
        'geo_location': 'Tokyo',
        'session_duration': 60.0,
        'command_sequence': 'ls',
        'resource_accessed': 'Jira',
        'auth_method': 'SSO'
    })
for i in range(15, 30): # Last 15 days: drifted to 3600s
    entity_c_events.append({
        'timestamp': now - datetime.timedelta(days=30-i),
        'entity_id': 'user_c',
        'entity_type': 'Employee',
        'device_fingerprint': 'device_3',
        'geo_location': 'Tokyo',
        'session_duration': 3600.0,
        'command_sequence': 'ls',
        'resource_accessed': 'Jira',
        'auth_method': 'SSO'
    })

df = pd.DataFrame(entity_a_events + entity_b_events + entity_c_events)

# Add basic time features required by compute_rolling_features
df['hour'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.dayofweek
df['device_str'] = df['device_fingerprint'].fillna('unknown')

# Compute Features
df_features = compute_rolling_features(df)

print("1. COLD START TEST (User B):")
user_b = df_features[df_features['entity_id'] == 'user_b'].iloc[0]
print(f"Session Duration Z-Score: {user_b['session_duration_zscore']:.2f}")
print("If the cold-start fallback worked, this shouldn't be NaN. It should use the peer-group average or safe default.")
if pd.isna(user_b['session_duration_zscore']):
    print("FAILED: Cold start resulted in NaN.")
else:
    print("PASSED: Cold start handled successfully via fallback.")

print("\n2. CONCEPT DRIFT TEST (User C):")
user_c = df_features[df_features['entity_id'] == 'user_c'].sort_values('timestamp')
first_drift_day = user_c.iloc[15] # The first day they did 3600s
last_drift_day = user_c.iloc[-1]  # The 15th day they did 3600s

print(f"Z-Score on Day 1 of new behavior: {first_drift_day['session_duration_zscore']:.2f} (Should be huge anomaly)")
print(f"Z-Score on Day 15 of new behavior: {last_drift_day['session_duration_zscore']:.2f} (Should decay back towards 0 as model learns)")
if last_drift_day['session_duration_zscore'] < first_drift_day['session_duration_zscore']:
    print("PASSED: Rolling window successfully decayed the anomaly score as it learned the new baseline.")
else:
    print("FAILED: Concept drift is not being learned.")
