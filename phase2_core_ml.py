# ==========================================
# PHASE 2: CORE ML (FEATURES, ISOLATION FOREST, XGBOOST)
# ==========================================
# Instructions: Copy and paste this into a new Google Colab cell.

# !pip install pandas numpy scikit-learn xgboost joblib

import os
import json
import pandas as pd
import numpy as np
import hashlib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.utils.class_weight import compute_sample_weight
import xgboost as xgb
import joblib

# 1. Mount Google Drive and Load Data
try:
    from google.colab import drive
    drive.mount('/content/drive')
    DATA_DIR = '/content/drive/MyDrive/Anomaly_Detection_Data'
except ImportError:
    print("Not in Colab. Using local directory.")
    DATA_DIR = './data'

print("Loading data...")
events_df = pd.read_csv(os.path.join(DATA_DIR, 'events.csv'))
events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
events_df = events_df.sort_values(by=['entity_id', 'timestamp']).reset_index(drop=True)

# 2. Feature Engineering (Temporal, Rolling, Cold-Start)
print("Engineering features...")

REAL_CITIES = {
    'New York': (40.7128, -74.0060),
    'London': (51.5074, -0.1278),
    'Tokyo': (35.6762, 139.6503),
    'Sydney': (-33.8688, 151.2093),
    'Moscow': (55.7558, 37.6173),
    'Beijing': (39.9042, 116.4074),
    'Mumbai': (19.0760, 72.8777),
    'Cairo': (30.0444, 31.2357),
    'Sao Paulo': (-23.5505, -46.6333),
    'Paris': (48.8566, 2.3522),
    'Berlin': (52.5200, 13.4050),
    'Toronto': (43.6510, -79.3470),
    'Dubai': (25.2048, 55.2708),
    'Singapore': (1.3521, 103.8198),
    'Johannesburg': (-26.2041, 28.0473),
    'DataCenter-US': (37.7749, -122.4194)
}

def get_coords(city):
    return REAL_CITIES.get(str(city), (0.0, 0.0))

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0 # Earth radius in km
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2)**2
    c = 2 * np.arcsin(np.sqrt(a))
    return R * c

def compute_rolling_features(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    df['device_str'] = df.get('device_fingerprint', pd.Series(['unknown']*len(df))).fillna('unknown')

    # 1. Geo Velocity
    coords = df['geo_location'].apply(lambda x: get_coords(str(x)))
    df['lat'] = [c[0] for c in coords]
    df['lon'] = [c[1] for c in coords]
    
    df = df.sort_values(['entity_id', 'timestamp'])
    df['prev_lat'] = df.groupby('entity_id')['lat'].shift(1)
    df['prev_lon'] = df.groupby('entity_id')['lon'].shift(1)
    df['prev_timestamp'] = df.groupby('entity_id')['timestamp'].shift(1)
    
    def calc_dist(row):
        if pd.isna(row['prev_lat']): return 0.0
        return haversine(row['lat'], row['lon'], row['prev_lat'], row['prev_lon'])
    
    df['distance_km'] = df.apply(calc_dist, axis=1)
    df['time_delta_hours'] = (df['timestamp'] - df['prev_timestamp']).dt.total_seconds() / 3600.0
    
    df['geo_velocity'] = np.where(df['time_delta_hours'] > 0, df['distance_km'] / df['time_delta_hours'], 0.0)
    df['geo_velocity'] = df['geo_velocity'].fillna(0.0)

    # 3. Has Privileged Command
    privileged_cmds = ['assume_role', 'list_buckets', 'export_all_data', 'SELECT *']
    def check_priv(cmds):
        if not isinstance(cmds, str): return 0
        return 1 if any(p in cmds for p in privileged_cmds) else 0
        
    df['has_privileged_command'] = df['command_sequence'].apply(check_priv)

    # 2. Recent Failed Auth Count
    df['is_failed_auth'] = (df['session_duration'] == 0.0).astype(int)

    # Set timestamp as index for time-based rolling
    df = df.set_index('timestamp')
    
    # Group by entity to calculate rolling baseline stats
    grouped = df.groupby('entity_id')
    
    df['recent_failed_auth_count'] = grouped['is_failed_auth'].transform(lambda x: x.rolling('10min').sum())
    
    # Session duration Z-Score (Rolling Window of 30 Days)
    rolling_mean_dur = grouped['session_duration'].transform(lambda x: x.rolling('30D', min_periods=1).mean())
    rolling_std_dur = grouped['session_duration'].transform(lambda x: x.rolling('30D', min_periods=1).std().replace(0, 1.0).fillna(1.0))
    df['session_duration_zscore'] = (df['session_duration'] - rolling_mean_dur) / rolling_std_dur
    
    # Login Hour Deviation
    rolling_mean_hour = grouped['hour'].transform(lambda x: x.rolling('30D', min_periods=1).mean())
    df['hour_deviation'] = abs(df['hour'] - rolling_mean_hour)
    
    # New Device Flag (Cumulative count of unique devices seen so far per entity)
    df['device_factor'] = pd.factorize(df['device_str'])[0]
    cumulative_unique_devices = grouped['device_factor'].transform(lambda x: ~x.duplicated())
    df['is_new_device'] = cumulative_unique_devices.astype(int)
    
    # New Geo Flag
    df['geo_factor'] = pd.factorize(df['geo_location'])[0]
    cumulative_unique_geos = grouped['geo_factor'].transform(lambda x: ~x.duplicated())
    df['is_new_geo'] = cumulative_unique_geos.astype(int)
    
    # Restore index
    df = df.reset_index()
    
    return df

feature_cols = ['hour_deviation', 'session_duration_zscore', 'is_new_device', 'is_new_geo', 
                'geo_velocity', 'recent_failed_auth_count', 'has_privileged_command']

if __name__ == '__main__':
    events_df = compute_rolling_features(events_df)
    
    # Cold Start & Concept Drift Handling
    # Fill NaNs for new entities with Peer-Group Averages (by entity_type)
    peer_group_means = events_df.groupby('entity_type')[['session_duration_zscore', 'hour_deviation']].transform('mean')
    events_df['session_duration_zscore'] = events_df['session_duration_zscore'].fillna(peer_group_means['session_duration_zscore']).fillna(0)
    events_df['hour_deviation'] = events_df['hour_deviation'].fillna(peer_group_means['hour_deviation']).fillna(0)

    # Concept Drift: The rolling windows above inherently handle drift because they only look at the last 30 days.
    # As behavior changes, the rolling mean adapts, and the deviation drops back to 0 over time.

    # 3. Model 1: Isolation Forest (Anomaly Scoring)
    print("Training Isolation Forest...")
    
    # Train Isolation Forest only on 'normal' and 'insider_drift' data to establish the pure baseline
    X_baseline = events_df[events_df['label'].isin(['normal', 'insider_drift'])][feature_cols]
    iso_forest = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
    iso_forest.fit(X_baseline)

    # Score all events (negative scores are anomalies)
    # We invert it so higher score = more anomalous
    events_df['anomaly_score'] = -iso_forest.score_samples(events_df[feature_cols])

    # 4. Model 2: XGBoost (Attack Classification)
    print("Training XGBoost Classifier...")
    # We train the classifier on events that are actual attacks, plus a sample of normal events.
    # XGBoost will learn to distinguish between attack types based on features.

    # Prepare Labels
    le = LabelEncoder()
    events_df['target'] = le.fit_transform(events_df['label'])

    X_clf = events_df[feature_cols]
    y_clf = events_df['target']

    X_train, X_test, y_train, y_test = train_test_split(X_clf, y_clf, test_size=0.2, stratify=y_clf, random_state=42)

    xgb_model = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=len(le.classes_),
        eval_metric='mlogloss',
        use_label_encoder=False,
        random_state=42
    )
    weights = compute_sample_weight(class_weight='balanced', y=y_train)
    xgb_model.fit(X_train, y_train, sample_weight=weights)

    print("\n--- XGBoost Test Set Evaluation ---")
    y_pred_test = xgb_model.predict(X_test)
    print(classification_report(y_test, y_pred_test, target_names=le.classes_))

    # Predict probabilities
    probs = xgb_model.predict_proba(X_clf)
    events_df['predicted_attack_class'] = le.inverse_transform(np.argmax(probs, axis=1))
    events_df['attack_confidence'] = np.max(probs, axis=1)

    # 5. Save Artifacts for next phases
    print("Saving models and scored dataset...")
    events_df.to_csv(os.path.join(DATA_DIR, 'scored_events.csv'), index=False)
    joblib.dump(iso_forest, os.path.join(DATA_DIR, 'iso_forest.joblib'))
    joblib.dump(xgb_model, os.path.join(DATA_DIR, 'xgboost.joblib'))
    joblib.dump(le, os.path.join(DATA_DIR, 'label_encoder.joblib'))

    print("\n=== PHASE 2 COMPLETE ===")
    print("Generated Features: ", feature_cols)
    print("Models saved successfully.")

    # Quick Evaluation Metric for Analyst
    flagged = events_df[events_df['anomaly_score'] > np.percentile(events_df['anomaly_score'], 95)]
    print("\nTop 5% Anomalous Events (Isolation Forest) captured the following true labels:")
    print(flagged['label'].value_counts())

    # Strict 1% Alert Budget Evaluation (As requested by Evaluation Criteria)
    top_1_percent_threshold = np.percentile(events_df['anomaly_score'], 99)
    top_1_percent_events = events_df[events_df['anomaly_score'] >= top_1_percent_threshold]

    # In the top 1%, how many were actually normal (False Positives)?
    # 'insider_drift' is also technically normal/legitimate for this baseline.
    false_positives = top_1_percent_events[top_1_percent_events['label'].isin(['normal', 'insider_drift'])]
    true_positives = top_1_percent_events[~top_1_percent_events['label'].isin(['normal', 'insider_drift'])]

    total_normal_events = len(events_df[events_df['label'].isin(['normal', 'insider_drift'])])
    false_positive_rate = len(false_positives) / total_normal_events if total_normal_events > 0 else 0
    precision_at_1_percent = len(true_positives) / len(top_1_percent_events) if len(top_1_percent_events) > 0 else 0

    print("\n--- EVALUATION CRITERIA: Analyst Alert Budget (Top 1%) ---")
    print(f"Total events in top 1%: {len(top_1_percent_events)}")
    print(f"True Positives (Attacks caught in top 1%): {len(true_positives)}")
    print(f"False Positives (Normal events flagged in top 1%): {len(false_positives)}")
    print(f"Precision @ Top 1%: {precision_at_1_percent:.4f} ({precision_at_1_percent*100:.2f}%)")
    print(f"False Positive Rate @ Top 1%: {false_positive_rate:.6f} ({false_positive_rate*100:.4f}%)")
