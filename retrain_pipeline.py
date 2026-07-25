import os
import pandas as pd
import numpy as np
import hashlib
from sqlalchemy import create_engine, text
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import precision_recall_curve, auc, precision_score, recall_score, confusion_matrix
import xgboost as xgb
import joblib
from dotenv import load_dotenv

load_dotenv()

DATA_DIR = './data'
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set!")
engine = create_engine(DATABASE_URL)

def load_and_merge_feedback():
    print("Loading historical data...")
    events_df = pd.read_csv(os.path.join(DATA_DIR, 'events.csv'))
    events_df['timestamp'] = pd.to_datetime(events_df['timestamp'])
    
    print("Pulling analyst feedback from PostgreSQL...")
    with engine.connect() as conn:
        feedback_df = pd.read_sql(
            text("SELECT timestamp, entity_id, status, predicted_attack_class FROM alerts WHERE status LIKE 'Resolved%'"), 
            conn
        )
    
    if len(feedback_df) == 0:
        print("No analyst feedback found in database. Exiting retraining pipeline.")
        return events_df, False

    feedback_df['timestamp'] = pd.to_datetime(feedback_df['timestamp'])
    
    # Merge feedback into historical data
    # We match exactly on timestamp and entity_id
    events_df = pd.merge(events_df, feedback_df, on=['timestamp', 'entity_id'], how='left')
    
    # Apply Analyst Corrections
    fp_mask = events_df['status'] == 'Resolved - False Positive'
    tp_mask = events_df['status'] == 'Resolved - True Positive'
    
    events_df.loc[fp_mask, 'label'] = 'normal'
    events_df.loc[tp_mask, 'label'] = events_df.loc[tp_mask, 'predicted_attack_class']
    
    # Cleanup
    events_df = events_df.drop(columns=['status', 'predicted_attack_class'])
    events_df = events_df.sort_values(by=['entity_id', 'timestamp']).reset_index(drop=True)
    
    print(f"Applied {fp_mask.sum()} False Positive corrections and {tp_mask.sum()} True Positive confirmations.")
    return events_df, True

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
    if pd.isna(city): return 0.0, 0.0
    return REAL_CITIES.get(str(city), (0.0, 0.0))

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat/2)**2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon/2)**2
    c = 2 * np.arcsin(np.sqrt(a))
    return R * c

def compute_rolling_features(df):
    df['device_str'] = df['device_fingerprint'].fillna('unknown')
    
    # 1. Geo Velocity
    coords = df['geo_location'].apply(lambda x: get_coords(x))
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
    
    # Group by entity
    grouped = df.groupby('entity_id')
    
    df['recent_failed_auth_count'] = grouped['is_failed_auth'].transform(lambda x: x.rolling('10min').sum())
    
    rolling_mean_dur = grouped['session_duration'].transform(lambda x: x.rolling('30D', min_periods=1).mean())
    rolling_std_dur = grouped['session_duration'].transform(lambda x: x.rolling('30D', min_periods=1).std().fillna(1.0))
    df['session_duration_zscore'] = (df['session_duration'] - rolling_mean_dur) / rolling_std_dur
    
    df['hour'] = df.index.hour
    rolling_mean_hour = grouped['hour'].transform(lambda x: x.rolling('30D', min_periods=1).mean())
    df['hour_deviation'] = abs(df['hour'] - rolling_mean_hour)
    
    df['device_factor'] = pd.factorize(df['device_str'])[0]
    cumulative_unique_devices = grouped['device_factor'].transform(lambda x: ~x.duplicated())
    df['is_new_device'] = cumulative_unique_devices.astype(int)
    
    df['geo_factor'] = pd.factorize(df['geo_location'])[0]
    cumulative_unique_geos = grouped['geo_factor'].transform(lambda x: ~x.duplicated())
    df['is_new_geo'] = cumulative_unique_geos.astype(int)
    
    df = df.reset_index()
    
    # Fill NaNs for new entities with Peer-Group Averages
    peer_group_means = df.groupby('entity_type')[['session_duration_zscore', 'hour_deviation']].transform('mean')
    df['session_duration_zscore'] = df['session_duration_zscore'].fillna(peer_group_means['session_duration_zscore']).fillna(0)
    df['hour_deviation'] = df['hour_deviation'].fillna(peer_group_means['hour_deviation']).fillna(0)
    
    return df

def calculate_metrics(model, X, y_true, normal_idx):
    probs = model.predict_proba(X)
    
    y_true_binary = (y_true != normal_idx).astype(int) 
    probs_attack = 1.0 - probs[:, normal_idx]
    
    preds = np.argmax(probs, axis=1)
    preds_binary = (preds != normal_idx).astype(int)
    
    precision, recall, _ = precision_recall_curve(y_true_binary, probs_attack)
    pr_auc = auc(recall, precision)
    
    recall_val = recall_score(y_true_binary, preds_binary, zero_division=0)
    precision_val = precision_score(y_true_binary, preds_binary, zero_division=0)
    
    tn, fp, fn, tp = confusion_matrix(y_true_binary, preds_binary).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    
    return pr_auc, recall_val, precision_val, fpr

def main():
    print("=== STARTING CONTINUOUS RETRAINING PIPELINE ===")
    
    df, has_feedback = load_and_merge_feedback()
    if not has_feedback:
        return
        
    print("Re-computing behavioral profiles (30-day rolling window)...")
    df = compute_rolling_features(df)
    
    from sklearn.model_selection import train_test_split
    train_df, eval_df = train_test_split(df, test_size=0.2, stratify=df['label'], random_state=42)
    
    # 2. Feature Engineering
    feature_cols = ['hour_deviation', 'session_duration_zscore', 'is_new_device', 'is_new_geo', 
                    'geo_velocity', 'recent_failed_auth_count', 'has_privileged_command']
    
    # 2. Load CURRENT Models
    print("Loading current models for baseline comparison...")
    try:
        current_xgb = joblib.load(os.path.join(DATA_DIR, 'xgboost.joblib'))
        le = joblib.load(os.path.join(DATA_DIR, 'label_encoder.joblib'))
        
        # Ensure normal mapping
        normal_idx = le.transform(['normal'])[0]
        if normal_idx != 0:
            print("Warning: 'normal' class is not index 0. Metrics logic may need adjustment.")
            
        X_eval = eval_df[feature_cols]
        y_eval = le.transform(eval_df['label'])
        
        curr_pr_auc, curr_rec, curr_prec, curr_fpr = calculate_metrics(current_xgb, X_eval, y_eval, normal_idx)
    except FileNotFoundError:
        print("[WARNING] Current models not found locally (likely still in Colab). Establishing baseline at 0.0 to force initial deployment.")
        # Fit a new LabelEncoder on the entire dataset to ensure we have one
        le = LabelEncoder()
        le.fit(df['label'])
        normal_idx = le.transform(['normal'])[0]
        
        curr_pr_auc, curr_rec, curr_prec, curr_fpr = 0.0, 0.0, 0.0, 1.0
        X_eval = eval_df[feature_cols]
        y_eval = le.transform(eval_df['label'])
    
    # 3. Train CANDIDATE Models
    print("Training candidate Isolation Forest on refreshed normal data...")
    X_train_baseline = train_df[train_df['label'].isin(['normal', 'insider_drift'])][feature_cols]
    cand_iso = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
    cand_iso.fit(X_train_baseline)
    
    print("Training candidate XGBoost classifier...")
    X_train = train_df[feature_cols]
    y_train = le.transform(train_df['label'])
    
    cand_xgb = xgb.XGBClassifier(
        objective='multi:softprob',
        num_class=len(le.classes_),
        eval_metric='mlogloss',
        use_label_encoder=False,
        random_state=42
    )
    cand_xgb.fit(X_train, y_train)
    
    cand_pr_auc, cand_rec, cand_prec, cand_fpr = calculate_metrics(cand_xgb, X_eval, y_eval, normal_idx)
    
    # 4. Gating Logic
    print("\n--- MODEL EVALUATION REPORT ---")
    print(f"{'Metric':<20} | {'Current Model':<15} | {'Candidate Model':<15}")
    print("-" * 55)
    print(f"{'PR-AUC':<20} | {curr_pr_auc:.4f}{'':<9} | {cand_pr_auc:.4f}")
    print(f"{'Recall':<20} | {curr_rec:.4f}{'':<9} | {cand_rec:.4f}")
    print(f"{'Precision':<20} | {curr_prec:.4f}{'':<9} | {cand_prec:.4f}")
    print(f"{'False Positive Rate':<20} | {curr_fpr:.4f}{'':<9} | {cand_fpr:.4f}")
    print("-" * 55)
    
    # Thresholds: PR-AUC, Recall, Precision must be >= (or very close to avoid micro-regressions), FPR must be <=
    # We add a small tolerance (0.02 or 2%) to allow for natural training variance
    # while strictly preventing major regressions.
    tol = 0.02
    if (cand_pr_auc >= curr_pr_auc - tol and
        cand_rec >= curr_rec - tol and
        cand_prec >= curr_prec - tol and
        cand_fpr <= curr_fpr + tol):
        
        print("\n[SUCCESS] Candidate model MEETS or BEATS current thresholds.")
        print("Promoting Candidate to Active Model...")
        joblib.dump(cand_iso, os.path.join(DATA_DIR, 'iso_forest.joblib'))
        joblib.dump(cand_xgb, os.path.join(DATA_DIR, 'xgboost.joblib'))
        
        # Save refreshed scored data
        df['anomaly_score'] = -cand_iso.score_samples(df[feature_cols])
        probs = cand_xgb.predict_proba(df[feature_cols])
        df['predicted_attack_class'] = le.inverse_transform(np.argmax(probs, axis=1))
        df['attack_confidence'] = np.max(probs, axis=1)
        df.to_csv(os.path.join(DATA_DIR, 'scored_events.csv'), index=False)
        
        print("Deployment Complete.")
    else:
        print("\n[FAILURE] Candidate model DID NOT meet all thresholds.")
        print("Rejecting Candidate Model. Active models remain unchanged.")

if __name__ == "__main__":
    main()
