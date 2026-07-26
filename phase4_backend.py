# ==========================================
# PHASE 4: BACKEND API & RISK SCORING (POSTGRESQL VERSION)
# ==========================================
# Run this locally using: python -m uvicorn phase4_backend:app --reload

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from typing import List
import json
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import numpy as np
import os
import asyncio
from sqlalchemy import create_engine, text, inspect
from dotenv import load_dotenv
from phase2_core_ml import compute_rolling_features
from phase3_chain_and_shap import detect_chains, CHAIN_PATTERNS

load_dotenv()

app = FastAPI(title="Honeywell SOC Assistant API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager_static = ConnectionManager()
manager_live = ConnectionManager()

# Database Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set. Please configure your .env file.")
engine = create_engine(DATABASE_URL)

# 1. Static Lookups
MITRE_MAPPING = {
    'brute_force': {'id': 'T1110', 'tactic': 'Credential Access'},
    'credential_stuffing': {'id': 'T1110.004', 'tactic': 'Credential Access'},
    'impossible_travel': {'id': 'T1078', 'tactic': 'Initial Access'},
    'lateral_movement': {'id': 'T1021', 'tactic': 'Lateral Movement'},
    'device_spoofing': {'id': 'T1036', 'tactic': 'Defense Evasion'},
    'chain_credential_compromise': {'id': 'T1078 -> T1567', 'tactic': 'Initial Access -> Exfiltration'},
    'chain_stealth_exfiltration': {'id': 'T1078 -> T1048', 'tactic': 'Initial Access -> Exfiltration'},
    'chain_brute_force_success': {'id': 'T1110 -> T1078', 'tactic': 'Credential Access -> Initial Access'},
    'chain_lateral_movement': {'id': 'T1021 -> T1059', 'tactic': 'Lateral Movement -> Execution'},
    'insider_drift': {'id': 'T1078.004', 'tactic': 'Monitor - Valid Accounts'},
    'low_and_slow': {'id': 'T1110.003', 'tactic': 'Credential Access - Password Spraying'},
    'normal': {'id': 'None', 'tactic': 'None'}
}

ACTION_RECOMMENDATIONS = {
    'brute_force': 'Temporarily block source IP and monitor account.',
    'credential_stuffing': 'Force password reset and enable MFA.',
    'impossible_travel': 'Verify login with user via out-of-band communication.',
    'lateral_movement': 'Isolate host, revoke temporary session tokens.',
    'device_spoofing': 'Require re-authentication and device registration.',
    'chain_credential_compromise': 'CRITICAL: Lock account immediately, initiate Incident Response.',
    'chain_stealth_exfiltration': 'CRITICAL: Block DB access, monitor for data extrusion, reset credentials.',
    'chain_brute_force_success': 'CRITICAL: Compromised account via brute force. Lock immediately.',
    'chain_lateral_movement': 'CRITICAL: Lateral movement detected. Isolate host and revoke all tokens.',
    'insider_drift': 'Monitor user footprint for legitimate role changes.',
    'low_and_slow': 'Monitor for distributed login attempts over long durations.',
    'normal': 'No action required.'
}

# 2. Adaptive Risk Scoring
def calculate_risk_score(row):
    score = 0
    
    # 1. Anomaly component (up to ~25 points)
    # The anomaly score generally ranges from ~0.35 (normal) to 0.85 (highly anomalous).
    anomaly_val = max(row.get('anomaly_score', 0.35) - 0.35, 0)
    score += min(anomaly_val * 50, 25)
    
    # 2. ML Classification component (up to ~45 points)
    if row.get('predicted_attack_class', 'normal') not in ['normal', 'insider_drift']:
        conf = row.get('attack_confidence', 0)
        # Use the raw probability to scale the score continuously
        score += (conf * 45)
            
    # 3. Contextual Risk Adders
    if row.get('chain_involved', False): 
        score += 20
    if row.get('resource_accessed') in ['Payroll', 'Production_DB', 'AWS_Console']: 
        score += 15
    if row.get('is_new_device', 0) == 1: 
        score += 10
    if row.get('is_new_geo', 0) == 1: 
        score += 10
        
    return min(int(score), 100)

# 3. Startup: Database Initialization
DATA_FILE = './data/final_alerts.csv'

@app.on_event("startup")
def init_db():
    if os.getenv("RESET_DB", "false").lower() == "true":
        print("RESET_DB flag detected. Dropping alerts table...")
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE IF EXISTS alerts"))
            
    insp = inspect(engine)
    if insp.has_table('alerts'):
        if not insp.has_table('live_alerts'):
            with engine.begin() as conn:
                conn.execute(text("CREATE TABLE live_alerts (LIKE alerts INCLUDING ALL);"))
        print("Connected to PostgreSQL! Alerts table already exists.")
        return
        
    print(f"Initializing PostgreSQL database from {DATA_FILE}...")
    if not os.path.exists(DATA_FILE):
        print(f"ERROR: Cannot find {DATA_FILE}")
        return
        
    df = pd.read_csv(DATA_FILE)
    
    # Calculate threshold on full dataset
    top_1_threshold = np.percentile(df['anomaly_score'], 99)
    
    # Filter to only keep alerts (Tier 1 strict budget OR Tier 2 safety net)
    mask = (df['anomaly_score'] >= top_1_threshold) | (df['predicted_attack_class'] != 'normal') | (df['chain_involved'] == True)
    df = df[mask].copy()
    
    df['alert_tier'] = np.where(df['anomaly_score'] >= top_1_threshold, 'Tier 1 (Strict 1%)', 'Tier 2 (Safety Net)')
    
    # Fix NaN truthiness
    df['chain_involved'] = df['chain_involved'].fillna(False)
    df['chain_type'] = df['chain_type'].replace({np.nan: None})
    
    # Add an ID column
    df.insert(0, 'id', range(1, len(df) + 1))
    
    # Enrich data
    risk_scores = []
    mitre_ids = []
    mitre_tactics = []
    recs = []
    
    for _, row in df.iterrows():
        alert = row.to_dict()
        risk_scores.append(calculate_risk_score(alert))
        
        attack_type = alert['predicted_attack_class'] if not alert.get('chain_involved') else alert.get('chain_type', 'chain_credential_compromise')
        mapping = MITRE_MAPPING.get(attack_type, MITRE_MAPPING['normal'])
        
        mitre_ids.append(mapping['id'])
        mitre_tactics.append(mapping['tactic'])
        recs.append(ACTION_RECOMMENDATIONS.get(attack_type, 'Investigate further.'))
        
    df['adaptive_risk_score'] = risk_scores
    df['mitre_mapping_id'] = mitre_ids
    df['mitre_mapping_tactic'] = mitre_tactics
    df['recommendation'] = recs
    df['status'] = 'Open'
    df['analyst_notes'] = ''
    
    # Drop alert_tier before DB insertion to maintain schema consistency
    db_df = df.drop(columns=['alert_tier'], errors='ignore')
    
    # Write to PostgreSQL for Static DB
    db_df.to_sql('alerts', engine, index=False)
    
    # Create the live_alerts table by copying the schema but with 0 rows
    db_df.iloc[0:0].to_sql('live_alerts', engine, if_exists='replace', index=False)
    
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE alerts ADD PRIMARY KEY (id);"))
        conn.execute(text("ALTER TABLE live_alerts ADD PRIMARY KEY (id);"))
        
    print(f"Successfully wrote {len(df)} enriched alerts to PostgreSQL.")

# 4. API Endpoints
def _fetch_alerts_data(table="alerts"):
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT * FROM {table} WHERE status = 'Open' ORDER BY adaptive_risk_score DESC"))
        alerts = []
        for row in result.mappings():
            d = dict(row)
            d['mitre_mapping'] = {'id': d.pop('mitre_mapping_id'), 'tactic': d.pop('mitre_mapping_tactic')}
            alerts.append(d)
        return {"status": "success", "total": len(alerts), "data": alerts}

# ----------------------------------------
# LIVE SIMULATION ENGINE (Integrated)
# ----------------------------------------
import random
import joblib
from datetime import datetime
import shap
from phase1_data_generator import SyntheticDataGenerator
from phase2_core_ml import compute_rolling_features, feature_cols
from phase3_chain_and_shap import detect_chains, CHAIN_PATTERNS

sim_task = None
sim_index = 0
is_sim_running = False

live_generator = None
live_context_df = pd.DataFrame()
iso_forest_model = None
xgboost_model = None
label_encoder = None
shap_explainer = None
historical_state = {}

def init_live_engine():
    global live_generator, iso_forest_model, xgboost_model, label_encoder, shap_explainer, historical_state, live_context_df
    if live_generator is not None:
        return # already initialized
        
    print("Initializing True Live Simulation Engine...")
    
    # 1. Load ML Models
    DATA_DIR = './data'
    iso_forest_model = joblib.load(os.path.join(DATA_DIR, 'iso_forest.joblib'))
    xgboost_model = joblib.load(os.path.join(DATA_DIR, 'xgboost.joblib'))
    label_encoder = joblib.load(os.path.join(DATA_DIR, 'label_encoder.joblib'))
    
    # Explainability Engine
    # Note: we use TreeExplainer for XGBoost which is extremely fast
    # If XGBoost is wrapped in CalibratedClassifierCV, unwrap it for SHAP
    shap_base_xgb = xgboost_model
    if hasattr(xgboost_model, "calibrated_classifiers_"):
        base_est = xgboost_model.calibrated_classifiers_[0].estimator
        shap_base_xgb = getattr(base_est, "estimator", base_est)
        
    shap_explainer = shap.TreeExplainer(shap_base_xgb)
    
    # 2. Init Generator
    live_generator = SyntheticDataGenerator(num_users=500, num_devices=50, days=30)
    live_generator.generate_profiles() # Load profiles (fast)
    
    # 3. Load historical context for cold-start (geo/device uniqueness & continuous features)
    events_hist = pd.read_csv(os.path.join(DATA_DIR, 'events.csv'))
    historical_state['devices'] = set(events_hist['device_fingerprint'].fillna('unknown').unique())
    historical_state['geos'] = set(events_hist['geo_location'].unique())
    
    events_hist['timestamp'] = pd.to_datetime(events_hist['timestamp'])
    events_hist['hour'] = events_hist['timestamp'].dt.hour
    
    historical_state['duration_mean'] = events_hist.groupby('entity_id')['session_duration'].mean().to_dict()
    historical_state['duration_std'] = events_hist.groupby('entity_id')['session_duration'].std().to_dict()
    historical_state['hour_mean'] = events_hist.groupby('entity_id')['hour'].mean().to_dict()
    
    historical_state['global_duration_mean'] = events_hist['session_duration'].mean()
    historical_state['global_duration_std'] = events_hist['session_duration'].std()
    historical_state['global_hour_mean'] = events_hist['hour'].mean()
    
    # Seed context df with last ~200 events from history just to have rolling baselines
    events_hist['timestamp'] = pd.to_datetime(events_hist['timestamp'])
    temp_df = events_hist.tail(200).copy()
    temp_featured = compute_rolling_features(temp_df)
    
    # Manually backfill cold-start features for the seed context using historical_state
    temp_featured['is_new_device'] = temp_featured['device_str'].apply(lambda x: 0 if x in historical_state['devices'] else 1)
    temp_featured['is_new_geo'] = temp_featured['geo_location'].apply(lambda x: 0 if x in historical_state['geos'] else 1)
    
    def get_zscore(row):
        eid = row['entity_id']
        mean = historical_state['duration_mean'].get(eid, historical_state['global_duration_mean'])
        std = historical_state['duration_std'].get(eid, historical_state['global_duration_std'])
        std = max(std if pd.notna(std) else 1.0, 1.0)
        return (row['session_duration'] - mean) / std
        
    def get_hour_dev(row):
        eid = row['entity_id']
        mean_hr = historical_state['hour_mean'].get(eid, historical_state['global_hour_mean'])
        hr = pd.to_datetime(row['timestamp']).hour
        return abs(hr - mean_hr)
        
    temp_featured['session_duration_zscore'] = temp_featured.apply(get_zscore, axis=1)
    temp_featured['hour_deviation'] = temp_featured.apply(get_hour_dev, axis=1)
    
    temp_featured['anomaly_score'] = -iso_forest_model.score_samples(temp_featured[feature_cols])
    live_context_df = temp_featured.copy()
async def simulation_loop():
    global sim_index, is_sim_running, live_context_df
    try:
        init_live_engine()
        
        while is_sim_running:
            # 1. Generate new events
            now = datetime.now()
            new_events_df = live_generator.generate_live_events(num_events=random.randint(2, 4), current_timestamp=now)
            
            # 2. Merge with context for rolling features
            new_events_df['is_new_event'] = True
            live_context_df['is_new_event'] = False
            merged_df = pd.concat([live_context_df, new_events_df], ignore_index=True)
            
            # 3. Compute Features (Note: this sorts by entity_id)
            featured_df = compute_rolling_features(merged_df.copy())
            
            # Patch continuous feature baselines utilizing full historical baseline instead of 200-row context
            def get_zscore(row):
                eid = row['entity_id']
                mean = historical_state['duration_mean'].get(eid, historical_state['global_duration_mean'])
                std = historical_state['duration_std'].get(eid, historical_state['global_duration_std'])
                std = max(std if pd.notna(std) else 1.0, 1.0)
                return (row['session_duration'] - mean) / std
                
            def get_hour_dev(row):
                eid = row['entity_id']
                mean_hr = historical_state['hour_mean'].get(eid, historical_state['global_hour_mean'])
                hr = pd.to_datetime(row['timestamp']).hour
                return abs(hr - mean_hr)
                
            featured_df['is_new_device'] = featured_df['device_str'].apply(lambda x: 0 if x in historical_state['devices'] else 1)
            featured_df['is_new_geo'] = featured_df['geo_location'].apply(lambda x: 0 if x in historical_state['geos'] else 1)
            featured_df['session_duration_zscore'] = featured_df.apply(get_zscore, axis=1)
            featured_df['hour_deviation'] = featured_df.apply(get_hour_dev, axis=1)

            # Pre-compute anomaly score on entire context so sliding window retains it for the dynamic threshold
            featured_df['anomaly_score'] = -iso_forest_model.score_samples(featured_df[feature_cols])
            
            # Extract just the newly generated rows using the marker
            current_batch = featured_df[featured_df['is_new_event'] == True].copy()
            
            # Update historical sets
            historical_state['devices'].update(current_batch['device_str'])
            historical_state['geos'].update(current_batch['geo_location'])
            
            # Update continuous baselines via Exponential Moving Average to allow Concept Drift adaptation
            alpha = 0.1
            for _, row in current_batch.iterrows():
                eid = row['entity_id']
                if eid in historical_state['duration_mean']:
                    historical_state['duration_mean'][eid] = (1 - alpha) * historical_state['duration_mean'][eid] + alpha * row['session_duration']
                    historical_state['hour_mean'][eid] = (1 - alpha) * historical_state['hour_mean'][eid] + alpha * pd.to_datetime(row['timestamp']).hour
                else:
                    historical_state['duration_mean'][eid] = row['session_duration']
                    historical_state['duration_std'][eid] = 1.0
                    historical_state['hour_mean'][eid] = pd.to_datetime(row['timestamp']).hour
            
            # 4. ML Scoring (Classification)
            X_batch = current_batch[feature_cols]
            
            # XGBoost Classification
            probs = xgboost_model.predict_proba(X_batch)
            current_batch['predicted_attack_class'] = label_encoder.inverse_transform(np.argmax(probs, axis=1))
            current_batch['attack_confidence'] = np.max(probs, axis=1)
            
            # 5. Chain Linking (Check if these new events complete a chain)
            detect_chains(featured_df, CHAIN_PATTERNS) # mutates featured_df
            
            # Map the chain results back to current_batch securely via index alignment
            chain_updates = featured_df.loc[current_batch.index, ['chain_involved', 'chain_type']]
            current_batch['chain_involved'] = chain_updates['chain_involved'].fillna(False)
            current_batch['chain_type'] = chain_updates['chain_type'].replace({np.nan: None})
            
            # 6. Filtering & SHAP
            threshold = 0.75 # Default threshold if percentile fails
            if 'anomaly_score' in live_context_df.columns:
                threshold = np.percentile(live_context_df['anomaly_score'].dropna(), 99)
            
            mask = (current_batch['anomaly_score'] >= threshold) | \
                   ((current_batch['predicted_attack_class'] != 'normal') & (current_batch['attack_confidence'] > 0.85)) | \
                   (current_batch['chain_involved'] == True)
            
            alerts_df = current_batch[mask].copy()
            
            if not alerts_df.empty:
                alerts_df['alert_tier'] = np.where(alerts_df['anomaly_score'] >= threshold, 'Tier 1 (Strict)', 'Tier 2 (Safety Net)')
            
            # Deduplicate alerts in the same tick to prevent UI/DB spam from attack bursts
            alerts = alerts_df.drop_duplicates(subset=['entity_id', 'predicted_attack_class'], keep='last').reset_index(drop=True)
            
            if len(alerts) > 0:
                print(f"Generated {len(new_events_df)} events. {len(alerts)} alerts detected.")
                # Generate SHAP reasons
                shap_values = shap_explainer.shap_values(alerts[feature_cols])
                reasons = []
                for i in range(len(alerts)):
                    row_reasons = []
                    if pd.notna(alerts.iloc[i]['chain_involved']) and alerts.iloc[i]['chain_involved']:
                        row_reasons.append(f"CRITICAL: Part of {alerts.iloc[i]['chain_type']} chain")
                        
                    pred_class_idx = np.where(label_encoder.classes_ == alerts.iloc[i]['predicted_attack_class'])[0][0]
                    row_shap = shap_values[pred_class_idx][i] if isinstance(shap_values, list) else shap_values[i, :, pred_class_idx] if len(shap_values.shape)==3 else shap_values[i]
                    
                    top_idx = np.argmax(row_shap)
                    if row_shap[top_idx] > 0:
                        row_reasons.append(f"Anomalous {feature_cols[top_idx]}")
                    reasons.append(" | ".join(row_reasons) if row_reasons else "Anomalous baseline deviation")
                
                alerts['reasons'] = reasons
                
                # Push alerts to DB & UI
                for _, row in alerts.iterrows():
                    alert_dict = row.to_dict()
                    
                    if 'is_new_event' in alert_dict:
                        del alert_dict['is_new_event']
                        
                    risk_score = calculate_risk_score(alert_dict)
                    attack_type = alert_dict['predicted_attack_class'] if not alert_dict.get('chain_involved') else alert_dict.get('chain_type', 'chain_credential_compromise')
                    mapping = MITRE_MAPPING.get(attack_type, MITRE_MAPPING['normal'])
                    
                    sim_index += 1
                    enriched_df = pd.DataFrame([{
                        **alert_dict,
                        'id': sim_index,
                        'adaptive_risk_score': risk_score,
                        'mitre_mapping_id': mapping['id'],
                        'mitre_mapping_tactic': mapping['tactic'],
                        'recommendation': ACTION_RECOMMENDATIONS.get(attack_type, 'Investigate further.'),
                        'status': 'Open',
                        'analyst_notes': ''
                    }])
                    
                    # Drop alert_tier before DB insertion to prevent schema mismatch on existing databases
                    if 'alert_tier' in enriched_df.columns:
                        enriched_df = enriched_df.drop(columns=['alert_tier'])
                        
                    enriched_df.to_sql('live_alerts', engine, if_exists='append', index=False)
                    asyncio.create_task(manager_live.broadcast(_fetch_alerts_data("live_alerts")))
            
            # 7. Prune context window to prevent memory leak
            # Must sort by timestamp because compute_rolling_features leaves the df sorted by entity_id!
            live_context_df = featured_df.sort_values('timestamp').tail(200).copy()
            
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        print("Simulation task cancelled gracefully.")
    except Exception as e:
        print(f"Simulation task crashed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        is_sim_running = False

@app.post("/api/simulation/start")
async def start_simulation():
    global sim_task, is_sim_running, sim_index
    if not is_sim_running:
        is_sim_running = True
        
        if sim_index == 0:
            with engine.connect() as conn:
                max_id = conn.execute(text("SELECT MAX(id) FROM live_alerts")).scalar()
                sim_index = max_id if max_id is not None else 0
                
        sim_task = asyncio.create_task(simulation_loop())
    return {"status": "started", "index": sim_index}

@app.post("/api/simulation/stop")
async def stop_simulation():
    global is_sim_running, sim_task
    is_sim_running = False
    if sim_task:
        sim_task.cancel()
    return {"status": "stopped", "index": sim_index}

@app.post("/api/simulation/reset")
async def reset_simulation():
    global is_sim_running, sim_task, sim_index
    is_sim_running = False
    if sim_task:
        sim_task.cancel()
        
    sim_index = 0
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE live_alerts"))
        
    await manager_live.broadcast(_fetch_alerts_data("live_alerts"))
    return {"status": "reset", "index": sim_index}

@app.get("/api/simulation/status")
async def status_simulation():
    return {"is_running": is_sim_running, "index": sim_index}

@app.get("/api/alerts")
def get_alerts(mode: str = "static"):
    table = "live_alerts" if mode == "live" else "alerts"
    return _fetch_alerts_data(table)

@app.websocket("/ws/alerts/{mode}")
async def websocket_alerts(websocket: WebSocket, mode: str):
    mgr = manager_live if mode == "live" else manager_static
    table = "live_alerts" if mode == "live" else "alerts"
    
    await mgr.connect(websocket)
    try:
        await websocket.send_json(_fetch_alerts_data(table))
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        mgr.disconnect(websocket)

@app.post("/api/broadcast")
async def trigger_broadcast(mode: str = "static"):
    mgr = manager_live if mode == "live" else manager_static
    table = "live_alerts" if mode == "live" else "alerts"
    await mgr.broadcast(_fetch_alerts_data(table))
    return {"status": "success"}

@app.get("/api/entity/{entity_id}/history")
def get_entity_history(entity_id: str, mode: str = "static"):
    table = "live_alerts" if mode == "live" else "alerts"
    with engine.connect() as conn:
        query = text(f"SELECT timestamp, adaptive_risk_score FROM {table} WHERE entity_id = :eid ORDER BY timestamp ASC")
        result = conn.execute(query, {"eid": entity_id})
        
        trend = []
        current_ema = None
        alpha = 0.4 # Smoothing factor to prevent wild zig-zags in the graph
        
        for row in result:
            score = row.adaptive_risk_score
            if current_ema is None:
                current_ema = score
            else:
                current_ema = (alpha * score) + ((1 - alpha) * current_ema)
            
            # Format timestamp nicely for UI
            try:
                dt = pd.to_datetime(row.timestamp)
                if mode == "live":
                    ts_str = dt.strftime("%H:%M:%S")
                else:
                    ts_str = dt.strftime("%m/%d %H:%M")
            except:
                ts_str = str(row.timestamp)
                
            trend.append({"timestamp": ts_str, "risk_score": int(current_ema)})
            
        # Return last 20 points max to keep graph readable
        return {"status": "success", "entity_id": entity_id, "risk_trend": trend[-20:]}

class FeedbackRequest(BaseModel):
    decision: str 
    notes: str = ""

@app.post("/api/alerts/{alert_id}/feedback")
async def submit_feedback(alert_id: int, feedback: FeedbackRequest, mode: str = "static"):
    new_status = 'Resolved - True Positive' if feedback.decision == 'accept' else 'Resolved - False Positive'
    
    table = "live_alerts" if mode == "live" else "alerts"
    mgr = manager_live if mode == "live" else manager_static
    
    with engine.begin() as conn:
        result = conn.execute(
            text(f"UPDATE {table} SET status = :status, analyst_notes = :notes WHERE id = :id"),
            {"status": new_status, "notes": feedback.notes, "id": alert_id}
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
            
    # Broadcast updated list to all WebSocket clients for the correct tab
    await mgr.broadcast(_fetch_alerts_data(table))
    
    return {"status": "success", "message": f"Feedback logged for alert {alert_id} in PostgreSQL."}
