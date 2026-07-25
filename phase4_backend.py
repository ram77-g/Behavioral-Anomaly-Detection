# ==========================================
# PHASE 4: BACKEND API & RISK SCORING (POSTGRESQL VERSION)
# ==========================================
# Run this locally using: python -m uvicorn phase4_backend:app --reload

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
import numpy as np
import os
from sqlalchemy import create_engine, text, inspect
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Honeywell SOC Assistant API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    'normal': {'id': 'None', 'tactic': 'None'}
}

ACTION_RECOMMENDATIONS = {
    'brute_force': 'Temporarily block source IP and monitor account.',
    'credential_stuffing': 'Force password reset and enable MFA.',
    'impossible_travel': 'Verify login with user via out-of-band communication.',
    'lateral_movement': 'Isolate host, revoke temporary session tokens.',
    'device_spoofing': 'Require re-authentication and device registration.',
    'chain_credential_compromise': 'CRITICAL: Lock account immediately, initiate Incident Response.',
    'normal': 'No action required.'
}

# 2. Adaptive Risk Scoring
def calculate_risk_score(row):
    score = 0
    score += min(max(row.get('anomaly_score', 0) * 15, 0), 20)
    
    if row.get('attack_confidence', 0) > 0.8: score += 15
    if row.get('chain_involved', False): score += 40
    if row.get('resource_accessed') in ['Payroll', 'Production_DB']: score += 25
    if row.get('is_new_device', 0) == 1: score += 15
    if row.get('is_new_geo', 0) == 1: score += 10
        
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
        print("Connected to PostgreSQL! Alerts table already exists.")
        return
        
    print(f"Initializing PostgreSQL database from {DATA_FILE}...")
    if not os.path.exists(DATA_FILE):
        print(f"ERROR: Cannot find {DATA_FILE}")
        return
        
    df = pd.read_csv(DATA_FILE)
    
    # Filter to only keep alerts (attacks or chain-involved)
    mask = (df['predicted_attack_class'] != 'normal') | (df['chain_involved'] == True)
    df = df[mask].copy()
    
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
        
        attack_type = alert['predicted_attack_class'] if not alert['chain_involved'] else 'chain_credential_compromise'
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
    
    # Write to PostgreSQL
    df.to_sql('alerts', engine, index=False)
    
    # Add a primary key constraint to the id column so we can easily update it
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE alerts ADD PRIMARY KEY (id);"))
        
    print(f"Successfully wrote {len(df)} enriched alerts to PostgreSQL.")

# 4. API Endpoints
@app.get("/api/alerts")
def get_alerts():
    with engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM alerts WHERE status = 'Open' ORDER BY adaptive_risk_score DESC"))
        # Restructure flat MITRE columns back into dictionary object for the frontend
        alerts = []
        for row in result.mappings():
            d = dict(row)
            d['mitre_mapping'] = {'id': d.pop('mitre_mapping_id'), 'tactic': d.pop('mitre_mapping_tactic')}
            alerts.append(d)
        return {"status": "success", "total": len(alerts), "data": alerts}

@app.get("/api/entity/{entity_id}/history")
def get_entity_history(entity_id: str):
    with engine.connect() as conn:
        query = text("SELECT timestamp, adaptive_risk_score FROM alerts WHERE entity_id = :eid ORDER BY timestamp DESC")
        result = conn.execute(query, {"eid": entity_id})
        trend = [{"timestamp": row.timestamp, "risk_score": row.adaptive_risk_score} for row in result]
        return {"status": "success", "entity_id": entity_id, "risk_trend": trend[::-1]}

class FeedbackRequest(BaseModel):
    decision: str 
    notes: str = ""

@app.post("/api/alerts/{alert_id}/feedback")
def submit_feedback(alert_id: int, feedback: FeedbackRequest):
    new_status = 'Resolved - True Positive' if feedback.decision == 'accept' else 'Resolved - False Positive'
    
    with engine.begin() as conn:
        result = conn.execute(
            text("UPDATE alerts SET status = :status, analyst_notes = :notes WHERE id = :id"),
            {"status": new_status, "notes": feedback.notes, "id": alert_id}
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
            
    return {"status": "success", "message": f"Feedback logged for alert {alert_id} in PostgreSQL."}
