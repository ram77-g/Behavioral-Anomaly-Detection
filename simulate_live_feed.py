import pandas as pd
import time
import requests
import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)

# Import backend logic
from phase4_backend import calculate_risk_score, MITRE_MAPPING, ACTION_RECOMMENDATIONS

print("========================================")
print(" LIVE INGESTION SIMULATOR ")
print("========================================")
print("Clearing existing database alerts...")

with engine.begin() as conn:
    conn.execute(text("TRUNCATE TABLE live_alerts;"))

df = pd.read_csv('./data/final_alerts.csv')
mask = (df['predicted_attack_class'] != 'normal') | (df['chain_involved'] == True)
df = df[mask].copy().reset_index(drop=True)

# For a better live demo, let's deduplicate consecutive attacks from the same entity
df['is_consecutive_duplicate'] = (df['entity_id'] == df['entity_id'].shift()) & (df['predicted_attack_class'] == df['predicted_attack_class'].shift())
df = df[~df['is_consecutive_duplicate']].drop(columns=['is_consecutive_duplicate']).reset_index(drop=True)

print(f"Streaming {len(df)} alerts to the dashboard in real-time...")
print("👉 OPEN YOUR REACT DASHBOARD NOW 👈\n")

for i, row in df.iterrows():
    alert = row.to_dict()
    
    risk_score = calculate_risk_score(alert)
    attack_type = alert['predicted_attack_class'] if not alert['chain_involved'] else 'chain_credential_compromise'
    mapping = MITRE_MAPPING.get(attack_type, MITRE_MAPPING['normal'])
    
    enriched_df = pd.DataFrame([{
        **alert,
        'id': i + 1,
        'adaptive_risk_score': risk_score,
        'mitre_mapping_id': mapping['id'],
        'mitre_mapping_tactic': mapping['tactic'],
        'recommendation': ACTION_RECOMMENDATIONS.get(attack_type, 'Investigate further.'),
        'status': 'Open',
        'analyst_notes': ''
    }])
    
    # Insert safely without overwriting schema
    enriched_df.to_sql('live_alerts', engine, if_exists='append', index=False)
    
    # Trigger WebSocket Push
    try:
        requests.post("http://127.0.0.1:8000/api/broadcast?mode=live")
    except:
        pass
        
    print(f"[{i+1}/{len(df)}] 🔴 Pushed Live Alert: {alert['entity_id']} -> {attack_type}")
    
    # Wait 3 seconds to simulate live ingestion
    time.sleep(3.0) 
