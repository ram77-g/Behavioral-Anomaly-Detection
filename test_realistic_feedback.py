import pandas as pd
import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)

DATA_DIR = './data'

print("Loading scored events...")
events_df = pd.read_csv(os.path.join(DATA_DIR, 'scored_events.csv'))

# Find actual normal events to act as our realistic false positives
fps = events_df[events_df['label'] == 'normal']
fps_sample = fps.sample(10, random_state=42)

with engine.begin() as conn:
    max_id_res = conn.execute(text("SELECT MAX(id) FROM alerts")).fetchone()
    next_id = (max_id_res[0] or 0) + 1
    
    for idx, row in fps_sample.iterrows():
        # Insert a fake alert just so feedback works
        conn.execute(
            text("""
            INSERT INTO alerts (id, entity_id, timestamp, predicted_attack_class, status, adaptive_risk_score, mitre_mapping_id, mitre_mapping_tactic, recommendation, analyst_notes)
            VALUES (:id, :eid, :ts, 'brute_force', 'Resolved - False Positive', 90, 'T1110', 'Credential Access', 'Ignore', 'Correcting the model')
            """),
            {"id": next_id, "eid": row['entity_id'], "ts": str(row['timestamp'])}
        )
        next_id += 1

print("Realistic feedback successfully injected into PostgreSQL.")
