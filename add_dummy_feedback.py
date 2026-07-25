from sqlalchemy import create_engine, text
engine = create_engine('postgresql://postgres:ram77_g@localhost:5432/Anomaly')
with engine.begin() as conn:
    conn.execute(text("UPDATE alerts SET status = 'Resolved - False Positive' WHERE id IN (1, 2, 3)"))
    conn.execute(text("UPDATE alerts SET status = 'Resolved - True Positive' WHERE id IN (4, 5)"))
print("Added dummy feedback.")
