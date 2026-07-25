import os
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set. Please configure your .env file.")

engine = create_engine(DATABASE_URL)
with engine.begin() as conn:
    conn.execute(text("UPDATE alerts SET status = 'Resolved - False Positive' WHERE id IN (1, 2, 3)"))
    conn.execute(text("UPDATE alerts SET status = 'Resolved - True Positive' WHERE id IN (4, 5)"))
print("Added dummy feedback.")
