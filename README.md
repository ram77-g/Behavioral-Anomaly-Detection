# Honeywell SOC Assistant: AI-Powered Behavioral Anomaly Detection

**Version:** v1.5 (Live Simulation Integrated)

## Application Description
The Honeywell SOC Assistant is an AI-powered Cybersecurity Analyst Copilot designed to combat alert fatigue in modern Security Operations Centers. Unlike traditional SIEM systems that rely on static rules, this platform leverages Unsupervised and Supervised Machine Learning (Isolation Forest & XGBoost) to learn the unique behavioral baselines of network entities (users and edge devices) in real-time. It automatically detects anomalies, classifies cyber attacks with high precision, reconstructs complex multi-stage Kill Chains, and explains its exact reasoning using Explainable AI (SHAP) directly within an interactive React dashboard.

---

## Full List of Implemented Features

### Data Generation & Simulation
- **Highly Realistic Synthetic Data Generator:** Automatically creates an enterprise environment with 500 users and 50 infrastructure edge devices.
- **Dynamic Behavioral Baselines:** Users have deterministic geographic and temporal behaviors, mapping to actual real-world IP blocks and cities.
- **Rigorous Attack Signatures:** Injects multiple classes of attacks (Brute Force, Credential Stuffing, Impossible Travel, Lateral Movement, Device Spoofing, Low-and-Slow).
- **Statistical Jitter & Drift:** Integrates mathematical jitter across attack parameters and simulates legitimate insider drift to ensure models don't overfit to noise.
- **True Live Simulation Engine:** A background `asyncio` engine running inside FastAPI that mathematically computes continuous baseline metrics (cold-start uniqueness, z-scores) dynamically over streaming data ticks.

### Core Machine Learning
- **Advanced Rolling Feature Engineering:** Transforms raw telemetry (duration, time, location) into complex sliding-window physical and network characteristics.
- **Isolation Forest (Anomaly Detection):** An unsupervised model deployed to isolate statistical outliers from normal baseline activity.
- **XGBoost (Attack Classification):** A supervised model that ingests anomalies and predicts the exact class of cyber attack with granular probability confidence arrays.

### Explainable AI & Attack Chains
- **Temporal Chain Linker:** A state machine sliding-window that correlates disjointed alerts across different times and entities into full MITRE ATT&CK Kill Chains (e.g., Credential Compromise, Lateral Movement).
- **Explainable AI (SHAP):** Calculates the exact mathematical weight of each feature that triggered an alert, translating raw numbers into plain-English reasoning for analysts.
- **MITRE ATT&CK Integration:** Every alert and chain is automatically mapped to standardized MITRE Framework IDs and associated with actionable remediation playbooks.

### Full-Stack Dashboard
- **React (Vite) Frontend:** A sleek, glassmorphic UI featuring a dark-mode, micro-animations, and interactive components.
- **Real-Time WebSockets:** Instantly streams detected live threats from the FastAPI backend to the dashboard without refreshing.
- **Interactive Relationship Graphs (vis-network):** Visually maps how entities, IPs, and geographic locations are connected during a cyber attack.
- **Historical Analysis & Trendlines:** Dynamic charts displaying network risk scores over time.
- **One-Click Incident Reporting:** Generates downloadable PDF security reports directly from the active alert pane.
- **PostgreSQL Database Storage:** A fully integrated Postgres database that durably persists all historical alerts, mappings, and SHAP reasoning for persistent review and historical analysis.

---

## Setup Instructions

### 1. Prerequisites
* Python 3.9+
* Node.js v18+
* PostgreSQL installed and running locally

### 2. Database Configuration
1. Create a PostgreSQL database named `Anomaly`.
2. Rename the `.env.example` file to `.env` in the root directory.
3. Update the `DATABASE_URL` in the `.env` file with your local PostgreSQL credentials:
   `DATABASE_URL=postgresql://username:password@localhost:5432/Anomaly`

### 3. Machine Learning Pipeline Execution
Our pipeline is designed to run 100% locally on your machine.
1. Open a terminal in the root directory.
2. Install Python dependencies: `pip install pandas numpy scikit-learn xgboost shap sqlalchemy psycopg2-binary fastapi uvicorn websockets python-dotenv joblib requests`
3. Run `python phase1_data_generator.py` to generate the foundational dataset (`data/events.csv`).
4. Run `python phase2_core_ml.py` to engineer features and train the Isolation Forest and XGBoost models.
5. Run `python phase3_chain_and_shap.py` to link temporal attack chains, generate SHAP explanations, and output the `data/final_alerts.csv`.

### 4. Backend Setup
1. Open a terminal in the root directory.
2. Start the FastAPI server: `python -m uvicorn phase4_backend:app --reload`
* The backend will automatically initialize the database table using the `data/final_alerts.csv` on the first startup.

### 5. Frontend Setup
1. Open a new terminal and navigate to the `dashboard` directory.
2. Install Node dependencies: `npm install`
3. Start the React development server: `npm run dev`
4. Access the SOC Assistant dashboard in your browser at the provided localhost URL.
5. **Live Simulation:** Once on the dashboard, toggle the "Live Simulation" button at the top and hit **Start** to watch the real-time event stream!
