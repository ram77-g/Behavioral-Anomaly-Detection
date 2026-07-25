# Honeywell SOC Assistant: AI-Powered Behavioral Anomaly Detection

**Version:** v1.1 (Live Simulation Integrated)

---

## Overview

Modern Security Operations Centers (SOCs) are overwhelmed by alert fatigue. Traditional rule-based SIEMs fire thousands of static, false-positive alerts daily. This forces analysts to manually cross-reference IP addresses, piece together fragmented logs across disjointed systems, and guess the context behind an alert, resulting in delayed incident response and missed stealthy attacks.

We built a comprehensive, AI-Powered Behavioral Anomaly Detection Pipeline and Analyst Copilot Dashboard. Instead of relying on static rules, our system learns the unique baseline behavior of every user and device in the network. It uses a sophisticated multi-stage machine learning pipeline to not only detect anomalies but to accurately classify the exact cyber attack in real-time, explain its reasoning in plain English, and provide actionable mitigation steps.

---

## Architecture & Pipeline

Our project is structured into four distinct phases, executing a complete end-to-end data pipeline from raw logs to an interactive UI.

### Phase 1: Synthetic Data Generation & Attack Injection
To train our models, we engineered a highly realistic synthetic data generator that mirrors a real enterprise network.
* **Baseline Profiling:** Generates 500 Users and 50 Devices, each with unique behavioral profiles and a dynamic dictionary of `REAL_CITIES` for deterministic geo-velocity tracking.
* **Rigorous Attack Signatures:** Injects cyber attacks including Brute Force, Credential Stuffing, Impossible Travel, Lateral Movement, Device Spoofing, and Low-and-Slow Exfiltration. Target routing randomly compromises infrastructure edge devices alongside normal users.
* **Mathematical Jitter & Drift:** Implements `np.random.normal()` statistical jitter across all attack durations and timestamps to ensure organically distributed ML probabilities. We also intentionally inject `insider_drift` (a legitimate, gradual footprint expansion) to force the unsupervised models to learn organic baseline shifts without throwing false positives.
* **Live Chain Injection Queue:** Utilizes a stateful queue to deterministically orchestrate multi-step `chain_credential_compromise` attacks, pushing distinct steps (e.g. VPN Access -> Config Changes -> Data Exfiltration) sequentially across multiple continuous intervals rather than all at once.

### Phase 2: Core Machine Learning & Feature Engineering
We transform raw logs into mathematical vectors to train our AI models.
* **Advanced Feature Engineering:** Calculates complex rolling windows across the dataset, such as physical travel speed and rolling standard deviations for session durations.
* **Dual-Model Approach:** An Isolation Forest model evaluates the data to filter out the noise. An XGBoost model then evaluates the anomalies and outputs a probability distribution across all attack classes to determine the AI Confidence Level.

### Phase 3: Attack Chain Linking & XAI (Explainable AI)
* **Temporal Chain Linker:** A sliding-window state machine that connects isolated events across a 2-hour window to detect complex Kill Chains. Built as an extensible library, it is currently seeded with 2 proof-of-concept patterns (Credential Compromise and Stealth Exfiltration).
* **Explainable AI (SHAP):** We integrated the SHAP library to crack open the XGBoost model. It calculates exactly which features drove the AI's decision and translates them into human-readable reasons, providing critical context to the analyst.

### Phase 4: Full-Stack React & FastAPI Dashboard
The final alerts are served to a cutting-edge analyst dashboard powered by PostgreSQL.
* **Dual Environment Backend:** The FastAPI backend securely segregates historical alerts from real-time live simulation streams using distinct database tables (`alerts` vs `live_alerts`) and dedicated WebSocket channels.
* **Adaptive Risk Scoring:** A dynamic backend algorithm that calculates highly varied risk scores (0-100) by directly scaling the raw Isolation Forest anomaly offsets and multiplying the exact XGBoost prediction probabilities, avoiding static blocks of "fake-looking" data. Includes fallback MITRE mapping logic.
* **Live Simulation Engine:** Features a native, built-in `asyncio` background task that simulates real-time attack data ingestion. It has been extensively upgraded from a simple timer-playback to a **True Live Streaming Engine** that mathematically integrates fresh synthetic data into a sliding temporal context window. It perfectly handles live continuous feature derivation, cold-start baselines, and injects temporally distributed multi-step attack chains across distinct simulation ticks to accurately simulate a real adversary kill chain.
* **Frontend UI:** Features a real-time dual-mode dashboard. Analysts can instantly toggle between static investigation and the live event stream. It includes a dynamic attack relationship network graph, historical risk trendlines, fully integrated start/pause/reset simulation controls, one-click PDF incident report generation, and a direct database feedback loop for continuous learning.

---

## Tech Stack

**Machine Learning & Data Processing:**
* Python
* Scikit-Learn (Isolation Forest)
* XGBoost
* SHAP (Explainable AI)
* Pandas & Numpy

**Backend API:**
* FastAPI (REST & WebSockets)
* Uvicorn
* SQLAlchemy (PostgreSQL Integration)
* Asyncio (Live Simulation Engine)

**Frontend Dashboard:**
* React (Vite)
* Custom CSS Glassmorphism
* vis-network (Interactive Relationship Graphs)
* recharts (Trendlines)
* jsPDF (Automated Reporting)
* Lucide Icons

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
2. Install Python dependencies: `pip install pandas numpy scikit-learn xgboost shap sqlalchemy psycopg2-binary fastapi uvicorn websockets python-dotenv`
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

---

## Continuous Learning

The system implements a continuous learning loop. When an analyst resolves an alert in the dashboard (marking it as a False Positive or Confirming the Threat), the decision is logged in PostgreSQL. The `retrain_pipeline.py` script can be run nightly to pull this feedback, merge it into the historical data, dynamically recalculate behavioral baselines, and retrain a Candidate Model that is only promoted to production if it beats the current active model's metrics.
