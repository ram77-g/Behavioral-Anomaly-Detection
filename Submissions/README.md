# Honeywell SOC Assistant: AI-Powered Behavioral Anomaly Detection

**Version:** v1.6 (Live Simulation Integrated)

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
- **Cold-Start Handling:** New entities with no history are scored against peer-group behavioral baselines until enough personal history accumulates.
- **Concept Drift Handling:** Rolling-window baseline updates let legitimate behavioral change age in naturally, rather than permanently flagging a user whose normal patterns have shifted.
- **Continuous Learning Pipeline:** A retrain-and-gate mechanism that trains a candidate model on newly verified analyst feedback and only promotes it to production if it measurably beats the current model on precision, recall, PR-AUC, and false positive rate.

### Explainable AI & Attack Chains
- **Temporal Chain Linker:** A state machine sliding-window that correlates disjointed alerts across different times and entities into full MITRE ATT&CK Kill Chains (e.g., Credential Compromise, Lateral Movement).
- **Explainable AI (SHAP):** Calculates the exact mathematical weight of each feature that triggered an alert, translating raw numbers into plain-English reasoning for analysts.
- **MITRE ATT&CK Integration:** Every alert and chain is automatically mapped to standardized MITRE Framework IDs and associated with actionable remediation playbooks.

### Full-Stack Dashboard
- **React (Vite) Frontend:** A sleek, glassmorphic UI featuring a dark-mode, micro-animations, and interactive components.
- **Overview Landing Dashboard:** A dedicated aggregate metrics panel presenting real-time attack type breakdowns, average risk scores, and total alert volumes.
- **Advanced Alert Queue Explorer:** Features real-time search and multi-variable filtering (by Tier, Entity ID, and Attack Class) to cleanly triage massive alert volumes.
- **Real-Time WebSockets:** Instantly streams detected live threats from the FastAPI backend to the dashboard without refreshing.
- **Interactive Relationship Graphs (vis-network):** Visually maps how entities, IPs, and geographic locations are connected during a cyber attack.
- **Historical Analysis & Trendlines:** Dynamic charts displaying network risk scores over time.
- **One-Click Incident Reporting:** Generates downloadable PDF security reports directly from the active alert pane.
- **PostgreSQL Database Storage:** A fully integrated Postgres database that durably persists all historical alerts, mappings, and SHAP reasoning for persistent review and historical analysis.

---

## Quick Start & Setup Instructions

Getting the project up and running is straightforward. The project is split into the **ML Pipeline**, the **FastAPI Backend**, and the **React Frontend**.

### 1. Prerequisites
* **Python 3.9+**
* **Node.js v18+**
* **PostgreSQL** (installed and running locally)

### 2. Database Configuration
1. Open your local PostgreSQL instance (via pgAdmin or psql) and create a new database named `Anomaly`.
2. In the root directory of this project, rename the `.env.example` file to `.env`.
3. Open `.env` and update the `DATABASE_URL` with your local PostgreSQL credentials:
   ```env
   DATABASE_URL=postgresql://username:password@localhost:5432/Anomaly
   ```

### 3. Machine Learning Pipeline Execution

1. Open a terminal in the root directory.
2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run Phase 1 to generate a fresh synthetic dataset (`data/events.csv`):
   ```bash
   python phase1_data_generator.py
   ```
4. Run Phase 2 to engineer features and train the Isolation Forest & XGBoost models:
   ```bash
   python phase2_core_ml.py
   ```
5. Run Phase 3 to link temporal attack chains, generate SHAP explanations, and output the final alerts:
   ```bash
   python phase3_chain_and_shap.py
   ```

### 4. Start the FastAPI Backend
1. Open a terminal in the root directory.
2. Start the backend server using Uvicorn:
   ```bash
   python -m uvicorn phase4_backend:app --reload
   ```
*Note: On its very first startup, the backend will automatically connect to PostgreSQL, initialize the database tables, and seed them using the `data/final_alerts.csv` generated in Phase 3.*

### 5. Start the React Frontend Dashboard
1. Open a **new** terminal and navigate into the `dashboard` directory:
   ```bash
   cd dashboard
   ```
2. Install the necessary Node dependencies:
   ```bash
   npm install
   ```
3. Start the React development server:
   ```bash
   npm run dev
   ```
4. Click the `localhost` URL provided in the terminal to access the SOC Assistant dashboard in your browser.
5. **Live Simulation Demo:** Once on the dashboard, toggle the **"Live Simulation"** button at the top menu and hit **Start** to watch the real-time event stream and continuous ML inference in action!

---

## Limitations & Tradeoffs

While the SOC Assistant is a highly functional prototype, there are deliberate design tradeoffs and inherent limitations within the current architecture:

1. **Synthetic Data Constraints:** The entire training and evaluation pipeline relies on synthetically generated data. While we rigorously model noise, temporal spacing, and baseline drift, synthetic data fundamentally cannot capture every obscure, compounding dependency or behavioral anomaly present in a real-world enterprise network.
2. **Dataset Size & Class Imbalance:** To ensure the pipeline executes swiftly on local machines for the hackathon demonstration, the dataset size is intentionally constrained. Real-world SIEMs process terabytes of data daily. Furthermore, while we employ sample weighting, the artificial class imbalance ratios may not perfectly mirror real-world attack distributions.
3. **Database Architecture:** The current implementation uses a single-node PostgreSQL architecture. This limits concurrent read/write throughput during high-velocity live simulations. In a production environment, this would need to be replaced with a distributed time-series database or a scalable event streaming platform (e.g., Apache Kafka).
4. **Feature Engineering vs. Deep Learning (Deliberate Tradeoff):** We consciously chose to use explicit, rolling-window feature engineering paired with XGBoost rather than deploying recurrent deep learning models (like LSTMs). While an LSTM could theoretically uncover deeper sequential patterns on its own, it acts as an impenetrable "black box." In cybersecurity, an analyst must understand exactly *why* an alert fired. Our feature-engineered approach allows SHAP to perfectly dissect the model's reasoning and provide plain-English, actionable explainability. We traded marginal deep-learning pattern recognition for 100% analyst transparency and trust.
