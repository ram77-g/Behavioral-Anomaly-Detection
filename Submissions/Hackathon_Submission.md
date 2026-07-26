# Honeywell SOC Assistant: AI-Powered Behavioral Anomaly Detection
**Hackathon Submission Documentation**

## The Problem
Modern Security Operations Centers (SOCs) are overwhelmed by alert fatigue. Traditional rule-based SIEMs fire thousands of static, false-positive alerts daily. This forces analysts to manually cross-reference IP addresses, piece together fragmented logs across disjointed systems, and guess the context behind an alert, resulting in delayed incident response and missed stealthy attacks (APTs).

## Our Solution
We built a complete, end-to-end **AI-Powered Behavioral Anomaly Detection Pipeline** and **Analyst Copilot Dashboard** — not a notebook demo, but a working system with a live database, a real-time API, and a production-style dashboard. Instead of relying on static rules, our system learns the unique baseline behavior of every user and infrastructure edge device in the network, continuously, and adapts as that behavior evolves. It detects anomalies, classifies the exact cyber attack in real-time, links isolated events into full multi-stage kill chains, explains its reasoning in plain English, and recommends the exact action an analyst should take next.

---

## Explicit Assumptions

To constrain the scope of the simulation while maintaining enterprise realism, this architecture relies on the following structural assumptions:
1. **Behavioral Gaussian Distribution:** We assume that legitimate physical human behavior (e.g., login times, session durations) roughly maps to stable statistical distributions that can be modeled using rolling Z-scores.
2. **Fixed Geographic Nodes:** For the `geo_velocity` calculation (Haversine formula), we assume IP addresses can be deterministically resolved to fixed geographic coordinates (e.g., city centers).
3. **Anomaly Budgeting:** We assume that an enterprise SOC has a fixed "Alert Budget" (e.g., they only have the manpower to investigate the top 1% most anomalous events daily), justifying our strict Isolation Forest contamination parameter.
4. **Log Continuity:** The Chain Linker assumes that multi-step attacks occur within a contiguous, unbroken temporal window (e.g., 2 hours), and that the SIEM ingests logs without significant network-induced chronological reordering.

---

## The Technical Flow & Implementation Pipeline

Our project is structured into 4 distinct phases, executing a complete end-to-end data pipeline from raw logs to an interactive real-time UI.

### Phase 1: Synthetic Data Generation & Attack Injection (The Foundation)
To train our models, we engineered a highly realistic synthetic data generator that mirrors a real enterprise network, complete with individual behavioral fingerprints for every entity.
* **Baseline Profiling:** Generates 500 Users and 50 Edge Devices (IoT/Infrastructure), each with unique behavioral profiles (usual login hours, usual geolocations mapped to real cities, standard devices, and resource access patterns).
* **Temporal Noise:** Injects realistic noise (e.g., users occasionally logging in late or traveling) to prevent the ML from overfitting and to stress-test false-positive handling under real-world conditions.
* **Rigorous Attack Signatures & Edge Cases:** Injects 7 highly realistic behavioral classes, covering the full spectrum from loud, obvious attacks to the stealthiest insider threats:
  1. **Brute Force:** High-velocity failed logins ending in a success.
  2. **Credential Stuffing:** One IP targeting multiple different user accounts.
  3. **Impossible Travel:** Geolocation jumps that defy physical travel limits (e.g., NY to Moscow in 15 mins).
  4. **Lateral Movement (Living off the Land):** Internal IPs pivoting to sensitive cloud resources (AWS) using privileged commands.
  5. **Device Spoofing:** Sudden changes in OS/Browser footprints.
  6. **Low-and-Slow Exfiltration (APT):** Multi-day, progressively longer queries to production databases to evade volume-based static thresholds.
  7. **Insider Drift (T1078.004):** Legitimate users slowly changing their baseline over time (used to train the models against permanent false positives).

### Phase 2: Core Machine Learning & Feature Engineering
We transform raw logs into mathematical vectors to train our AI models, engineering signal that goes well beyond simple thresholds.
* **Advanced Feature Engineering:** We calculate complex rolling windows across the dataset:
  - `geo_velocity`: Uses real city coordinates and the Haversine formula to calculate the physical speed of a user's travel between logins (km/h).
  - `recent_failed_auth_count`: A 10-minute rolling window tracking login failures.
  - `session_duration_zscore`: A 30-day rolling baseline tracking deviations from a user's normal session length.
  - `has_privileged_command`: NLP string matching for high-risk commands (e.g., `assume_role`).
* **Unsupervised Anomaly Detection:** An **Isolation Forest** model evaluates the data to filter out the noise and acts as a strict baseline filter.
* **Supervised Attack Classification:** An **XGBoost** model (using Stratified Train/Test splits and sample weighting) evaluates the anomalies. It outputs a probability distribution across all attack classes, selecting the highest probability as the prediction and the raw percentage as the **AI Confidence Level**.

### Phase 3: Attack Chain Linking & XAI (Explainable AI)
Single events rarely tell the full story of a breach — real attackers act in sequences, so our system thinks in sequences too.
* **Generalized Temporal Chain Linker:** We built a configurable sliding-window pattern-library architecture that connects isolated events. It currently evaluates 4 major multi-step attack patterns (e.g., `chain_credential_compromise`, `chain_lateral_movement`), each with its own configurable temporal gap, and is designed to scale to new patterns without rewriting detection logic.
* **Explainable AI (SHAP):** Black-box AI is useless to an analyst. We integrated the **SHAP (SHapley Additive exPlanations)** library to crack open the XGBoost model. It calculates exactly which features drove the AI's decision and translates them into human-readable reasons (e.g., *"Physically impossible travel velocity detected (1020 km/h)"*), so every single alert comes with a defensible, transparent justification.

### Phase 4: Backend Simulation Engine & Dashboard
The final alerts are pushed to a PostgreSQL database and served to a cutting-edge analyst dashboard, built to feel like a real SOC tool, not a hackathon prototype.
* **Live Simulation Engine (FastAPI):** A background `asyncio` engine running inside FastAPI that streams events, computes rolling baselines continuously in real-time, and scores them dynamically rather than replaying static scores — genuine live inference, not playback.
* **Adaptive Risk Score & MITRE Mapping:** Applies a score (0-100) based on contextual severity and automatically maps every attack (including Insider Drift -> T1078.004) to the official **MITRE ATT&CK Framework**.
* **React + Vite Frontend (Glassmorphism Aesthetic):**
  - **Overview Dashboard:** A landing panel presenting real-time aggregate metrics (Total Alerts, Avg Risk) and dynamic visual breakdown cards of active attack types.
  - **Alert Queue Explorer with Filtering:** An advanced triage queue allowing analysts to filter by Entity ID, Tier Level (Critical vs Safety Net), and specific Attack Classes instantly, with alerts sorted by severity and risk score dynamically.
  - **Real-Time WebSocket Push:** Instantly streams detected live threats from the FastAPI backend directly to the dashboard without polling.
  - **Attack Relationship Graph:** A visual `vis-network` node graph showing the physical relationship between the Entity, the Malicious IP, and the Compromised Resource.

---

## Hackathon Evaluation Criteria Achieved
1. **Explainability:** Fully achieved. XAI (SHAP) translates complex mathematics into plain English, ensuring the analyst always understands *why* the AI flagged an event.
2. **Analyst Usability:** Delivered a stunning, premium, responsive UI featuring modern glassmorphism, real-time WebSocket updates, one-click PDF incident reporting, and an intuitive incident-response workflow.
3. **Tiered False Positive Reduction:** We implemented a two-tier alerting system to combat alert fatigue:
   - **Tier 1 (Strict Top-1% Budget):** Filters out 99% of normal noise, achieving a verified **25.8% precision rate** on the absolute most anomalous events.
   - **Tier 2 (Safety Net):** Leverages the Chain Linker and XGBoost high-confidence classifications to catch stealthier attacks, achieving a highly accurate **98.01% precision rate** across the entire attack surface.

### Detailed Evaluation Metrics (XGBoost Classifier)

Below are the per-class metrics generated during the latest pipeline evaluation run on the validation set, demonstrating the model's ability to cleanly separate attack patterns from noise.

| Attack Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **Brute Force** | 1.00 | 1.00 | 1.00 | 775 |
| **Credential Stuffing** | 0.99 | 1.00 | 0.99 | 148 |
| **Device Spoofing** | 0.98 | 1.00 | 0.99 | 50 |
| **Impossible Travel** | 0.93 | 0.98 | 0.95 | 48 |
| **Lateral Movement** | 0.82 | 0.93 | 0.87 | 43 |
| **Low and Slow (APT)** | 0.99 | 0.99 | 0.99 | 148 |
| **Chain Credential Compromise** | 0.90 | 0.97 | 0.93 | 79 |

**Global Performance:**
- **ROC-AUC (Macro):** 0.991
- **PR-AUC (Macro):** 0.974
- **Overall Accuracy:** 97.4%

---

## Full Feature List

**Data & Simulation**
- Synthetic enterprise data generator: 500 users, 50 edge devices, individual behavioral profiles
- 7 distinct behavioral classes injected, including 6 real attack types and 1 deliberate false-positive edge case (insider drift)
- Multi-step attack chain injection, not just isolated event anomalies
- Real-world city coordinates for geographically accurate travel-velocity modeling
- Live simulation engine: on-the-fly event generation and real-time scoring, not CSV replay

**Machine Learning**
- Isolation Forest for unsupervised behavioral baseline scoring
- XGBoost for supervised multi-class attack classification, with stratified splits and class-balanced sample weighting
- 7-feature engineered pipeline including geo-velocity, privileged-command detection, and rolling temporal statistics
- Cold-start handling via peer-group baseline fallback for brand-new entities
- Concept drift handling via rolling-window baseline updates
- Continuous learning: a retrain-and-gate pipeline that only promotes a new model if it measurably outperforms the current one across precision, recall, PR-AUC, and false positive rate

**Detection & Explainability**
- Configurable, extensible attack chain pattern library (4 active multi-step patterns)
- SHAP-based explainability on every flagged alert, in plain English
- Adaptive, additive risk scoring (0-100) based on contextual severity
- Full MITRE ATT&CK technique mapping on every alert and chain
- Recommended remediation action tied to every attack type
- Two-tier alerting system separating strict-budget critical alerts from safety-net catches

**Dashboard & Analyst Experience**
- Real-time WebSocket-powered live dashboard, no polling or manual refresh
- Overview panel with aggregate metrics and attack-type breakdowns
- Searchable, filterable alert queue (by entity, tier, and attack class)
- Interactive attack relationship graph (entity, IP, and resource connections)
- Historical risk trendlines per entity
- One-click analyst feedback loop (accept/reject) feeding directly into the retraining pipeline
- One-click downloadable PDF incident reports
- Full PostgreSQL persistence for alerts, feedback, and historical analysis

---

## Limitations & Tradeoffs

While the SOC Assistant is a highly functional prototype, there are deliberate design tradeoffs and inherent limitations within the current architecture:

1. **Synthetic Data Constraints:** The entire training and evaluation pipeline relies on synthetically generated data. While we rigorously model noise, temporal spacing, and baseline drift, synthetic data fundamentally cannot capture every obscure, compounding dependency or behavioral anomaly present in a real-world enterprise network.
2. **Dataset Size & Class Imbalance:** To ensure the pipeline executes swiftly on local machines for the hackathon demonstration, the dataset size is intentionally constrained. Real-world SIEMs process terabytes of data daily. Furthermore, while we employ sample weighting, the artificial class imbalance ratios may not perfectly mirror real-world attack distributions.
3. **Database Architecture:** The current implementation uses a single-node PostgreSQL architecture. This limits concurrent read/write throughput during high-velocity live simulations. In a production environment, this would need to be replaced with a distributed time-series database or a scalable event streaming platform (e.g., Apache Kafka).
4. **Feature Engineering vs. Deep Learning (Deliberate Tradeoff):** We consciously chose to use explicit, rolling-window feature engineering paired with XGBoost rather than deploying recurrent deep learning models (like LSTMs). While an LSTM could theoretically uncover deeper sequential patterns on its own, it acts as an impenetrable "black box." In cybersecurity, an analyst must understand exactly *why* an alert fired. Our feature-engineered approach allows SHAP to perfectly dissect the model's reasoning and provide plain-English, actionable explainability. We traded marginal deep-learning pattern recognition for 100% analyst transparency and trust.
