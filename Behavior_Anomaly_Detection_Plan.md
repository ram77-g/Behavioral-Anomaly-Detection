# AI-Powered Behavioral Anomaly Detection for Cybersecurity (Honeywell)

## Problem Statement
Build an AI-powered SOC (Security Operations Center) assistant that learns the normal behavior of users/devices and detects suspicious activities in real time. Instead of using known malware signatures, it detects anomalies based on behavior.

Example:
Rahul normally logs in at 9 AM from Bangalore using a Windows laptop and accesses GitHub/Jira.
One day he logs in at 2 AM from Russia using an unknown MacBook and downloads payroll files.
→ AI should detect this as anomalous, classify the attack, explain why, and assign a risk score.

---

## Main Goal

Learn Normal Behavior
        ↓
Detect Anomalies
        ↓
Classify Attack Type
        ↓
Detect Attack Chains
        ↓
Explain Why
        ↓
Risk Score
        ↓
Dashboard for Analyst

---

## Constraints (Must Handle)

1. **Sequential Data** — learn behavior over time, not one login at a time. Sequence/order of actions matters.
2. **Class Imbalance** — attacks are a tiny fraction of total events.
3. **Concept Drift** — a user's normal behavior changes over time (new job role, new hours). Handled via rolling-window baseline updates so old behavior ages out naturally, instead of permanently flagging someone.
4. **Cold Start** — new users/devices have no history. Handled by comparing against a peer-group average (same `entity_type`) until enough personal history builds up, then blending in personal history.
5. **Explainability** — every alert must include reasons, not just a score.

---

## Synthetic Data

Honeywell expects us to generate realistic access logs ourselves.

**Schema (fixed, must follow exactly):**
| Field | Description |
|---|---|
| entity_id | user_id or device_id |
| entity_type | user / service_account / edge_device |
| timestamp | access or connection time |
| source_ip / geo_location | origin of the access |
| resource_accessed | file, endpoint, port, or device function |
| auth_method | password, token, certificate, biometric |
| session_duration | length of connection |
| command_sequence | ordered list of actions taken (for privileged sessions) |
| device_fingerprint | OS/firmware version, MAC address, protocol used |
| label | normal / anomaly_type (training/eval only, hidden at inference) |

**Quality bar:** each synthetic entity gets a consistent underlying behavioral profile (typical login hour ± spread, home geo, usual device, usual resource set), and events are sampled *around* that profile with realistic noise — not pure randomness. This matters because the Isolation Forest and classifier are only as good as how realistic the "normal" clusters are.

Attack rate target: 0.5–3% of sessions, ground-truth labels kept separate from the training/inference data.

---

## Behaviors to Simulate

**Normal:** regular login hours, same location, same device, typical resources — sampled with noise around each entity's profile.

**Attacks (isolated anomaly patterns):**
- Brute Force
- Impossible Travel
- Credential Stuffing
- Lateral Movement
- Device Spoofing
- Low-and-Slow Exfiltration
- Insider Drift (edge case, used for false-positive tuning)

---

## Attack Chains (Key Differentiator)

Don't only detect single events — link sequences of events per entity within a time window.

Example:
Login → Password Reset → New Device → Payroll Access → Large Download
= Credential Compromise (entire chain, not any single step)

**Implementation approach:** rule-based sequence linker, not a separate ML model. Slide a time window per entity, match observed event sequences against a small set of known bad patterns (like the one above). This is intentionally simple — kept efficient rather than building a second sequence model — because it's one of the biggest ways our submission stands out from teams that only score isolated events.

Attack chains must be injected into the synthetic generator as actual linked rows (not just a single flagged row) so the chain detector has real sequences to catch.

---

## Deliverables

- Synthetic log generator with documented behavioral assumptions and injected attack taxonomy
- Behavior/anomaly detection model
- Attack-type classifier
- Attack chain detector
- Explainable risk score (SHAP-based)
- Analyst dashboard
- Report (assumptions, metrics, known limitations)

**Dashboard must show:** ranked alert queue, risk score, timeline, reasons, attack type, recommendations, entity/user history, and accept/reject controls for analyst feedback — plus the innovation layer described below (attack relationship graph, MITRE mapping, risk history trend, confidence meter, analyst action recommendations).

---

## Tech Stack (finalized)

**Backend:** Python, FastAPI

**Data:** Pandas, NumPy, Faker

**Database:** PostgreSQL (already set up) — entities, sessions/events, alerts, and feedback as relational tables; JSONB columns for `command_sequence` and `device_fingerprint`

**Dashboard:** React + FastAPI (chosen over Streamlit — same build speed for us, more polished demo). Attack relationship graph built with React Flow or vis-network.

**Visualization:** Recharts or Plotly (in-dashboard), Excalidraw/draw.io for the architecture diagram

**LLM:** optional, added last if time allows — a hosted API call layer that turns SHAP output into a plain-English sentence. Used only for explanation phrasing, never for detection.

---

## ML Pipeline

Synthetic Logs
      ↓
Feature Engineering (rolling per-entity stats: login-hour deviation, geo distance, new-device flag, resource-access frequency, session-duration z-score)
      ↓
Isolation Forest (behavior/anomaly scoring)
      ↓
XGBoost or Random Forest (attack-type classification)
      ↓
Rule-Based Chain Linker (attack chain detection)
      ↓
Risk Scoring — adaptive, additive point system (anomaly score + attack-type confidence + chain involvement + risk factors like high-value resource, new device, multiple failed logins)
      ↓
SHAP Explainability
      ↓
MITRE ATT&CK Mapping + Analyst Action Recommendations
      ↓
LLM Explanation (optional, later)
      ↓
Dashboard (alert graph, risk trend, confidence meter)

---

## Recommended Models (locked in)

- Behavior/Anomaly Scoring: Isolation Forest — fast to train, robust to noisy synthetic data, still explainable.
- Attack Classification: XGBoost or Random Forest
- Explainability: SHAP, converted into readable "reason" strings

This combination is deliberately not overly complex — no deep learning training loop, no GPU dependency, fast to iterate on — while still fully satisfying the imbalance, multi-class, and explainability requirements.

---

## Features That Make This Stand Out

**Core differentiators:**
- Attack Chain Detection (rule-based, low-risk, high differentiation)
- Analyst Feedback Loop (accept/reject, stored for future evaluation)
- Adaptive Learning (concept drift via rolling-window baseline updates)

**Innovation / polish layer (dashboard + risk scoring):**
- Attack relationship graph — React Flow/vis-network visualization of entity-device-resource relationships per alert, suspicious nodes/edges highlighted in red
- Adaptive rule-based risk scoring — additive point system by risk factor (e.g., high-value resource +20, new device +15, attack chain involvement +25, multiple failed logins +10) instead of fixed weights
- Analyst action recommendations — static lookup from attack type to recommended action (Force MFA, Lock Account, Notify SOC)
- MITRE ATT&CK technique mapping — static lookup from attack type to technique ID and tactic (e.g., Credential Stuffing → T1110, Brute Force, Credential Access)
- Per-entity risk history trend — sparkline/chart of risk score over recent time periods in the entity history view
- Confidence meter — classifier probability shown per alert alongside the risk score
- LLM Security Copilot ("why was this flagged?") — stretch goal only
- Timeline of User Activity

---

## Build Order (dependency-based, not clock-based)

**Phase 1: Foundation**
1. Set up repo structure, PostgreSQL schema (entities, sessions/events, alerts, feedback tables)
2. Build the synthetic data generator (per-entity behavior profiles + noise sampling)
3. Inject attack patterns as defined (brute force, impossible travel, credential stuffing, lateral movement, device spoofing, low-and-slow, insider drift)
4. Inject attack chains as linked event sequences (not isolated rows)
5. Generate a large enough dataset (normal-heavy, attacks at 0.5–3%), load into Postgres, keep ground-truth labels separate

**Phase 2: Core ML**
6. Feature engineering (per-entity rolling stats: login hour deviation, geo distance, new-device flag, resource-access frequency, session duration z-score)
7. Train Isolation Forest for anomaly scoring
8. Train XGBoost/Random Forest for attack-type classification on flagged events
9. Add cold-start fallback (peer-group averaging for new entities)
10. Add concept drift handling (rolling-window baseline updates)

**Phase 3: Chain Detection + Explainability**
11. Build rule-based attack chain linker (sliding time window per entity, match against known bad sequences)
12. Integrate SHAP for per-alert feature attribution
13. Turn SHAP output into a readable "reason" string (rule-based text first, LLM later if time allows)

**Phase 4: Backend + Risk Scoring**
14. FastAPI endpoints: ingest events, run detection, return alerts, accept/store analyst feedback
15. Risk scoring logic combining anomaly score + attack-type confidence + chain involvement
15.5. Implement rule-based adaptive risk scoring — additive point system by risk factor (e.g., high-value resource +20, new device +15, attack chain involvement +25, multiple failed logins +10) replacing fixed-weight combination
15.6. Build analyst action recommendation mapping — static lookup from attack type to recommended actions (e.g., Force MFA, Lock Account, Notify SOC)
15.7. Build MITRE ATT&CK technique mapping — static lookup from attack type to MITRE technique ID and tactic (e.g., Credential Stuffing → T1110, Brute Force, Credential Access)

**Phase 5: Dashboard**
16. React dashboard: alert queue (ranked by risk score), alert detail view (reasons, attack type, timeline), entity history view, accept/reject buttons wired to feedback endpoint
16.5. Attack relationship graph — React Flow or vis-network visualization of entity-device-resource relationships per alert, with suspicious nodes/edges highlighted in red
16.6. Per-entity risk history trend — small chart/sparkline in entity history view showing risk score over recent time periods
16.7. Confidence meter per alert — display classifier probability for the predicted attack type alongside the risk score

**Phase 6: Polish (only if time remains)**
17. LLM API call layer for natural-language explanations
18. Visual polish, loading states, edge case handling

**Phase 7: Deliverables**
19. Architecture diagram (modules + data flow)
20. Report (assumptions, metrics, known limitations)
21. Fill in the provided presentation template
22. Convert everything to PDF/zip, test upload before deadline

Phases 1–10 are non-negotiable core. If time runs short, cut Phase 6 first, then trim the innovation-layer items in Phases 4–5 in this order if needed: risk history trend → confidence meter → analyst recommendations, keeping the attack relationship graph and MITRE mapping as the last things to cut — never skip Phase 7.

---

## Evaluation Criteria (from problem statement, for reference)

- Detection accuracy on imbalanced labels
- Correct anomaly-type classification
- False positive rate at a realistic analyst alert budget (e.g., top 1% of events)
- Explainability / analyst usability
- Handling cold-start entities and concept drift
- System design & scalability (real-time streaming feasibility)
- Report clarity

Sequence-awareness is covered by rolling/temporal features feeding XGBoost together with rule-based attack chain linking, allowing the model to learn behavior over time without requiring a separate deep-learning sequence model.