###### **Phase 1: Foundation**



1. Set up repo structure, PostgreSQL schema (entities, sessions/events, alerts, feedback tables)



2\. Build the synthetic data generator (per-entity behavior profiles + noise sampling)



3\. Inject attack patterns as defined (brute force, impossible travel, credential stuffing, lateral movement, device spoofing, low-and-slow, insider drift)



4\. Inject attack chains as linked event sequences (not isolated rows)



5\. Generate a large enough dataset (normal-heavy, attacks at 0.5–3%), load into Postgres, keep ground-truth labels separate





###### **Phase 2: Core ML**



6\. Feature engineering (per-entity rolling stats: login hour deviation, geo distance, new-device flag, resource-access frequency, session duration z-score)



7\. Train Isolation Forest for anomaly scoring



8\. Train XGBoost/Random Forest for attack-type classification on flagged events



9\. Add cold-start fallback (peer-group averaging for new entities)



10\. Add concept drift handling (rolling-window baseline updates)







###### **Phase 3: Chain Detection + Explainability**



11\. Build rule-based attack chain linker (sliding time window per entity, match against known bad sequences)



12\. Integrate SHAP for per-alert feature attribution



13\. Turn SHAP output into a readable "reason" string (rule-based text first, LLM later if time allows)







###### **Phase 4: Backend + Risk Scoring**



14\. FastAPI endpoints: ingest events, run detection, return alerts, accept/store analyst feedback



15\. Risk scoring logic combining anomaly score + attack-type confidence + chain involvement



15.5. Implement rule-based adaptive risk scoring — additive point system by risk factor (e.g., high-value resource +20, new device +15, attack chain involvement +25, multiple failed logins +10) replacing fixed-weight combination



15.6. Build analyst action recommendation mapping — static lookup from attack type to recommended actions (e.g., Force MFA, Lock Account, Notify SOC)



15.7. Build MITRE ATT\&CK technique mapping — static lookup from attack type to MITRE technique ID and tactic (e.g., Credential Stuffing → T1110, Brute Force, Credential Access)





###### **Phase 5: Dashboard**



16\. React dashboard: alert queue (ranked by risk score), alert detail view (reasons, attack type, timeline), entity history view, accept/reject buttons wired to feedback endpoint



16.5. Attack relationship graph — React Flow or vis-network visualization of entity-device-resource relationships per alert, with suspicious nodes/edges highlighted in red



16.6. Per-entity risk history trend — small chart/sparkline in entity history view showing risk score over recent time periods



16.7. Confidence meter per alert — display classifier probability for the predicted attack type alongside the risk score







###### **Phase 6: Polish** 



17\. LLM API call layer for natural-language explanations



18\. Visual polish, loading states, edge case handling







###### **Phase 7: Deliverables**



19\. Architecture diagram (modules + data flow)



20\. Report (assumptions, metrics, known limitations)



21\. Fill in the provided presentation template



22\. Convert everything to PDF/zip, test upload before deadline

