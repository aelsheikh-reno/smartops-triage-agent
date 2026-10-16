# Brief: Build the Triage Question Bank

Read CLAUDE.md and docs/design-decisions.md first. Create branch feat/triage-question-bank and work only there.

Sources: shallow-clone splunk/security_content, elastic/detection-rules, SigmaHQ/sigma, LOLBAS-Project/LOLBAS, GTFOBins/GTFOBins.github.io, magicsword-io/LOLDrivers, mitre-attack/attack-stix-data into sources/. Validate technique IDs against ATT&CK v20.0 (enterprise-attack-20.0.json); no revoked or deprecated IDs.

Layout:
- bank/questions/Q-*.yaml, bank/detections/ (metadata + flow), bank/techniques/T*.yaml, bank/explanations/BE-*.yaml, bank/facts/CF-*.yaml, bank/reason_codes.yaml, bank/overlays/customer/ (empty slot)
- tools/validate (refs exist, ≤5 steps, valid outcomes, required fields, license), tools/load_sql (YAML → SQLite, Postgres-compatible: detections, questions, flow_steps, question_needs, context_facts), tools/rank_facts (facts ranked by detections unblocked)

Question fields: id, text, tests, answer_source, needs, source, license, status, version.
Detection fields: id (escu:/sigma:/elastic:), name, techniques, data_source, required_alert_fields, intent, fp_quality (good|vague|none), flow. Every flow starts with Q0.

Steps (stop after each):
1. Ask me the pilot domain: endpoint Windows, identity/authentication, or network. Select ~25 detections.
2. Build 3 detections end to end and show them for review.
3. After approval, build the rest of the pilot plus technique fallbacks.
4. Run validate, load_sql, rank_facts; show the top 15 context facts.
5. Commit, push, open a draft PR. Do not merge.
