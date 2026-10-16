# SmartOps Triage Agent: Design Decisions

## 1. What triage is
A fast, time-boxed first pass on an alert: is it worth investigating, and how urgently? It does not prove malice; that is investigation. Two separate calls: verdict (malicious or benign) and priority (how fast). Asset criticality changes priority and autonomy, never the verdict.

## 2. Method
For each detection, list its 2–3 most common benign explanations and test only those, as yes/no questions. One holds → close as false positive or benign true positive, with a reason code. None holds → escalate. Missing answer → unknown → analyst decides.

Vendor alerts (AV/EDR, IDS/IPS, WAF, email gateway, DLP, proxy, firewall, device control) add a third close: **mitigated true positive**, when the activity was malicious or unwanted but the control that raised the alert stopped it (blocked, quarantined, denied) and nothing else needs doing. Each vendor family is one generic detection (`vendor:` prefix) bound to normalized alert fields, never one per product.

Mitigated true positive never applies to high-risk families: hack tools, credential dumpers, ransomware, web shells, exploit frameworks, remote access trojans and remote-admin tools, miners, proxyware and cracks. Those escalate even when blocked. Antivirus test files (EICAR and similar) flag; they never close as low risk. Only a block before execution counts: post-execution quarantine or cleaning, a pending reboot and partial remediation answer unknown and flag. Each vendor's action values map to the bank's normalized values in `docs/normalization.md`.

Internal sources: for firewall, IDS and WAF alerts, a source inside the customer's internal networks (a per-customer parameter) never closes on denied, blocked or patched; it flags or escalates. IDS alerts from internal sources flag whatever the answer.

## 3. Boundary
Only entities named in the alert, only alerts that already fired, a fixed ±24h window. Pivoting to other entities or building raw-log timelines is investigation, out of scope.

## 4. Questions are portable, answers are local
Every question is answerable by one lookup against:
- Context store: assets, identities, allowlists, VPN ranges, sanctioned tools, change windows with their implementers (customer-provided or mined from Splunk)
- Baseline engine: "is this normal for this entity?" yes/no, from the customer's logs
- Case memory: precedents (past closures with reasons)
- Alert field: values in the notable itself

### Capabilities and the MCP layer
The agent never knows which tools a customer has. Each question declares exactly one capability (`bank/capabilities.yaml`, e.g. `list.lookup`, `entity.baseline`, `org.prevalence`, `change.window`, `file.signer`, `file.reputation`). The agent calls an MCP server, which routes the capability to whatever tools exist for that customer; any of them may be disconnected. The bank holds no tool names or SPL.

`alert.field` reads a normalized field of the alert itself (for example the control's action). It is answered locally, not through the MCP server, and does not count against the call budget.

Answer contract: `answer` (yes | no | unknown), `unknown_reason` (no_capability | unavailable | no_data), `evidence`, `source_tool`, `observed_at`.
- no_data: follow the step's `on_unknown`.
- unavailable (tool down, timeout): never closes; the alert is flagged and the detection runs in Recommend until the capability is healthy again.
- no_capability: resolved per customer at onboarding. The question is disabled, its step follows `on_unknown` without a call, and it is listed in the coverage report.
- A yes that rests on seed data with `verified: false` taints the rest of the flow: that step and any later close reached through it become a flag until onboarding verifies the entry.
- Reputation and anomaly capabilities are escalate_only: a hit escalates or flags and never closes; a miss is never benign evidence.
- `vuln.not_applicable` answers unknown when the signature maps to no CVE (most generic IDS and WAF rules), so it never closes them. The replay gate counts these unknowns.
- `alert.history` counts alerts that already fired inside the triage window and share a key (the fingerprint, or a source, destination, user or campaign key). It reads existing alerts only, never raw logs. A count at or above the per-customer threshold (default 3) turns a close into a flag: a burst is not noise.
- `change.window` answers yes only when an approved change covers the host and time and lists the alert's user (or one of their groups) as implementer; no when nothing covers it, or every covering change lists implementers without the user; unknown (no_data) when a covering change has no implementer data.

The MCP server enforces scope: entities named in the alert only; fixed windows (±24h for event lookups; baselines and prevalence use their declared lookbacks and return counts, not raw events); read-only; a per-call timeout (timeout = unavailable); at most 6 calls per alert including Q0, counted on the worst single path through the flow (steps plus the guards of the closing step). Resolving a file's hash or signer inside a lookup is the server's job and does not count against the budget.

Write-back goes only through `list.propose_update`. Reduce-scrutiny changes (allowlist additions) need human approval with an owner and an expiry. Increase-scrutiny changes (watchlists, removing an allowlist entry) may be automatic; removing an allowlist entry must notify the fact's owner. Enforcement blocks need approval.

Vendor neutrality: the bank holds no vendor or product names. Only offline metadata (`data_source`, `sigma_logsource`, `sigma_refs`, `source`, `license`) may name them, plus seed data under `bank/seeds/`, which is loaded into the customer's context store at onboarding and never reaches the agent. Question text describes what to check about an entity, never where or with which tool. The agent receives a runtime bundle (`tools/export_bundle.py`) built without the offline metadata; the validator fails if the bundle contains an offline key or a vendor name.

Allowlist and "known tool" lookups match on file hash, or code-signing signer plus path, never on name or path alone. Names and paths are attacker-controlled. Where the alert lacks hash or signer, fetch them from the same process's creation event by process GUID; if still unavailable, the answer is unknown.

## 5. Bank structure
- Two levels: rule-level flows per known detection (ESCU, Sigma, Elastic) and technique-level fallback flows per ATT&CK technique.
- Technique-only rules are capped at Recommend mode.
- No questions (usually a custom rule): no verdict; the agent sends a context pack, the analyst triages, curation drafts questions from the analyst's reasoning, and the rule starts in Shadow.
- Flows: at most 5 steps, early exit; each step has on_yes / on_no / on_unknown → next | close:<disposition>:<reason_code> | escalate | flag.
- Guards: a step that can close may carry guards, extra checks that run only when the step would close. Each names a question, the answers that trigger it and the result (flag or escalate); an unknown guard answer flags. A guard that fires on no means the close needs a yes from it. Guards never create a close. They hold conditions such as "blocked, but not if the client got a success status" without spending a step.
- Attacker influence: none, low, medium (control-recorded but forgeable in transit, such as alerts forwarded over syslog), high. Every close path must rest on a yes rated none or low. A question may rate itself per source profile (direct API or forwarded); the profile is recorded per vendor family at onboarding, and a close left without a none/low yes under the customer's profile flags.
- Q0 precedent check first in every flow: same fingerprint (rule + entity + key attributes) closed with a recorded reason within the validity window (e.g. 24h–7d), the detection's precedent entity not a crown jewel, no other alert on it in the window → close citing the precedent. In Shadow and Recommend the precedent is shown to the analyst instead.
  - Each detection names its precedent entity and rates each fingerprint field's attacker influence. Q0's rating is the least attacker-chosen field's. If every field is attacker-chosen (sender, subject, message id), the precedent flags. If the best field is medium (spoofable source addresses), the close also needs a low-rated yes from a guard, such as "every connection was denied".
  - A precedent closed as mitigated true positive is inherited only when the current alert was also blocked.
  - Three or more earlier alerts with the same fingerprint in the triage window turn the precedent close into a flag.
- Two layers: public base bank plus a customer layer (runbooks, mined closures) that overrides base entries by ID. Mined closures are evidence, not truth, and go through curation.

## 6. Repeat alerts
An alert matching an open case's fingerprint is attached to it without new triage; re-triage only if the count spikes or a new attribute value appears. A rule firing hundreds of times on one entity becomes a tuning ticket (throttling or risk-based alerting).

## 7. Storage
- Question bank: YAML in git, loaded into SQL tables. Exact, repeatable, auditable, reviewed through PRs.
- Custom-rule matching: pgvector in the same Postgres, offline only.
- Investigation (later): graph database. The YAML already has typed nodes, typed edges and stable IDs, so it loads into a graph DB unchanged.
- Runtime is a loop: load the detection's steps, answer each with one lookup, follow yes/no/unknown, stop at the first close or escalate.

## 8. Rule intent service (custom rules)
Runs once per rule, at onboarding and on rule change, never per alert:
1. Parse the SPL (data source, fields, filters, thresholds, entity); write intent as "Detects <behavior> on <entity> from <data source>".
2. Classify: threat, policy/compliance, or operational noise. Only threat rules go to triage.
3. LLM proposes ATT&CK techniques; vector search returns the 3 closest known detections; trust where both agree.
4. Strong match → inherit questions as drafts, start in Shadow. Technique only → capped at Recommend. Neither → context pack.
5. Drop inherited questions needing alert fields the rule doesn't produce.
6. A senior analyst approves the mapping once; stored in SQL. No vector search at runtime.

Each known detection carries `sigma_logsource` ({product, category} or {product, service}, from Sigma's own taxonomy) and `sigma_refs` (equivalent or closest SigmaHQ rules). These are offline metadata that let this service match custom rules to known detections across SIEMs; they are never used at runtime. The bank holds no OCSF. If a customer's data is in OCSF, the mapping lives in the MCP server's per-customer adapter.

## 9. Model split
Offline: a frontier model drafts questions from public sources; a senior analyst approves. Runtime: Cisco Foundation-sec-8B only selects and answers approved questions; anything new it proposes goes to curation as a draft.

## 10. Modes and guardrails
Per detection: Shadow (verdict hidden) → Recommend (analyst accepts or overrides) → Auto (close benign, escalate suspicious). Suggested promotion threshold: ≥95% agreement over 50+ alerts. Auto mode requires process telemetry with hashes (Sysmon or EDR); customers on Security 4688 only stay in Recommend. Permanent: no auto-close on crown jewels (in every mode, any close on a crown-jewel entity becomes a flag; this is how the AV review's "crown-jewel host → flag" is met for every detection); audit 5–10% of auto-closures; escalation is never suppressed.

## 11. Sources and licenses
- splunk/security_content (ESCU), Apache-2.0: known_false_positives, ATT&CK mapping, data source
- elastic/detection-rules, Elastic License 2.0: "Triage and analysis", "False positive analysis"
- SigmaHQ/sigma, Detection Rule License (attribution): falsepositives
- LOLBAS, GTFOBins, LOLDrivers: legitimate uses of binaries and drivers
- Azure/Azure-Sentinel, MIT: primary source for the identity and cloud domain (Entra ID, M365, Azure). It has no false-positive field; benign hints live in query comments and descriptions. Its `entityMappings` are the model for which entities a detection's alert exposes.
- MITRE ATT&CK v20.0 (mitre-attack/attack-stix-data): techniques, detection strategies. v19 (April 2026) revoked T1562.001 → T1685 and T1070.001 → T1685.005; use current IDs.
Record source and license on every question; non-Apache text needs legal review before commercial use.

## 12. Later phases
Cross-customer analytics with anonymized counts only (question ID, outcome, sector). Investigation agent using an attack-path graph (e.g. MITRE Attack Flow) and a per-incident evidence graph.
