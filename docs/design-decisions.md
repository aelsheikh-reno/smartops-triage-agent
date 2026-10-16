# SmartOps Triage Agent: Design Decisions

## 1. What triage is
A fast, time-boxed first pass on an alert: is it worth investigating, and how urgently? It does not prove malice; that is investigation. Two separate calls: verdict (malicious or benign) and priority (how fast). Asset criticality changes priority and autonomy, never the verdict.

## 2. Method
For each detection, list its 2–3 most common benign explanations and test only those, as yes/no questions. One holds → close as false positive or benign true positive, with a reason code. None holds → escalate. Missing answer → unknown → analyst decides.

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

Answer contract: `answer` (yes | no | unknown), `unknown_reason` (no_capability | unavailable | no_data), `evidence`, `source_tool`, `observed_at`.
- no_data: follow the step's `on_unknown`.
- unavailable (tool down, timeout): never closes; the alert is flagged and the detection runs in Recommend until the capability is healthy again.
- no_capability: resolved per customer at onboarding. The question is disabled, its step follows `on_unknown` without a call, and it is listed in the coverage report.
- A yes that rests on seed data with `verified: false` taints the rest of the flow: that step and any later close reached through it become a flag until onboarding verifies the entry.
- Reputation and anomaly capabilities are escalate_only: a hit escalates, a miss is never benign evidence.
- `change.window` answers yes only when an approved change covers the host and time and lists the alert's user (or one of their groups) as implementer; no when nothing covers it, or every covering change lists implementers without the user; unknown (no_data) when a covering change has no implementer data.

The MCP server enforces scope: entities named in the alert only; fixed windows (±24h for event lookups; baselines and prevalence use their declared lookbacks and return counts, not raw events); read-only; a per-call timeout (timeout = unavailable); at most 6 calls per alert including Q0. Resolving a file's hash or signer inside a lookup is the server's job and does not count against the budget.

Write-back goes only through `list.propose_update`. Reduce-scrutiny changes (allowlist additions) need human approval with an owner and an expiry. Increase-scrutiny changes (watchlists, removing an allowlist entry) may be automatic; removing an allowlist entry must notify the fact's owner. Enforcement blocks need approval.

Vendor neutrality: the bank holds no vendor or product names. Only offline metadata (`data_source`, `sigma_logsource`, `sigma_refs`, `source`, `license`) may name them, plus seed data under `bank/seeds/`, which is loaded into the customer's context store at onboarding and never reaches the agent. Question text describes what to check about an entity, never where or with which tool. The agent receives a runtime bundle (`tools/export_bundle.py`) built without the offline metadata; the validator fails if the bundle contains an offline key or a vendor name.

Allowlist and "known tool" lookups match on file hash, or code-signing signer plus path, never on name or path alone. Names and paths are attacker-controlled. Where the alert lacks hash or signer, fetch them from the same process's creation event by process GUID; if still unavailable, the answer is unknown.

## 5. Bank structure
- Two levels: rule-level flows per known detection (ESCU, Sigma, Elastic) and technique-level fallback flows per ATT&CK technique.
- Technique-only rules are capped at Recommend mode.
- No questions (usually a custom rule): no verdict; the agent sends a context pack, the analyst triages, the steward drafts questions from the analyst's reasoning for human approval, and the rule starts in Shadow.
- Flows: at most 5 steps, early exit; each step has on_yes / on_no / on_unknown → next | close:<disposition>:<reason_code> | escalate | flag.
- Q0 precedent check first in every flow: same fingerprint (rule + entity + key attributes) closed with a recorded reason within the validity window (e.g. 24h–7d), not a crown jewel, no other alert on the entity in the window → close citing the precedent. In Shadow and Recommend the precedent is shown to the analyst instead.
- Two layers: public base bank plus a customer layer (runbooks, mined closures) that overrides base entries by ID. Mined closures are evidence, not truth, and go through curation.

## 6. Repeat alerts
An alert matching an open case's fingerprint is attached to it without new triage; re-triage only if the count spikes or a new attribute value appears. A rule firing hundreds of times on one entity becomes a tuning ticket (throttling or risk-based alerting).

## 7. Storage
- Question bank: YAML in git, loaded into SQL tables. Exact, repeatable, auditable, reviewed through PRs.
- Custom-rule matching: pgvector in the same Postgres, offline only.
- Investigation (later): graph database. The YAML already has typed nodes, typed edges and stable IDs, so it loads into a graph DB unchanged.
- Runtime is a loop: load the detection's steps, answer each with one lookup, follow yes/no/unknown, stop at the first close or escalate.

## 8. Rule intent service (custom rules)
Runs once per rule, at onboarding and on rule change, never per alert.

Inputs:
- the rule's SPL
- the results of running it: read-only, last 30 days, with a row cap (parameter)
- a sample of its notables

A rule that never fired uses the SPL only.

Steps:
1. Parse the SPL. The intent comes mainly from the SPL logic: results show what fires, not what the author intended.
2. The local per-rule model (§9) writes the intent ("Detects <behavior> on <entity> from <data source>"), classifies the rule (threat, policy/compliance or operational noise) and proposes ATT&CK techniques. Only threat rules go to triage.
   - The results sharpen these.
   - The notables record which fields are actually populated. Step 5 uses this list, not fields guessed from the SPL.
3. Vector search, then the reranker (§13), returns the 3 closest known detections. A strong match is one where the techniques and the closest detections agree.
4. Strong match → inherit questions as drafts. Technique only → capped at Recommend. Neither → context pack. Every mapping starts in Shadow.
5. Drop inherited questions that need fields the notables don't populate.
6. The steward asks the customer's rule owner to confirm in plain language, for example: "This rule detects X. In 30 days it fired 400 times, 92% from the patch servers. Is that what you intended?" The mapping is stored in SQL once confirmed. No vector search at runtime.
   - If the rule has no active owner (`identity.status`), the steward asks the SOC lead instead.
   - If nobody confirms within 14 days (parameter `intent_confirm_days`), the mapping may run but is capped at Recommend. It can never reach Auto until someone confirms it.
   - The steward re-asks monthly and lists unconfirmed mappings in its metrics.

Data and safety:
- Everything in this service runs on the customer's premises.
- Results and notables pass the injection classifier (§13) before the model reads them.

Boundary:
- The service is read-only and never changes a rule.
- Noise patterns it finds go to the steward as a fact proposal or a tuning ticket (§6), and a human decides between them. A fact keeps the alerts visible and closes them. Tuning stops them firing, which blinds detection on those entities.

Safety net: a wrong intent leaves the rule in Shadow. Analysts disagree with its verdicts, so it never reaches the promotion threshold, and it never wrongly closes anything.

Each known detection carries `sigma_logsource` ({product, category} or {product, service}, from Sigma's own taxonomy) and `sigma_refs` (equivalent or closest SigmaHQ rules). These are offline metadata that let this service match custom rules to known detections across SIEMs; they are never used at runtime. The bank holds no OCSF. If a customer's data is in OCSF, the mapping lives in the MCP server's per-customer adapter.

## 9. Model roles
Deployment principle: every model that touches customer data runs on the customer's premises. That covers the runtime models, the rule intent model, the steward, the injection classifier and the reranker. The only model outside the customer is the offline drafting model, and it sees public sources only.

Offline (Reno's build pipeline, public sources only):
- A frontier model drafts questions, explanations and facts from public sources.
- Gates (validate, the attacker-influence check, replay) and an external review check them.
- A human approves before anything leaves draft.
- This model never sees customer data.

Runtime decisions use no language model:
- Question selection is a bank lookup: detection ID (or the approved custom-rule mapping, §8) → flow.
- Each answer comes from one capability lookup through the MCP server (§4).
- The verdict is where the flow stops.

Local model roles (on the customer's premises):
- The bank and the flows don't depend on which model fills a role. Each deployment picks a model per role from an evaluation harness run on our test sets, within the customer's hardware. Check each model's license before use.
- Per-alert roles need speed, so they use a small model. Candidates: Cisco Foundation-sec-8B (an instruction-tuned variant), gpt-oss-20b, a small Gemma.
- Per-rule roles run once per rule and need reasoning, so they use the largest model the hardware fits. Candidates: gpt-oss-120b, a larger Gemma.
- No model has tool access in any role.

Roles:
1. Explanation writer (per alert): turns the answered checks into the analyst-facing explanation. It cannot change the verdict, the priority or the mode.
2. Close reviewer (per alert, raise-only):
   - It reads every alert the flow would close, with its answers and evidence, and returns keep, or flag with a one-line reason.
   - It can turn a close into a flag. It can never turn a flag or an escalation into a close.
   - If it is wrong, the worst case is that an analyst reviews one extra alert. It can never cause a missed attack.
   - In Shadow, measure how often it flags and how often analysts agree its flags were worth a look. Below a per-customer threshold (parameter `model_review_min_precision`, draft default 0.3), it is switched off for that detection.
   - Its calls do not count against the 6-call MCP budget.
3. Rule intent (per rule, §8).
4. Steward drafting (§12): proposal and runbook text.
5. Investigation (later phase).

Audit sampling, for the 5–10% audit of automatic closes (§10):
- Half the sample is the closes the close reviewer ranks oddest.
- The other half is random, so the audit is not blind to what the model misses.
- Humans do every audit.

Proposals for new questions, facts or exceptions come only from the Knowledge Steward (§12), never from a per-alert role.

Supporting models: the injection classifier and the reranker (§13), on the customer's premises.

## 10. Modes and guardrails
Per detection: Shadow (verdict hidden) → Recommend (analyst accepts or overrides) → Auto (close benign, escalate suspicious). Suggested promotion threshold: ≥95% agreement over 50+ alerts. Auto mode requires process telemetry with hashes (Sysmon or EDR); customers on Security 4688 only stay in Recommend. Permanent: no auto-close on crown jewels; audit 5–10% of auto-closures; escalation is never suppressed.

## 11. Sources and licenses
- splunk/security_content (ESCU), Apache-2.0: known_false_positives, ATT&CK mapping, data source
- elastic/detection-rules, Elastic License 2.0: "Triage and analysis", "False positive analysis"
- SigmaHQ/sigma, Detection Rule License (attribution): falsepositives
- LOLBAS, GTFOBins, LOLDrivers: legitimate uses of binaries and drivers
- Azure/Azure-Sentinel, MIT: primary source for the identity and cloud domain (Entra ID, M365, Azure). It has no false-positive field; benign hints live in query comments and descriptions. Its `entityMappings` are the model for which entities a detection's alert exposes.
- MITRE ATT&CK v20.0 (mitre-attack/attack-stix-data): techniques, detection strategies. v19 (April 2026) revoked T1562.001 → T1685 and T1070.001 → T1685.005; use current IDs.
Record source and license on every question; non-Apache text needs legal review before commercial use.

## 12. Knowledge Steward agent
A second agent keeps the triage knowledge current: context facts, allowlists, exceptions, questions and runbooks. It runs continuously, so triage quality does not depend on people following documentation or on who is still on the team. The triage agent decides; the steward keeps the knowledge it decides with up to date.

Duties:
1. Fact freshness: finds facts near expiry, or whose owner is disabled or has left (identity capabilities), and asks the right person to re-confirm. Expired facts stop being used.
2. Closure mining: turns recurring analyst closure reasons into proposals: a new exception, a new fact or a new benign question.
3. Cleanup: proposes removing allowlist and exception entries unused for 90 days (per-customer parameter).
4. New patterns: drafts a new question when a benign cause recurs and no question covers it.
5. Rule changes: new or edited detections are re-mapped by the rule intent service (§8) and start in Shadow; the steward tracks each one until it is mapped, has questions and has a mode.
6. Runbook sync: generates human-readable runbooks from the bank, so the documentation always matches what the triage agent does.
7. Turnover resilience: all knowledge lives in the bank and the context store, with owner, reason, evidence and history, never only in people's heads.

Guardrails:
- It proposes, and never decides, anything that reduces scrutiny: an allowlist entry, an exception, a trusted entity, or a question that adds a close path. Each needs human approval, an owner and an expiry, with a full audit trail.
- It may apply increase-scrutiny changes on its own (a watchlist entry, removing an expired entry), and must notify the fact's owner.
- Anti-poisoning: a reduce-scrutiny proposal needs evidence from at least 3 analyst closures, by at least 2 different analysts, on at least 3 distinct days (per-customer parameters). The triage agent's own automatic closures never count as evidence, so the two agents cannot reinforce each other. A proposal driven by alerts from a single source, or by a burst inside one window, is rejected.
- It writes only through the MCP server's `list.propose_update` and fact-update capabilities, and never edits customer tools directly.
- It runs on the same deployment as the triage agent, on the customer's premises.

Metrics: proposals made, accepted and rejected; unconfirmed rule mappings (§8); stale facts; average fact age; unused entries removed; time from a recurring pattern to an approved fact; runbook drift (should be zero).

Capabilities it needs (specification only; to be added to `bank/capabilities.yaml` in a steward group with `flow_use: forbidden`, so no triage flow can call them):
- `fact.metadata`: a fact's owner, expiry and last use.
- `list.usage`: hit counts and last hit per list entry.
- `identity.status`: whether an owner's account is active.
- `closure.history`: analyst closures with reason and analyst id.
- `rule.inventory`: enabled detections and their change dates.

## 13. Model guardrails
The structure is the primary defence. No language model decides a verdict: verdicts come from yes/no capability lookups rated for attacker influence (§4, §5). The controls below are defence in depth on top of that structure, not a replacement for it.

### Prompt-injection classifier
It runs on every input a language model reads that contains alert or customer-sourced content:
- the explanation writer (§9; it never changes the verdict)
- the close reviewer (§9)
- the steward's closure mining (§12)
- the rule intent model (§8), on SPL, rule descriptions, search results and notables
- investigation (later phase)

On a hit, what happens depends on where the text came from. In every case the text never reaches the model, and the hit is logged with its score.
- In an alert (explanation writer, close reviewer, investigation):
  - The alert escalates with reason code `injection_suspected`, in every mode.
  - A hit is never benign evidence. Injection text inside an alert is itself evidence of an attacker.
- In the rule intent service (§8):
  - A hit in the SPL or the rule description stops the mapping, and the rule goes to a human.
  - A hit in a past notable or search result excludes that item from the model's inputs, and the item is opened as a review case for the SOC.
- In the steward's closure mining (§12): the closure is not counted as evidence for any proposal, and the note goes to the SOC lead.

Model choice is open. Candidates:
- Protect AI's DeBERTa-v3 prompt-injection classifier. Splunk's post on the OWASP Top 10 for LLM applications points to Protect AI's detection model.
- A guard model from Cisco Foundation AI, if one exists. A quick search in October 2026 found none; Foundation-sec-8B is a security LLM, not a classifier.
- Meta's Prompt Guard, a public prompt-attack classifier, under the Llama community license.

Before choosing, check each license and evaluate the candidates on our own test set of benign and injected alert text: command lines, email bodies, URLs, rule descriptions. The threshold is set per deployment, and the false-positive rate is reported. The classifier's false-positive rate on the customer's own benign alert text is measured in Shadow and is part of the gate before Recommend. The classifier runs on the customer's premises, on the same deployment as the agents.

### Reranker
Offline and supporting paths only, never the runtime triage path, which stays SQL-only:
- the rule intent service, after the vector search for the closest known detections, so the mapping put to the rule owner rests on the best candidates
- the steward's closure mining, to group similar closure reasons
- investigation (later phase)

Model choice is open: an open-weight cross-encoder running on the customer's premises.

## 14. Later phases
Cross-customer analytics with anonymized counts only (question ID, outcome, sector). Investigation agent using an attack-path graph (e.g. MITRE Attack Flow) and a per-incident evidence graph.

Detection engineering module: tunes, fixes and writes the customer's detections from evidence gathered by the rule intent service and the steward. It needs change control and testing, and is out of scope until triage is proven.
