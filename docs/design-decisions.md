# SmartOps Triage Agent: Design Decisions

Build status: built today are the question bank (`bank/`) and its offline gates and tools (`tools/`: validate, attacker-influence check, replay, review packet, SQL loader, runtime-bundle export). Everything marked "(designed, not built)" is design only: agreed direction, not running software, and open to change when it is built and measured.

## 1. What triage is
A fast, time-boxed first pass on an alert: is it worth investigating, and how urgently? It does not prove malice; that is investigation. Two separate calls: verdict (malicious or benign) and priority (how fast). Asset criticality changes priority and autonomy, never the verdict.

## 2. Method
For each detection, list its 2–3 most common benign explanations and test only those, as yes/no questions. One holds → close as false positive or benign true positive, with a reason code. None holds → escalate. Missing answer → unknown → analyst decides.

Vendor alerts (AV/EDR, IDS/IPS, WAF, email gateway, DLP, proxy, firewall, device control) add a third close: **mitigated true positive**, when the activity was malicious or unwanted but the control that raised the alert stopped it (blocked, quarantined, denied) and nothing else needs doing. Each vendor family is one generic detection (`vendor:` prefix) bound to normalized alert fields, never one per product.

Mitigated true positive never applies to high-risk families: hack tools, credential dumpers, ransomware, web shells, exploit frameworks, remote access trojans and remote-admin tools, miners, proxyware and cracks. Those escalate even when blocked. Antivirus test files (EICAR and similar) flag; they never close as low risk. Only a block before execution counts: post-execution quarantine or cleaning, a pending reboot and partial remediation answer unknown and flag. Each vendor's action values map to the bank's normalized values in `docs/normalization.md`.

Internal sources: for firewall, IDS and WAF alerts, a source inside the customer's internal networks (a per-customer parameter) never closes on denied, blocked or patched; it flags or escalates. Tuned-signature and approved-scanner closes still apply to internal sources. In IDS and firewall flows an approved scanner closes only while its scan job targets the alert's destination (unknown flags); in WAF flows it needs a change ticket naming the source.

## 3. Boundary
Only entities named in the alert, only alerts that already fired, and the triage window: the 24h before the alert (look-back only, parameter). Nothing after the alert is read at triage time; forward-looking checks belong to the Falsifier (§5), after the fact. Pivoting to other entities or building raw-log timelines is investigation, out of scope.

## 4. Unit of work: the entity (designed, not built)
The unit of decision stays the alert: each alert runs its own yes/no flow and gets its own verdict. The unit of work is the entity: the host (by asset ID) and the user.
- Intake groups incoming alerts by entity over a short window (parameter, default 10 minutes).
- Context and measurements are fetched once per entity and shared through the measurement cache (§19).
- Precedent, burst and repeat logic key on the entity.

Entity guard: it runs once per entity per window, before Q0.
- If the entity has an open escalation, or at least N alerts (parameter, default 3) from at least 2 different detections in the window, every close on that entity becomes a flag, and the entity is marked "hot" for the window.
- It is raise-only: it can turn closes into flags, never the reverse. Each alert's flow still runs, so its answers and evidence reach the analyst.
- A hot entity raises the alert's priority (§18).

ES risk notables (risk-based alerting) are entity-level by nature. They get their own flow family in batch 2.

The queue shown to analysts groups flags and escalations by entity, so three alerts on one host are one item to review, not three.

Entity resolution needs asset IDs and identity lookups; data readiness (§9) measures how many alerts map to both.

## 5. Agents (designed, not built)
Agents are decoupled. Each has its own instructions, tools, model and permissions: its own service account, with least privilege. Agents call each other as tools.

| Agent | Runs | Job |
|---|---|---|
| Triage agent | every alert | Runs the fixed flow and applies the thresholds. A local model writes the explanation and reviews closes (raise-only). |
| Tool Broker | every question | Routes each question to a domain specialist and returns a measurement plus evidence (§7). |
| Domain specialists (under the Tool Broker) | build mode at onboarding and in Shadow; run mode per question | Endpoint, network, identity, email, threat intel and Splunk. Each knows its tools through an MCP gateway. The Splunk specialist also runs the data readiness checks (§9). |
| Detection Engineer | at onboarding and on rule change | Works out what each detection is for (§15). It asks the Splunk specialist for data and never writes SPL itself. Read-only for now; in a later phase it gains rule changes (the detection engineering module, §27). |
| Use Case Manager | continuously | The duties in §25, plus repairing recipes (§8) and proposing threshold changes (§11). |
| Falsifier | after the fact, on sampled closes | Tries to prove sampled closes wrong, and prepares the approval packet for every reduce-scrutiny proposal. Raise-only. |
| Tier-2 analyst | later phase | Investigation. Fully agentic; a human reads the result. |

### Falsifier (designed, not built)
Job: try to prove sampled closes wrong. It runs after the fact, never in the triage path.
- It may look forward 24–72h after the close (new alerts, logins, outbound connections on the entity) and pivot to other entities and raw logs. The triage boundary (§3) does not apply to audit.
- Output per close: "could not falsify", listing what it checked, or "possible miss", with the evidence.
- Raise-only: it can reopen a close or flag it, never close or approve anything.
- Humans fully review every "possible miss", plus a random slice of "could not falsify", which measures the Falsifier's own miss rate.
- The promotion gate (§17) counts only human-confirmed results.
- It runs on the customer's premises; every input it passes to a model goes through the injection classifier (§26).

Approval packets: for every reduce-scrutiny proposal (from the Use Case Manager or a person), it prepares one page:
- Replay: what the change would have closed over the last 90 days, including any past escalations or confirmed incidents among them. The replay is deterministic, run from stored measurements (§11), not by a model.
- Attacker's view: can an attacker meet this condition? The same attacker-influence test as the bank (§12).
- Evidence: which closures support the proposal, and whether the anti-poisoning rule (§25) is met.

Low-risk items (an unchanged renewal of an entry still in use) are batched for one-click approval.

## 6. Product Operator (designed, not built)
For the first six months a Reno Product Operator runs the system at the customer: onboarding, recipe building, the approval desk, audits and tuning. A named customer person shadows the operator throughout.

Accountability, written for SAMA, NCA and CBUAE expectations:
- The Reno operator prepares and runs everything.
- The customer's named owner co-signs every reduce-scrutiny change and every promotion to Auto.
- Each Auto detection has a named accountable owner at the customer.

Handover is an exit test, not a date. The customer operator has:
- run the weekly cycle alone for 4 consecutive weeks
- cleared the approval queue within its SLA
- passed one audit with no confirmed false close

After handover, Reno senior auditing continues as a remote subscription: review of the Falsifier's findings plus the audit sample (§17).

## 7. Questions are portable, answers are local
Every question is answerable by one lookup against:
- Context store: assets, identities, allowlists, VPN ranges, sanctioned tools, change windows with their implementers (customer-provided or mined from Splunk)
- Baseline engine: "is this normal for this entity?" yes/no, from the customer's logs
- Case memory: precedents (past closures with reasons)
- Alert field: values in the notable itself

### Capabilities and the Tool Broker (designed, not built)
The Triage agent never knows which tools a customer has. Each question declares exactly one capability (`bank/capabilities.yaml`, e.g. `list.lookup`, `entity.baseline`, `org.prevalence`, `change.window`, `file.signer`, `file.reputation`). The bank holds no tool names or SPL.

Flow of one question:
1. The Triage agent sends the question to the Tool Broker: capability plus inputs, with the windows and lookbacks taken from the parameter table (§11).
2. The Tool Broker routes it to the domain specialist that owns the capability for this customer. Any of the customer's tools may be disconnected.
3. The specialist runs the customer's frozen recipe for that capability (§8).
4. It returns a measurement (a count, a match, a value) with evidence.
5. The Triage agent applies the threshold from the parameter table and gets yes, no or unknown.

Principle: the broker measures, the Triage agent judges. No threshold lives in a recipe. `docs/capability-spec.md` lists, for each capability, the measurement it returns and the Triage-side rule that turns it into an answer.

`alert.field` reads a normalized field of the alert itself (for example the control's action). The Triage agent answers it locally, not through the Tool Broker, and it does not count against the call budget.

Splunk's own MCP server, where present, is used to execute searches and list metadata. Its SPL generation is never trusted directly: any SPL it suggests is a draft that must pass the recipe tests (§8) before it is used.

Answer contract: `answer` (yes | no | unknown), `unknown_reason` (no_capability | unavailable | no_data), `evidence`, `source_tool`, `observed_at`. The Tool Broker returns the measurement, evidence, source tool and time; the Triage agent sets the answer.
- no_data: follow the step's `on_unknown`.
- unavailable (tool down, timeout): never closes; the alert is flagged and the detection runs in Recommend until the capability is healthy again.
- no_capability: resolved per customer at onboarding. The question is disabled, its step follows `on_unknown` without a call, and it is listed in the coverage report.
- A yes that rests on seed data with `verified: false` taints the rest of the flow: that step and any later close reached through it become a flag until onboarding verifies the entry. The same holds for a value translation not yet approved (§8).
- Reputation and anomaly capabilities are escalate_only: a hit escalates or flags and never closes; a miss is never benign evidence.
- `change.window` answers yes only when an approved change covers the host and time and lists the alert's user (or one of their groups) as implementer; no when nothing covers it, or every covering change lists implementers without the user; unknown (no_data) when a covering change has no implementer data.
- `vuln.not_applicable` answers unknown when the signature maps to no CVE (most generic IDS and WAF rules), so it never closes them. The replay gate counts these unknowns.
- `alert.history` counts alerts that already fired inside the triage window and share a key (the fingerprint, or a source, destination, user or campaign key). It reads existing alerts only, never raw logs. A count at or above the per-customer threshold (default 3; proxy 10) is used as a guard that raises the outcome, typically a close to a flag: a burst is not noise.

The Tool Broker enforces scope: entities named in the alert only; fixed windows (the 24h look-back triage window for event lookups; baselines and prevalence use their declared lookbacks and return counts, not raw events); read-only; a per-call timeout (timeout = unavailable); at most 6 calls per alert including Q0, counted on the worst single path through the flow (steps plus the guards of the closing step). Resolving a file's hash or signer inside a lookup is the broker's job and does not count against the budget.

Write-back goes only through `list.propose_update`. Reduce-scrutiny changes (allowlist additions) need human approval with an owner and an expiry. Increase-scrutiny changes (watchlists, removing an allowlist entry) may be automatic; removing an allowlist entry must notify the fact's owner. Enforcement blocks need approval.

Vendor neutrality: the bank holds no vendor or product names. Only offline metadata (`data_source`, `sigma_logsource`, `sigma_refs`, `source`, `license`) may name them, plus seed data under `bank/seeds/`, which is loaded into the customer's context store at onboarding and never reaches the agent. Question text describes what to check about an entity, never where or with which tool. The Triage agent receives a runtime bundle (`tools/export_bundle.py`) built without the offline metadata; the validator fails if the bundle contains an offline key or a vendor name. Recipe templates (§8) may name tools; they ship separately from the runtime bundle.

Vendor value mappings (`docs/normalization.md`) mark each row verified or not. The cap is per customer: a detection is capped at Recommend for a customer while that customer's product rows for its family are unverified, as recorded by the onboarding check "Check vendor alerts are normalized". The detection declares `auto_requires: [vendor_mapping_verified]`; `validate` requires it for any family with unverified rows.

Allowlist and "known tool" lookups match on file hash, or code-signing signer plus path, never on name or path alone. Names and paths are attacker-controlled. Where the alert lacks hash or signer, fetch them from the same process's creation event by process GUID; if still unavailable, the answer is unknown.

## 8. Recipes (designed, not built)
A recipe is how one capability is measured on one customer's tools. It has two layers.

Template: the generic way to measure a capability on a type of tool. Templates ship in the bank as YAML and are reviewed like questions.
- Event searches are Sigma rules, compiled to SPL by pySigma with a per-customer pipeline (index, sourcetype, field names).
- Lookups and API calls (lists, threat intel, change records, alert history) are small typed templates with the same lifecycle.

Customer recipe: the template bound to one customer. It holds the pipeline, the compiled query (a frozen copy), the value table, known-answer tests, status and version. Recipes are stored in the customer's database on premises and looked up by exact key (capability + customer + tool). There is no vector store at runtime; vector search may help a specialist find the closest template while building.

Lifecycle:
1. Build mode (agentic). At onboarding the specialist binds the template, compiles it and runs known-answer tests. A known value must return the expected result, and the data source must show recent events, so an empty result is never mistaken for "no". Status: shadow.
2. Shadow. Queries may change freely; humans review every answer.
3. Promotion freezes the recipes the detection uses. Runtime runs only frozen recipes.
4. Known-answer tests run daily. On a failure, the Use Case Manager has the specialist repair the recipe, and that capability returns to Shadow.
5. Live fallback. With no recipe, or a broken one, the specialist may answer agentically, but that answer can only raise scrutiny (flag or escalate). It never supports a close.
6. Runtime values (hash, host, user) are inserted escaped, as parameters, never concatenated into query text.

Value tables: a small local model translates raw vendor values (for example an antivirus action string) into a fixed short list. The first time a value appears, the translation is saved to the customer's value table and goes to the Use Case Manager for approval. A close path that depends on an unapproved translation becomes a flag, mirroring the unverified-seed rule. Approved translations are plain lookups, with no model involved.

## 9. Data readiness (designed, not built)
Owned by the Splunk specialist. The checks run at onboarding, before any recipe is built:
- CIM data models enabled and accelerated, with acceleration completeness
- field coverage per data model (for example, the share of process events that carry a hash)
- ingestion delay and time sync
- Enterprise Security asset and identity lookups populated
- notable volume per rule, with historical dispositions (feeds the addressable-volume report, §10)
- search-head concurrency headroom (feeds the throughput limits, §19)
- EDR agent coverage across hosts
- whether risk-based alerting is in use
- asset-ID availability in the Malware data model (without it, AV precedents rate medium)
- entity resolution quality: the share of alerts mapped to an asset ID and to an identity (§4)

The output is a data health report for the customer. It feeds the coverage report and decides which capabilities can be built at all. The full checklist is at the end of `docs/capability-spec.md`.

## 10. Addressable volume (designed, not built)
At onboarding, from the customer's 6–12 months of notable history, compute per rule:
- its share of total notable volume
- its historical share closed as false positive or benign. This is the ceiling the system can ever reach on that rule: the flows can only close what analysts would have closed.
- whether the bank covers it: rule-level, technique-only or none

The addressable volume is the sum, over covered rules, of volume share × ceiling. It is the only number used in sales claims. It also orders the customer's onboarding, and decides which detections to build next. The value metric is analyst hours saved and entities to review per day, not only the auto-close percentage.

## 11. Thresholds and parameters (designed, not built)
- Thresholds live on the Triage agent side, in parameters. Precedence: customer + detection > customer default > detection default > global default (`bank/parameters.yaml`).
- Every parameter has a minimum and a maximum in the bank, and validation rejects values outside them.
- A change that adds scrutiny may apply directly. A change that removes scrutiny needs human approval, with an owner and an expiry.
- Time windows and lookbacks travel with the request to the Tool Broker, but their values come from the same parameter table.
- Measurements are stored. In Shadow, the Use Case Manager replays stored measurements against candidate thresholds and proposes changes with that evidence.
- The promotion gate (the audited false-close rate, §17) belongs to the mode controller, not to flows.
- No model-generated confidence scores. "High confidence" means every answer on the close path came from a frozen recipe with a low attacker-influence rating.

## 12. Bank structure
- Two levels: rule-level flows per known detection (ESCU, Sigma, Elastic) and technique-level fallback flows per ATT&CK technique.
- Technique-only rules are capped at Recommend mode.
- No questions (usually a custom rule): no verdict; the agent sends a context pack, the analyst triages, the Use Case Manager drafts questions from the analyst's reasoning for human approval, and the rule starts in Shadow.
- Flows: at most 5 steps, early exit; each step has on_yes / on_no / on_unknown → next | close:<disposition>:<reason_code> | escalate | flag.
- Guards: a step may carry guards, extra checks that run when the step reaches a close or, where a guard says so, a flag outcome. Each names a question, the answers that trigger it and the result (flag or escalate); an unknown guard answer raises to at least flag. Guards only raise: a close becomes a flag or an escalation, a flag becomes an escalation, never the reverse, and no guard attaches to an escalate outcome. All applicable guards run and the strongest result wins (escalate > flag), whatever their order. A guard may apply only to some matched list entry types (for example analysis hosts versus approved tools). A guard that fires on no means a close needs a yes from it. Guards never create a close, and their calls count against the call budget on their path.
- Attacker influence: none, low, medium (control-recorded but forgeable in transit, such as alerts forwarded over syslog), high. Every close path must rest on a yes rated none or low. A question may rate itself per source profile (direct API or forwarded); the profile is recorded per vendor family at onboarding, and a close left without a none/low yes under the customer's profile flags.
  - Rating rules (designed, not built; the bank change comes next): a question cannot be rated lower than its capability's rating in `docs/capability-spec.md` without a written reason, which is flagged for review. Baselines default to high. `change.window` is low, and only for approved changes whose approver is not the implementer. Identity group membership is never the only low-rated answer on a close path.
- Q0 precedent check first in every flow: same fingerprint (rule + entity + key attributes) closed with a recorded reason within the validity window (e.g. 24h–7d), the detection's precedent entity not a crown jewel, no other alert on it in the window → close citing the precedent. In Shadow and Recommend the precedent is shown to the analyst instead.
  - Changes (designed, not built; the bank change comes next): inherit only closes that passed audit, or at least 2 independent analyst closes of the same fingerprint; "no other alert on it in the window" becomes "no alert of higher severity on the entity in the window" (the entity guard, §4, now covers alerts from other detections); validity defaults to 24h with a maximum of 72h (parameter bounds).
  - Each detection names its precedent entity and rates each fingerprint field's attacker influence. Q0's rating is the least attacker-chosen field's. If every field is attacker-chosen (sender, subject, message id), the precedent never closes or flags by itself: the flow proceeds and the match is shown as context. If the best field is medium (spoofable source addresses), the close also needs a low-rated yes from a guard, such as "every connection was denied".
  - A precedent closed as mitigated true positive is inherited only when the current alert was also blocked.
  - Three or more earlier alerts with the same fingerprint in the triage window turn the precedent close into a flag.
- Two layers: public base bank plus a customer layer (runbooks, mined closures) that overrides base entries by ID. Mined closures are evidence, not truth, and go through curation.

## 13. Repeat alerts (designed, not built)
An alert matching an open case's fingerprint is attached to it without new triage. An attached alert triggers re-triage when the case's count spikes or the alert brings a new attribute value. A rule firing hundreds of times on one entity becomes a tuning ticket (throttling or risk-based alerting).

## 14. Storage
- Question bank: YAML in git, loaded into SQL tables. Exact, repeatable, auditable, reviewed through PRs.
- Custom-rule matching: pgvector in the same Postgres, offline only.
- Customer recipes, value tables, stored measurements and decision logs: the customer's database on premises, keyed exactly (capability + customer + tool) (designed, not built).
- Investigation (later phase): graph database. The YAML already has typed nodes, typed edges and stable IDs, so it loads into a graph DB unchanged.
- Runtime is a loop: load the detection's steps, answer each with one measurement and its threshold, follow yes/no/unknown, stop at the first close or escalate.

## 15. Detection Engineer (custom rules) (designed, not built)
Runs once per rule, at onboarding and on rule change, never per alert.

Inputs:
- the rule's SPL
- the results of running it, read-only, over the last 30 days with a row cap (parameter), plus field coverage. The Detection Engineer asks the Splunk specialist for these; it never runs searches or writes SPL itself.
- a sample of its notables

A rule that never fired uses the SPL only.

Steps:
1. Parse the SPL. The intent comes mainly from the SPL logic: results show what fires, not what the author intended.
2. The local per-rule model (§16) writes the intent ("Detects <behavior> on <entity> from <data source>"), classifies the rule (threat, policy/compliance or operational noise) and proposes ATT&CK techniques. Only threat rules go to triage.
   - The results sharpen these.
   - The notables record which fields are actually populated. Step 5 uses this list, not fields guessed from the SPL.
3. Vector search, then the reranker (§26), returns the 3 closest known detections. A strong match is one where the techniques and the closest detections agree.
4. Strong match → inherit questions as drafts. Technique only → capped at Recommend. Neither → context pack. Every mapping starts in Shadow.
5. Drop inherited questions that need fields the notables don't populate.
6. The Use Case Manager asks the customer's rule owner to confirm in plain language, for example: "This rule detects X. In 30 days it fired 400 times, 92% from the patch servers. Is that what you intended?" The mapping is stored in SQL once confirmed. No vector search at runtime.
   - If the rule has no active owner (`identity.status`), the Use Case Manager asks the SOC lead instead.
   - If nobody confirms within 14 days (parameter `intent_confirm_days`), the mapping may run but is capped at Recommend. It can never reach Auto until someone confirms it.
   - The Use Case Manager re-asks monthly and lists unconfirmed mappings in its metrics.

Data and safety:
- Everything the Detection Engineer does runs on the customer's premises.
- Results and notables pass the injection classifier (§26) before the model reads them.

Boundary:
- The Detection Engineer is read-only and never changes a rule.
- Noise patterns it finds go to the Use Case Manager as a fact proposal or a tuning ticket (§13), and a human decides between them. A fact keeps the alerts visible and closes them. Tuning stops them firing, which blinds detection on those entities.

Safety net: a wrong intent leaves the rule in Shadow. Analysts disagree with its verdicts, so it never reaches the promotion threshold, and it never wrongly closes anything.

Later phase: the Detection Engineer gains rule changes (the detection engineering module, §27).

Each known detection carries `sigma_logsource` ({product, category} or {product, service}, from Sigma's own taxonomy) and `sigma_refs` (equivalent or closest SigmaHQ rules). These are offline metadata that let this service match custom rules to known detections across SIEMs; they are never used at runtime. The bank holds no OCSF. If a customer's data is in OCSF, the mapping lives in the Tool Broker's per-customer adapter.

## 16. Model roles (designed, not built)
Deployment principle: every model that touches customer data runs on the customer's premises. That covers the runtime models, the domain specialists, the Detection Engineer's model, the Use Case Manager, the injection classifier and the reranker. The only model outside the customer is the offline drafting model, and it sees public sources only.

Offline (Reno's build pipeline, public sources only):
- A frontier model drafts questions, explanations and facts from public sources.
- Gates (validate, the attacker-influence check, replay) and an external review check them.
- A human approves before anything leaves draft.
- This model never sees customer data.

Runtime decisions use no language model:
- Question selection is a bank lookup: detection ID (or the approved custom-rule mapping, §15) → flow.
- Each answer comes from one capability measurement through the Tool Broker, run by a frozen recipe (§7, §8), with the threshold applied by the Triage agent (§11).
- The verdict is where the flow stops.

Local model roles (on the customer's premises):
- The bank and the flows don't depend on which model fills a role. Each deployment picks a model per role from an evaluation harness run on our test sets, within the customer's hardware. Check each model's license before use.
- Per-alert roles need speed, so they use a small model. Candidates: Cisco Foundation-sec-8B (an instruction-tuned variant), gpt-oss-20b, a small Gemma.
- Per-rule roles run once per rule and need reasoning, so they use the largest model the hardware fits. Candidates: gpt-oss-120b, a larger Gemma.
- No model has tool access in any runtime role. The domain specialists' build mode and live fallback are the only agentic tool use, read-only through the MCP gateway, and neither can support a close.

Roles:
1. Explanation writer (per alert): turns the answered checks into the analyst-facing explanation. It cannot change the verdict, the priority or the mode.
2. Close reviewer (per alert, raise-only):
   - It reads every alert the flow would close, with its answers and evidence, and returns keep, or flag with a one-line reason.
   - It can turn a close into a flag. It can never turn a flag or an escalation into a close.
   - If it is wrong, the worst case is that an analyst reviews one extra alert. It can never cause a missed attack.
   - In Shadow, measure how often it flags and how often analysts agree its flags were worth a look. Below a per-customer threshold (parameter `model_review_min_precision`, draft default 0.3), it is switched off for that detection.
   - Its calls do not count against the 6-call Tool Broker budget.
3. Detection Engineer (per rule, §15).
4. Use Case Manager drafting (§25): proposal and runbook text.
5. Domain specialists (§5, §8):
   - Build mode (per customer, at onboarding and in Shadow): the largest local model the hardware fits binds templates, compiles and tests recipes.
   - Run mode (per question): no model. A frozen recipe runs.
   - Live fallback (no recipe or a broken one): a local model answers agentically; the answer is raise-only.
   - Value translation (first sighting of a raw vendor value): a small local model; the translation waits for Use Case Manager approval.
6. Investigation (later phase).

Audit sampling, for the 5–10% audit of automatic closes (§17):
- Half the sample is the closes the close reviewer ranks oddest.
- The other half is random, so the audit is not blind to what the model misses.
- Humans do every audit.

Proposals for new questions, facts or exceptions come only from the Use Case Manager (§25), never from a per-alert role.

Supporting models: the injection classifier and the reranker (§26), on the customer's premises.

## 17. Modes and guardrails (designed, not built)
Per detection: Shadow (verdict hidden) → Recommend (analyst accepts or overrides) → Auto (close benign, escalate suspicious). Auto mode requires process telemetry with hashes (Sysmon or EDR); customers on Security 4688 only stay in Recommend. Permanent: no auto-close on crown jewels (in every mode, any close on a crown-jewel entity becomes a flag; this is how the AV review's "crown-jewel host → flag" is met for every detection); audit 5–10% of auto-closures; escalation is never suppressed.

### Promotion gate: the audited false-close rate
- The gate is the audited false-close rate. A senior reviewer (the Reno Product Operator, then the subscription auditor after handover, §6) checks a sample of the detection's closes, with the Falsifier's findings (§5) attached.
- Sample: stratified by detection; at least 200 closes for high-volume detections, and every close for low-volume ones.
- Zero confirmed false closes are required to promote.
- The arithmetic: if a detection's true false-close rate were p, the chance of seeing no false close in 200 independent closes is (1 − p)^200. Setting that to 5% gives p ≈ 3/200 = 1.5% (the rule of three). So zero misses in 200 means the true miss rate is below about 1.5%, with 95% confidence. A smaller sample proves less: zero in 50 only bounds it below about 6%.
- Outcome checks (below) also count against the gate: a confirmed miss found there counts exactly like one found in the sample.
- Agreement with analysts stays a diagnostic only, reported per detection, never the gate. Analysts close the same easy alerts the flow does; agreement cannot show the closes that both got wrong.
- The customer's named owner co-signs every promotion to Auto (§6).

### Outcome checks
When an incident is confirmed, every close on the same entities in the previous 30 days (parameter) is re-checked. Each miss counts against the gate of the detection that closed it, and opens a review of that flow.

## 18. Splunk ES integration (designed, not built)
- Each disposition is written back to the ES notable: status, owner, comment, and a link to the evidence.
- Priority = ES urgency (severity × asset priority), adjusted by the verdict and by the entity being hot (§4). SLA clocks run per priority (parameters).
- Escalation target and ticketing are configured at onboarding. They use the customer's existing ES integration to ServiceNow or Jira, and escalate to a named IR queue.
- The analyst works in ES Incident Review or Mission Control, grouped by entity, where our comment and evidence link appear on the notable.

## 19. Throughput (designed, not built)
- A measurement cache keyed by (capability, entity, window), with a time-to-live, shared across all alerts on the entity (§4).
- Alert-history lookups batched.
- A concurrency cap on searches against the customer's search head (parameter).
- The backlog is processed in priority order.
- A load test on the customer's search head is an onboarding gate before Shadow.

## 20. Decision log and compliance (designed, not built)
- Per alert, the log holds:
  - the inputs and measurements
  - the recipe, flow, parameter and model versions used
  - every answer and the verdict
  - the entity-guard state (hot or not, and why)
  - who or what made each change (agent, operator, approver)
- Retention is a per-regulator parameter.
- All service-account access is logged.

## 21. Degraded mode (designed, not built)
Triggers:
- more than a threshold share of capabilities unavailable (parameter)
- failing recipe tests
- an approval backlog over its limit (parameter)

Response: the affected detections drop to Recommend (or to Shadow), and a daily report lists what is degraded and why. They return automatically once the cause clears and the recipe tests pass.

## 22. SOC manager metrics (designed, not built)
- addressable volume, and actual against it (§10)
- analyst hours saved
- entities to review per day
- time to triage
- auto-close rate
- split by disposition
- audited false-close rate
- backlog and SLA breaches
- approval queue age

## 23. HA, DR and backup (gap)
Case memory, recipes, value tables, parameters and decision logs need backup and restore. High availability and disaster recovery are not designed yet; this is a known gap.

## 24. Sources and licenses
- splunk/security_content (ESCU), Apache-2.0: known_false_positives, ATT&CK mapping, data source
- elastic/detection-rules, Elastic License 2.0: "Triage and analysis", "False positive analysis"
- SigmaHQ/sigma, Detection Rule License (attribution): falsepositives
- LOLBAS, GTFOBins, LOLDrivers: legitimate uses of binaries and drivers
- Azure/Azure-Sentinel, MIT: primary source for the identity and cloud domain (Entra ID, M365, Azure). It has no false-positive field; benign hints live in query comments and descriptions. Its `entityMappings` are the model for which entities a detection's alert exposes.
- MITRE ATT&CK v20.0 (mitre-attack/attack-stix-data): techniques, detection strategies. v19 (April 2026) revoked T1562.001 → T1685 and T1070.001 → T1685.005; use current IDs.
Record source and license on every question; non-Apache text needs legal review before commercial use.

## 25. Use Case Manager (designed, not built)
The Use Case Manager keeps the triage knowledge current: context facts, allowlists, exceptions, questions and runbooks. It runs continuously, so triage quality does not depend on people following documentation or on who is still on the team. The triage agent decides; the Use Case Manager keeps the knowledge it decides with up to date.

Duties:
1. Fact freshness: finds facts near expiry, or whose owner is disabled or has left (identity capabilities), and asks the right person to re-confirm. Expired facts stop being used.
2. Closure mining: turns recurring analyst closure reasons into proposals: a new exception, a new fact or a new benign question.
3. Cleanup: proposes removing allowlist and exception entries unused for 90 days (per-customer parameter).
4. New patterns: drafts a new question when a benign cause recurs and no question covers it.
5. Rule changes: new or edited detections are re-mapped by the Detection Engineer (§15) and start in Shadow; the Use Case Manager tracks each one until it is mapped, has questions and has a mode.
6. Runbook sync: generates human-readable runbooks from the bank, so the documentation always matches what the triage agent does.
7. Turnover resilience: all knowledge lives in the bank and the context store, with owner, reason, evidence and history, never only in people's heads.
8. Recipe repair: when a recipe's daily known-answer tests fail, it has the owning specialist repair the recipe, and that capability returns to Shadow (§8).
9. Threshold proposals: replays stored measurements against candidate thresholds in Shadow and proposes changes with that evidence (§11).
10. Value tables: approves or rejects each new raw-value translation (§8).

Guardrails:
- It proposes, and never decides, anything that reduces scrutiny: an allowlist entry, an exception, a trusted entity, or a question that adds a close path. Each needs human approval, an owner and an expiry, with a full audit trail.
- It may apply increase-scrutiny changes on its own (a watchlist entry, removing an expired entry), and must notify the fact's owner.
- Anti-poisoning: a reduce-scrutiny proposal needs evidence from at least 3 analyst closures, by at least 2 different analysts, on at least 3 distinct days (per-customer parameters). The triage agent's own automatic closures never count as evidence, so the two agents cannot reinforce each other. A proposal driven by alerts from a single source, or by a burst inside one window, is rejected.
- It writes only through the Tool Broker's `list.propose_update` and fact-update capabilities, and never edits customer tools directly.
- It runs on the same deployment as the triage agent, on the customer's premises.

Metrics: proposals made, accepted and rejected; unconfirmed rule mappings (§15); stale facts; average fact age; unused entries removed; time from a recurring pattern to an approved fact; runbook drift (should be zero).

Capabilities it needs (specification only; to be added to `bank/capabilities.yaml` in a Use Case Manager group with `flow_use: forbidden`, so no triage flow can call them):
- `fact.metadata`: a fact's owner, expiry and last use.
- `list.usage`: hit counts and last hit per list entry.
- `identity.status`: whether an owner's account is active.
- `closure.history`: analyst closures with reason and analyst id.
- `rule.inventory`: enabled detections and their change dates.

## 26. Model guardrails (designed, not built)
The structure is the primary defence. No language model decides a verdict: verdicts come from yes/no capability lookups rated for attacker influence (§7, §12). The controls below are defence in depth on top of that structure, not a replacement for it.

### Prompt-injection classifier
It runs on every input a language model reads that contains alert or customer-sourced content:
- the explanation writer (§16; it never changes the verdict)
- the close reviewer (§16)
- the Use Case Manager's closure mining (§25)
- the domain specialists' build mode, live fallback and value translation (§8), on tool output
- the Detection Engineer's model (§15), on SPL, rule descriptions, search results and notables
- the Falsifier (§5), on the alerts, logs and records it reads
- investigation (later phase)

On a hit, what happens depends on where the text came from. In every case the text never reaches the model, and the hit is logged with its score.
- In an alert (explanation writer, close reviewer, investigation), with reason code `injection_suspected`:
  - Shadow and Recommend: a hit flags.
  - Auto: a hit flags, deduplicated, with a per-source rate limit so a flood of crafted alerts cannot bury the queue. It escalates only with a second signal: another alert on the entity, or a reputation hit.
  - A hit is never benign evidence; it can never support a close.
- In the Detection Engineer (§15):
  - A hit in the SPL or the rule description stops the mapping, and the rule goes to a human.
  - A hit in a past notable or search result excludes that item from the model's inputs, and the item is opened as a review case for the SOC.
- In the Use Case Manager's closure mining (§25): the closure is not counted as evidence for any proposal, and the note goes to the SOC lead.

Model choice is open. Candidates:
- Protect AI's DeBERTa-v3 prompt-injection classifier. Splunk's post on the OWASP Top 10 for LLM applications points to Protect AI's detection model.
- A guard model from Cisco Foundation AI, if one exists. A quick search in October 2026 found none; Foundation-sec-8B is a security LLM, not a classifier.
- Meta's Prompt Guard, a public prompt-attack classifier, under the Llama community license.

Before choosing, check each license and evaluate the candidates on our own test set of benign and injected alert text: command lines, email bodies, URLs, rule descriptions. The threshold is set per deployment, and the false-positive rate is reported. The classifier's false-positive rate on the customer's own benign alert text is measured in Shadow and is part of the gate before Recommend. The classifier runs on the customer's premises, on the same deployment as the agents.

### Reranker
Offline and supporting paths only, never the runtime triage path, which stays SQL-only:
- the Detection Engineer, after the vector search for the closest known detections, so the mapping put to the rule owner rests on the best candidates
- the Use Case Manager's closure mining, to group similar closure reasons
- investigation (later phase)

Model choice is open: an open-weight cross-encoder running on the customer's premises.

## 27. Later phases
Cross-customer analytics with anonymized counts only (question ID, outcome, sector). Tier-2 analyst agent (investigation) using an attack-path graph (e.g. MITRE Attack Flow) and a per-incident evidence graph.

Detection engineering module: the Detection Engineer gains rule changes. It tunes, fixes and writes the customer's detections from evidence it and the Use Case Manager gather. It needs change control and testing, and is out of scope until triage is proven.
