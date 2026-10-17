# SmartOps Triage Agent: Design Decisions

**Version 1 scope.** Version 1 builds and tests one SIEM adapter: Splunk ES. All lab tests and the first pilots run on Splunk. The design stays vendor-agnostic: nothing outside the Splunk adapter and Splunk recipes may depend on Splunk.

Build status: built today are the question bank (`bank/`) and its offline gates and tools (`tools/`: validate, attacker-influence check, replay, review packet, SQL loader, runtime-bundle export). The intake, context-question, broker-question, onboarding and pilot documents (`docs/intake/`, `docs/broker-questions.md`, `docs/reuse-map.md`, `docs/assumptions.md`, `docs/pilot-terms.md`) describe designed, not built, components. Everything marked "(designed, not built)" is design only: agreed direction, not running software, and open to change when it is built and measured.

## 1. What triage is
A fast, time-boxed first pass on an alert: is it worth investigating, and how urgently? It does not prove malice; that is investigation. Two separate calls: verdict (malicious or benign) and priority (how fast). Asset criticality changes priority and autonomy, never the verdict.

## 2. Method
For each detection, list its 2–3 most common benign explanations and test only those, as yes/no questions. One holds → close as false positive or benign true positive, with a reason code. None holds → escalate. Missing answer → unknown → analyst decides.

Vendor alerts (AV/EDR, IDS/IPS, WAF, email gateway, DLP, proxy, firewall, device control) add a third close: **mitigated true positive**, when the activity was malicious or unwanted but the control that raised the alert stopped it (blocked, quarantined, denied) and nothing else needs doing. Each control-alert family is one generic detection (a D-ID in its family, mapped from any product's alerts through `product_alert:` entries in the rule map) bound to normalized alert fields, never one per product.

Mitigated true positive never applies to high-risk families: hack tools, credential dumpers, ransomware, web shells, exploit frameworks, remote access trojans and remote-admin tools, miners, proxyware and cracks. Those escalate even when blocked. Antivirus test files (EICAR and similar) flag; they never close as low risk. Only a block before execution counts: post-execution quarantine or cleaning, a pending reboot and partial remediation answer unknown and flag. Each vendor's action values map to the bank's normalized values in `docs/normalization.md`.

Internal sources: for firewall, IDS and WAF alerts, a source inside the customer's internal networks (a per-customer parameter) never closes on denied, blocked or patched; it flags or escalates. Tuned-signature and approved-scanner closes still apply to internal sources. In IDS and firewall flows an approved scanner closes only while its scan job targets the alert's destination (unknown flags); in WAF flows it needs a change ticket naming the source.

## 3. Boundary
Only entities named in the alert, only alerts that already fired, and the triage window: the 24h before the alert (look-back only, parameter). Nothing after the alert is read at triage time; forward-looking checks belong to the Falsifier (§7), after the fact. Pivoting to other entities or building raw-log timelines is investigation, out of scope.

## 4. Intake: SIEM-agnostic (designed, not built)
Flow: SIEM alert → normalizer (one inbound adapter per SIEM) → normalized alert → Triage agent, which asks the context questions (§5) and then its flow's triage questions through the Tool Broker. Write-back of status, comment, priority and ticket to the SIEM goes through the broker too (§20).

### One way in, one way out
- **In: the normalizer only.** It receives the alerts that start triage and nothing else. It never queries a tool. Alerts arrive by the SIEM's push mechanism (for example a Splunk ES alert action or webhook, a Sentinel automation rule, an Elastic connector), or by polling: the normalizer may poll the SIEM's alert queue with one fixed, read-only "new alerts since cursor" query per SIEM. That poll is the only query the normalizer ever runs. It never runs entity-specific or investigation queries; those are broker reads.
- **Out: the Tool Broker only.** Every read from any tool (SIEM, EDR, identity, email, threat intel, SOAR, asset and identity lookups) goes through the broker, for every agent: the Triage agent, the Detection Engineer, the Use Case Manager, the Falsifier, and the local models. No model calls a tool directly. The domain specialists are part of the broker, not callers of it.
- **Write-back through the broker.** Writing status, comment, priority and ticket to the SIEM alert are the broker's only write actions to a SIEM, on a fixed allowlist. What was the "outbound adapter" is the broker's write recipe per SIEM. Context-store proposals keep going through `list.propose_update` (§9).
- **Scope profiles.** The broker knows how far each caller may look:
  - `triage`: the alert's entities and fingerprint, 24h look-back only (§3)
  - `falsifier`: may look forward up to 72h after the close, pivot to other entities and read raw logs (§7)
  - `detection_engineering`: rule-wide and historical (for example 30 days), never per alert (§17)

  A call outside the caller's profile is refused and logged. Use Case Manager reads (fact metadata, list usage, closure history) run under their own read-only profile (§27).

SIEM adapters: Splunk ES in version 1 (see Version 1 scope above). Later: Microsoft Sentinel, Elastic Security, IBM QRadar, FortiSIEM and CrowdStrike Falcon Next-Gen SIEM. Nothing in the triage layer or the shared bank may assume one SIEM, its query language or its field names. Everything SIEM-specific lives in the inbound adapter and in the broker's per-customer recipes (§10), including its write recipes.

### Normalized alert v1
The normalizer turns each SIEM's alert into one shape, `normalized_alert` v1, specified field by field in `docs/intake/normalized-alert-v1.md`. It starts from smartops-soc-app's `context_service/templates/normalized_seed.py` (branch `feature/normalized-seed-template`, commit `062d456`) and keeps all of its sections. Added for triage:
- `schema_version`
- `source_alert`: SIEM, source alert ID, link back to the alert in the SIEM
- `detection.rule_id` (stable rule ID) and `detection.library` (escu | sentinel | elastic | sigma | custom | vendor)
- canonical entity roles: primary host (with asset ID), primary user, src, dest, file, process
- a typed entity list, using the entity types of smartops-soc-app's `engine/contracts/schemas/task-input.v1.schema.json` (main, commit `a2d0eb0`). An unknown type is rejected, never mapped to the nearest known one.
- `first_seen`, `last_seen`, `count` (dedup at intake)
- `reporting_control`: vendor and product, action, signature, category, for vendor alerts
- `alert:severity`: the alert's severity on the one normalized scale (`bank/contract/severity.yaml`: informational, low, medium, high, critical), mapped from each SIEM's own severity in `bank/intake/severity-map.yaml` (Splunk ES first). An unmapped value flags with reason `severity_unmapped`; the normalizer never guesses a level. C-02, C-03, Q0, the entity guard, the routine rule and priority compare only normalized severities (round 6, §3).

### Lessons carried over from smartops-soc-app
Each is cited by file on smartops-soc-app `main` at commit `a2d0eb0`, with the commit that introduced it.
- **Event time comes from the event, never the alert's creation time.** A SIEM alert's creation time can trail the activity: in the version 1 SIEM, a Splunk ES notable's `_time` is when the correlation search ran, often minutes to an hour after the activity. The event time is ESCU's `firstTime`, which carries no offset and takes `_time`'s offset. `engine/src/smartops/context.py`, `notable_event_time()` (introduced in `786a32f`; the bug and the 9-minute gap on run `072fd610` are in `docs/analyst-bug-report.md` C6 and `docs/smartops-issues-report.md` P1). Each adapter names its own event-time field; the normalizer never falls back to the alert's creation time silently: it records which field it used.
- **Dedup at intake.** ESCU rules run every 5 minutes over a 60-minute span with no throttle, so each event was raised about 12 times. `engine/src/smartops/context.py`, `notables_spl()` (`dedup search_name dest firstTime`, introduced in `ebc8e66`). The normalizer folds repeats on (rule ID, primary entity, event time) into one alert with `first_seen`, `last_seen` and `count`.
- **Escape attacker-controlled values before they enter any query.** `engine/src/smartops/context.py`, `_spl_escape()` (introduced in `330d1bc`). Recipes go further: runtime values are bound as parameters, never concatenated (§10). Every adapter escapes in its own query language.

### Entity missing
If the normalizer cannot fill an entity the detection needs (its `required_roles`, or the precedent entity), the alert flags with reason `entity_missing` and the normalizer opens a fix ticket for the rule's owner (the rule's entity mapping or field extraction is broken). It never guesses an entity, and it never runs the flow on a partial alert. Data readiness (§11) measures how often this happens per rule.

### Matching an alert to the bank
Matching uses the exact rule ID, never the rule name. Detections have neutral IDs (D-0001…), grouped by family (endpoint, identity, endpoint malware, network, email, data protection), not by source library. One matching table, `bank/intake/rule-map.yaml`, maps every source rule ID to a D-ID; several source IDs may map to one D-ID. Only the normalizer and the Detection Engineer read it; the Triage agent never does.
- Rules from public libraries (Splunk ESCU, Microsoft Sentinel, Elastic, Sigma) match by ID, because those libraries are bank sources (§26).
- QRadar, FortiSIEM and custom rules have no public library in the bank. They go through the Detection Engineer (§17), which maps each to a known detection, a technique fallback or none, once per rule, and records the mapping in the rule map.
- Product alerts (AV/EDR, IDS, firewall, WAF, proxy, email, DLP, device control) map through `product_alert:` entries to the control-alert families (§2), which bind to the normalized `reporting_control` fields, so they work on every SIEM.
- Where a detection came from is kept on it as `derived_from` metadata, for our own reference only: the one place a triage file may name a library or vendor.

## 5. Context questions (designed, not built)
There is no separate context service. Context is a small fixed set of broker questions, the context questions, that the Triage agent asks once per entity per grouping window, at the "Group by entity" step (§6). The broker batches them and caches the answers per entity (§21), so every alert on the entity reads the same answers. They never hand the Triage agent a free-form bundle. Specified in `docs/intake/context-questions.md`; the rules every broker question follows are in `docs/broker-questions.md`.

Starting set:

| ID | Question | Answer type |
|---|---|---|
| C-01 | Open escalation or case on the entity | yes/no |
| C-02 | Alerts on the entity in the window | count, and count of distinct detections |
| C-03 | Highest severity of any other alert on the entity in the last 24h (the Triage agent compares it with this alert's: "higher severity") | value from a fixed list |
| C-04 | Audited closes, and independent human closes (manual closes in Shadow and analyst overrides, by distinct analysts), of this fingerprint: human evidence only (`bank/contract/evidence.yaml`) | count |
| C-05 | Asset priority | critical, high, medium or low |
| C-06 | Crown-jewel asset | yes/no |
| C-07 | Privileged user | yes/no |
| C-08 | Asset class | server, workstation, network, other or unknown |
| C-09 | Business time of the alert (designed, not built) | business_hours, after_hours, weekend, public_holiday or change_freeze |

**Guard-only questions.** C-09 is `guard_only` in the contract. Only a guard may read it: never Q0, the entity guard, priority, `closes_need_known` or a flow step, and the executor refuses to answer it as a step. It can only raise scrutiny (for example, an admin action after hours or in a change freeze flags); business hours are never evidence that an action is benign. It is answered from the customer's business calendar (working days Sunday–Thursday or Monday–Friday, hours including reduced hours such as Ramadan, public holidays, change freezes; `CF-0033`, capability `calendar.business_time`). It stays designed until the contract moves it out of `designed:`.

They feed the entity guard (§6), Q0 (§14) and priority (§20). They never close an alert on their own: they can only raise scrutiny or set priority.

**Missing context never closes and never escalates.** If a context question (C-01…C-08) is unknown or its source is unavailable, the alert cannot close on anything that depends on it, and the outcome is a flag with reason `context_unknown`, naming the C-ID. Missing context never escalates by itself, and no unknown answer is replaced by a worst-case value. Per question: C-01 or C-02 unknown, every close on the entity flags; C-03 or C-04 unknown, Q0 cannot close and the flow continues; C-05 unknown, priority stays at the SIEM's own urgency and any close that depends on asset priority flags; C-06 unknown, every close flags (Q0 and the crown-jewel rule depend on it) and Q-0067 flags; C-07 unknown, priority is not raised; C-08 unknown, Q-0067 flags and the entity guard uses the global defaults. A known server or crown jewel still follows the flow (Q-0067 escalates). `validate` rejects a worst-case default and any path where an unknown context answer leads to escalate.

Every answer carries a status and provenance (`docs/broker-questions.md`). A source that is down gives `source_unavailable`, never "no hit": an empty answer from an unavailable source is not evidence. For the entity guard, an unavailable C-01 or C-02 means the entity cannot be ruled out, so closes on it flag.

Everything else is asked only when a flow step reaches it, as a triage question: threat intel, baselines, prevalence, EDR detail.

Moved out of the per-alert path, from smartops-soc-app's `context_service/templates/context_contract.py` (branch `feature/context-contract-template`, commit `40e399d`):
- `rule_intent` (deployed SPL compared with the reference SPL) and `escu_context` → the Detection Engineer (§17), once per rule
- `opencti_threat_intelligence` → the threat-intel specialist, on demand, and only as typed answers (a reputation hit or not), never as a narrative

## 6. Unit of work: the entity (designed, not built)
The unit of decision stays the alert: each alert runs its own yes/no flow and gets its own verdict. The unit of work is the entity: the host (by asset ID) and the user.
- Intake (§4) groups incoming normalized alerts by entity over a short window (parameter, default 10 minutes).
- The context questions (§5) are asked once per entity and their answers, like all measurements, are shared through the broker's cache (§21).
- Precedent, burst and repeat logic key on the entity.

Entity guard: it runs once per entity per window, before Q0, and again on a fresh C-02 immediately before any close on the entity is written.
- If the entity has an open escalation, or at least N alerts (parameter, default 3) from at least 2 different detections in the window, or at least 2 distinct non-routine detections of medium normalized severity or above in the 24h look-back (`entity_day_min_detections`, `entity_day_counted_severities`, bounded; #18), every close on that entity becomes a flag, and the entity is marked "hot".
- A new alert on the entity invalidates the cached C-02 for the window. When the entity turns hot, the closes already written on it inside the window (for the 24h rule, the look-back) are reopened as flags with reason `entity_hot` (round 6, S1, S2). The replay gate checks both on alert sequences: 3 alerts from 2 detections within 4 minutes all flag; PsExec and LSASS access on one host, both medium, 15 minutes apart, both flag.
- It is raise-only: it can turn closes into flags, never the reverse. Each alert's flow still runs, so its answers and evidence reach the analyst.
- A hot entity raises the alert's priority (§20).
- It reads only broker answers: C-01 (open escalation), C-02 (alerts and distinct detections in the window) and C-08 (asset class, which picks N and the window).

Noisy entities (designed, not built):
- A pair (entity, detection) may be marked routine. A routine alert does not count toward N.
- Routine is a reduce-scrutiny change. The Use Case Manager proposes it from at least 4 weeks of consistent benign closes that are human evidence (`bank/contract/evidence.yaml`, `bank/triage/proposals.yaml`); it goes through an approval packet (§7), and a human approves it with an owner and an expiry.
- Always counted, never routine:
  - alerts of high or critical normalized severity
  - any detection not on that entity's routine list
  - any alert on an entity with an open escalation
- N, the detection count and the window are set per entity class from C-08 (server, workstation, network, other), as parameters with bounds and direction tags (`by_entity_class` in `bank/triage/parameters.yaml`; §13). Global default: N = 3 from 2 detections in 10 minutes, the same for every class until #18 measures otherwise. An unknown asset class uses the global defaults; it never picks the strictest class.
- Metric: the share of entities hot per day (§24). Issue #18 measures it on replayed bursts before the defaults are fixed.

Risk-based alerting (for example Splunk ES risk notables) is entity-level by nature, but its flows are deferred: most customers don't use it (`docs/assumptions.md`). Batch 2 is authentication and identity detections only.

The queue shown to analysts groups flags and escalations by entity, so three alerts on one host are one item to review, not three.

Entity resolution needs asset IDs and identity lookups; Phase 0 (§11) measures how many alerts map to both. An alert whose required entity cannot be filled flags with `entity_missing` (§4).

## 7. Agents (designed, not built)
Agents are decoupled. Each has its own instructions, tools, model and permissions: its own service account, with least privilege. Agents call each other as tools.

| Agent | Runs | Job |
|---|---|---|
| Triage agent | every alert | Runs the fixed flow and applies the thresholds. A local model writes the explanation and reviews closes (raise-only). |
| Tool Broker | every question | Routes each question to a domain specialist and returns a measurement plus evidence (§9). The only way out to any tool, for every agent and model, and the only path for SIEM write-back (§4). It answers the context questions (§5) once per entity and caches them. |
| Domain specialists (under the Tool Broker) | build mode at onboarding and in Shadow; run mode per question | Endpoint, network, identity, email, threat intel and SIEM (one SIEM specialist per SIEM the customer runs). Each knows its tools through an MCP gateway or read-only SOAR actions (§9). The endpoint specialist covers Defender, CrowdStrike, Kaspersky and other EDRs. The SIEM specialist also runs the Phase 0 checks (§11). |
| Detection Engineer | at onboarding and on rule change | Works out what each detection is for (§17). It reads data only through the Tool Broker, under the `detection_engineering` scope profile (§4), and never writes queries itself. It also owns, once per rule, what the old per-alert context carried as `rule_intent` and `escu_context` (§5). Read-only for now; in a later phase it gains rule changes (the detection engineering module, §29). |
| Use Case Manager | continuously | The duties in §27, plus repairing recipes (§10) and proposing threshold changes (§13). |
| Falsifier | after the fact, on sampled closes | Tries to prove sampled closes wrong, and prepares the approval packet for every reduce-scrutiny proposal. Raise-only. |
| Tier-2 analyst | later phase | Investigation. Fully agentic; a human reads the result. |

### Falsifier (designed, not built)
Job: try to prove sampled closes wrong. It runs after the fact, never in the triage path.
- It may look forward 24–72h after the close (new alerts, logins, outbound connections on the entity) and pivot to other entities and raw logs. The triage boundary (§3) does not apply to audit. Every read goes through the Tool Broker under the `falsifier` scope profile (§4).
- Output per close: "could not falsify", listing what it checked, or "possible miss", with the evidence.
- Raise-only: it can reopen a close or flag it, never close or approve anything.
- Humans fully review every "possible miss", plus a random slice of "could not falsify", which measures the Falsifier's own miss rate.
- The promotion gate (§19) counts only human-confirmed results.
- It runs on the customer's premises; every input it passes to a model goes through the injection classifier (§28).

Approval packets: for every reduce-scrutiny proposal (from the Use Case Manager or a person), it prepares one page:
- Replay: what the change would have closed over the last 90 days, including any past escalations or confirmed incidents among them. The replay is deterministic, run from stored measurements (§13), not by a model.
- Attacker's view: can an attacker meet this condition? The same attacker-influence test as the bank (§14).
- Evidence: which closures support the proposal, and whether the anti-poisoning rule (§27) is met.

Low-risk items (an unchanged renewal of an entry still in use) are batched for one-click approval.

## 8. Product Operator (designed, not built)
For the first six months a Reno Product Operator runs the system at the customer: onboarding, recipe building, the approval desk, audits and tuning. A named customer person shadows the operator throughout.

Accountability, written for SAMA, NCA and CBUAE expectations:
- The Reno operator prepares and runs everything.
- The customer's named owner co-signs every reduce-scrutiny change and every promotion to Auto.
- Each Auto detection has a named accountable owner at the customer.

Handover is an exit test, not a date. The customer operator has:
- run the weekly cycle alone for 4 consecutive weeks
- cleared the approval queue within its SLA
- passed one audit with no confirmed false close

After handover, Reno senior auditing continues as a remote subscription: review of the Falsifier's findings plus the audit sample (§19).

## 9. Questions are portable, answers are local
Every question is answerable by one lookup against:
- Context store: assets, identities, allowlists, VPN ranges, sanctioned tools, change windows with their implementers (customer-provided or mined from the SIEM)
- Baseline engine: "is this normal for this entity?" yes/no, from the customer's logs
- Case memory: precedents (past closures with reasons)
- The normalized alert itself (§4), as a broker source (`alert.class`, `alert.measure`)

### Capabilities and the Tool Broker (designed, not built)
The Triage agent never knows which tools a customer has. The bank is split in three parts, plus intake:
- `bank/contract/`: the interface both sides share. Every question's ID and answer type (yes/no, count, number, value from a fixed list, time), the status values, the trust values and the message envelope (below). Nothing else.
- `bank/triage/`: what the Triage agent uses. Detections and their flows, questions (text, role inputs, ratings), context questions, parameters, guards, modes, reason codes.
- `bank/broker/`: what the Tool Broker uses. Capabilities and their implementations (`question_map.yaml`: which capability answers each question, and the broker-only inputs such as the context list it reads), sources and source authority, translations and their kinds, per-customer verifications, scope profiles, context lists and seeds, fallback rules.
- `bank/intake/`: what the normalizer and the Detection Engineer use. The rule map, the use-case catalog and the pilot list.

triage/ reads contract/ only, never broker/; broker/ implements contract/. `validate` enforces it with the triage-neutrality gate: no file in triage/ or contract/ may name a vendor, product or rule library, refer to the broker's internals (translations, rows, sources, recipes, context-list IDs) or hold a field name or query-language token; `derived_from` metadata is the only exception. Each question has exactly one capability on the broker side (`bank/broker/capabilities.yaml`, e.g. `list.lookup`, `entity.baseline`, `org.prevalence`, `change.window`, `file.signer`, `file.reputation`). The bank holds no tool names, no query language and no SIEM product terms.

Flow of one question:
1. The Triage agent sends the question to the Tool Broker: its question ID plus role inputs, with the windows and lookbacks taken from the parameter table (§13), in the message envelope below.
2. The Tool Broker maps the question to its capability and routes it to the domain specialist that owns the capability for this customer. Any of the customer's tools may be disconnected.
3. The specialist runs the customer's frozen recipe for that capability (§10).
4. It returns a measurement (a count, a match, a value) with evidence.
5. The Triage agent applies the threshold from the parameter table and gets yes, no or unknown.

Principle: the broker measures, the Triage agent judges. No threshold lives in a recipe. `docs/capability-spec.md` lists, for each capability, the measurement it returns and the Triage-side rule that turns it into an answer.

The normalized alert is a broker source (`source: alert`, no tool call). Questions about the alert itself (`alert.class`, which returns a value from a fixed list through a translation, and `alert.measure`, which returns a number) are answered by the Tool Broker through a recipe and return a typed answer like any other question. The Triage agent never sees field names. They do not count against the call budget, since no tool is called.

A SIEM's own MCP server (for example Splunk's), where present, is used to execute searches and list metadata. Its query generation is never trusted directly: any query it suggests is a draft that must pass the recipe tests (§10) before it is used.

Answer contract (`bank/contract/answer.yaml`): every broker answer returns the answer in contract terms (bool, count, number, a value from a fixed list, or a time), a `status` (answered | unknown | source_unavailable | sources_disagree) and a `trust` (checked | not_checked), plus opaque provenance the Triage agent logs and never interprets.
- The broker decides trust. checked: answered from the source set at onboarding through a translation verified for this customer, or standards-defined, or with no translation at all. not_checked: anything else (an unverified translation, a fallback source, a model-proposed translation). An ambiguous translation answers status unknown.
- **The Auto rule, in triage terms:** a not_checked answer may support a close in Shadow and Recommend, and the explanation marks it ("not_checked: <question>"); it never supports a close in Auto, where the close becomes a flag. In Auto the outcome is also never weaker than the same flow with every not_checked answer read as unknown: the Triage agent takes the stricter of the two (round 6, §5.1; `tools/equivalence.py` found 94 paths in 23 flows where the trust rule alone flagged and the unknown reading could escalate, mostly a not_checked baseline yes that stops a flow before its change-record step). The Triage agent never sees translations, rows, vendors or translation kinds. Each flow step on a non-bool question carries a rule (for example `gte: alert_history_min_count`, or the enum values that mean yes); the Triage agent applies it and gets yes, no or unknown. Status unknown is no_data; source_unavailable and sources_disagree never close.
- no_data: follow the step's `on_unknown`.
- unavailable (tool down, a missed deadline, or a deferred request past its maximum wait): `source_unavailable`, which never supports a close; the alert is flagged and the detection runs in Recommend until the capability is healthy again. It is never cached.
- no_capability: resolved per customer at onboarding. The question is disabled, its step follows `on_unknown` without a call, and it is listed in the coverage report.
- A yes that rests on seed data with `verified: false` taints the rest of the flow: that step and any later close reached through it become a flag until onboarding verifies the entry. The same holds for a value translation not yet approved (§10).
- Reputation and anomaly capabilities are escalate_only: a hit escalates or flags and never closes; a miss is never benign evidence.
- `change.window` answers yes only when an approved change covers the host and time and lists the alert's user (or one of their groups) as implementer; no when nothing covers it, or every covering change lists implementers without the user; unknown (no_data) when a covering change has no implementer data.
- `vuln.not_applicable` answers unknown when the signature maps to no CVE (most generic IDS and WAF rules), so it never closes them. The replay gate counts these unknowns.
- `alert.history` counts alerts that already fired inside the triage window and share a key (the fingerprint, or a source, destination, user or campaign key). It reads existing alerts only, never raw logs. A count at or above the per-customer threshold (default 3; proxy 10) is used as a guard that raises the outcome, typically a close to a flag: a burst is not noise.

Every question asked of the broker follows `docs/broker-questions.md`: a bank ID (C-xx or Q-xxxx), one entity, fingerprint or alert inside the caller's scope profile, one typed answer with a status and provenance, no threshold, read-only, a frozen recipe per source, and raw evidence kept as a link.

Under the `triage` profile the Tool Broker enforces: entities named in the alert only; fixed windows (the 24h look-back triage window for event lookups; baselines and prevalence use their declared lookbacks and return counts, not raw events); read-only; a per-call timeout (timeout = unavailable); at most 6 calls per alert, counted on the worst single path through the flow (Q0, the steps and the guards of the closing step).
- **The call budget counts calls to outside tools only:** the SIEM, the EDR, identity, email, threat intel, change and ticketing, the vulnerability scanner and SOAR (`scope.budget_counts_sources` in `bank/broker/capabilities.yaml`).
- Lookups in our own cached context and list store do not count (`list.lookup`, the context questions), and neither do the normalized alert (`alert.class`, `alert.measure`), case memory (`precedent.check`), rules over cached context answers (`context.rule`), or resolving a file's hash or signer inside a lookup.
- The flow limit is unchanged and still enforced by `validate`: at most 5 steps per flow in total, with Q0 counting as step 1.

### Parallel runs and asynchronous answers (designed, not built)
Many alerts are triaged in parallel and the broker answers asynchronously, so every message is tied to a unique run. The schema is `bank/contract/envelope.yaml`; `validate` checks that it requires these fields and runs the worked messages in `bank/contract/envelope_examples.yaml` through the acceptance rules.

IDs:
- `alert_id`: the SIEM plus the source alert ID. The same alert arriving twice is deduplicated, not triaged twice.
- `run_id`: unique per triage run of one alert (UUID). A re-triage gets a new run_id linked to the same alert_id.
- `entity_window_id`: one per entity grouping window (§6). The context questions for that window carry it.
- `request_id`: unique per question sent: run_id (or entity_window_id) + step + question ID + attempt. The attempt grows only when the Triage agent deliberately asks again (a new request, for example after source_unavailable); a transport retry reuses the request_id unchanged.
- `measurement_id`: one per broker measurement. A cached answer reused by several runs keeps its measurement_id, and each answer records which measurement it came from.

Message envelope:
- Every broker request carries request_id, run_id or entity_window_id, question ID, scope profile and deadline.
- Every answer echoes request_id and run_id (or entity_window_id), plus measurement_id, answer, status, trust and provenance.

Rules:
- The Triage agent accepts an answer only if it matches a pending request_id for that run. Mismatches are rejected and logged.
- Each question has a deadline (`question_timeout_seconds`, a bounded parameter; a longer deadline reduces scrutiny). No answer by the deadline gives `source_unavailable`, which never supports a close: the alert flags (round 6, B4).
- Overload or rate limiting: the broker's router returns `defer` (reason overload or rate_limited) instead of an answer. The request waits, served in priority order when capacity returns, and is never answered unknown. The wait is bounded by `defer_max_wait_seconds` from the first defer (a second defer never extends it); past it the status is `source_unavailable`.
- A late answer is logged and discarded, never applied.
- A transport retry reuses the request_id. The broker returns the same completed measurement (answered, unknown or sources_disagree) for a repeated request_id and never measures twice. `source_unavailable` is never cached, so a retry after it measures again under a new measurement_id. The attempt number grows only when the Triage agent deliberately asks the question again.
- `validate` runs the worked sequences (deadline missed, deferred and answered, deferred past the maximum) and retries (cached measurement, re-measure after source_unavailable, a cached source_unavailable rejected) in `bank/contract/envelope_examples.yaml`.
- The decision log (§22) is keyed by run_id and lists every request_id and measurement_id. The SIEM write-back (§20) carries run_id.
- Context answers are shared through entity_window_id. Each run records which context measurements it used.

### Shared verification per product version (designed, not built)
A translation row can be checked without each customer repeating the full verification. A shared verification for one product and version (`bank/broker/verifications/shared/<product>/<version>.yaml`: the vendor doc, an in-depth check and the rows it covers) makes a row checked for a customer only when that customer also has a sanity sample of at least `verification_shared_sanity_alerts` (default 20) real alerts on the same version. A different version, a sample on another version or a row the shared record does not cover is not_checked. Schema: `bank/contract/verification.yaml`.

### Sources (designed, not built)
- Any capability may be answered from the SIEM, from the EDR's or another tool's API directly, or through a SOAR action.
- **Translations and trust (broker side).** Each translation row (`bank/broker/translations/`) has a kind: ambiguous (the value does not say what happened: status unknown in every mode), unverified (from vendor docs: not_checked until verified for the customer), proposed (model-proposed in build mode: not_checked; it must be checked and frozen before it is relied on), or standards-defined (for example HTTP status codes, citing RFC 9110: checked once in the shared broker layer, with no per-customer spot check; which field the product logs stays a recipe known-answer test). A row verified for the customer answers checked. A fallback-source answer is always not_checked, unless its row is ambiguous (then unknown). Verification is per customer (`bank/broker/customers/<c>/verifications.yaml`): a cited vendor doc, a Product Operator spot check of at least 20 real alerts (`verification_min_spot_check_alerts`, bounded), checker, date, product version and expiry; a product version change re-opens it. Details: `docs/broker-questions.md`.
- **Email quarantine.** An email or DLP "quarantined" supports a close only when it happened before the user received the item (`email.delivery_stage: pre_delivery`). After delivery (for example a purge of a delivered message), or with no delivery stage, it is ambiguous. The translation is limited to the email and DLP questions (Q-0074, Q-0062); an endpoint question can never use it, and `validate` enforces that.
- **Source authority.** The SIEM alert only starts triage. For each capability the broker answers from the authoritative source set at onboarding, usually the tool's own API. The SIEM is authoritative only for alert history and log searches (`alert.history`, `entity.baseline`, `org.prevalence`, `traffic.denied_only` and the other event-search capabilities; `source_authority` in `bank/broker/capabilities.yaml`). A fallback source is used only when the authoritative one is unavailable or not granted, and its unverified answers can only raise scrutiny. `validate` rejects a capability whose authoritative source is the SIEM outside that list.
- Each capability has one authoritative source per customer, set at onboarding, and a fallback order. If two sources disagree, the answer is unknown and the alert flags; disagreement is never resolved by picking one.
- Endpoint run status (Q-0049, `endpoint.run_status`): the authoritative source is the endpoint product's API (for Defender, the alert evidence in its security API). The broker finds the product's alert by the vendor alert ID the normalizer filled (`reporting_control.vendor_alert_id`); if that is missing, by device (`reporting_control.endpoint_device`), file hash and a bounded window ending at the alert time (`edr_alert_match_window_minutes`, a broker parameter since round 6). No match, or several, answers unknown. Inside the vendor's alert the broker reads the evidence item for the alerted file, picked by SHA-256, never the first item; for Defender, `detectionStatus` comes from the file, process and registry evidence subtypes and `remediationStatus` from the base evidence type (round 6, S7; known-answer tests in the translation, run by `validate`; #20). The run-status translation belongs to the API recipe. The SIEM's copy of the product's alert (for Defender, event log 1116/1117) is a fallback only, used when the API is unavailable or not granted; its answers are always not_checked: "ran" escalates; pre_execution may support a close in Shadow or Recommend (marked) but never in Auto; event 1117 "Block" and a quarantine alone are ambiguous and answer unknown in every mode. The same holds for CrowdStrike and every other endpoint product: the vendor API is authoritative, the SIEM copy is a fallback, and the rows are unverified until the lab tests (#20 for Defender, #9 for CrowdStrike).
- SOAR is read-only. The broker may call only actions on an approved read-only list (lookups, enrichments); any other action is refused and logged. Containment and enforcement actions are never called by the broker.
- Tool API limits are respected: per-entity caching (the measurement cache, §21), batching, and a concurrency cap per source (parameter).
- Recipes and their known-answer tests exist per source (§10). Attacker-influence ratings are per source profile and still apply (§14): the same capability may rate lower from a direct API than from a forwarded copy in the SIEM.
- The endpoint specialist covers Defender, CrowdStrike, Kaspersky and other EDRs, through the MCP gateway or read-only SOAR actions.

Context-store write-back goes only through `list.propose_update`. Reduce-scrutiny changes (allowlist additions) need human approval with an owner and an expiry. Increase-scrutiny changes (watchlists, removing an allowlist entry) may be automatic; removing an allowlist entry must notify the fact's owner. Enforcement blocks need approval.

Vendor-specific content (query languages, SIEM product terms, CIM, ECS and vendor field names, vendor API calls) lives only in adapter folders, broker recipes and translations. Core, triage logic, questions, flows, capabilities and parameters never contain it. `validate` enforces this twice: the vendor-leak gate scans questions, context questions, detections' flows and required roles, capabilities, parameters and context rules for query-language tokens, SIEM product terms and schema field names; the triage-neutrality gate scans every file in `bank/triage/` and `bank/contract/` (comments included) for vendor, product and rule-library names, references to the broker's internals, field names and query-language tokens, with `derived_from` as the only exception. Both allow vendor content in broker translations, adapters and intake (the rule map, the use-case catalog).

Vendor neutrality: the bank holds no vendor or product names. Only offline metadata (`data_source`, `sigma_logsource`, `sigma_refs`, `source`, `license`) may name them, plus seed data under `bank/broker/seeds/`, which is loaded into the customer's context store at onboarding and never reaches the agent. Question text describes what to check about an entity, never where or with which tool. The Triage agent receives a triage bundle (contract/ and triage/ only) and the Tool Broker a broker bundle (contract/ plus broker/ without translations or seeds), both from `tools/export_bundle.py` and both built without the offline metadata; the validator fails if a bundle contains an offline key or a vendor name, or if the triage bundle carries anything the broker implements. Recipe templates and translations (§10) may name tools; they ship separately with the broker's recipes.

Translations (`docs/normalization.md`) give each row a kind; verified is per customer. A detection is Auto-eligible for a customer only when every translation row its close paths rest on is verified for that customer (or standards-defined), as recorded by the onboarding check "Check vendor alerts are normalized" in the customer layer; `validate` enforces it for every customer that sets a detection to Auto (`bank/triage/customers/<c>/modes.yaml`). Fallback-source translations do not count against Auto eligibility: their answers are always not_checked at runtime, so in Auto they flag rather than close and can never be what an Auto close rests on; counting them would make every detection with a fallback permanently ineligible without making any close safer.

Allowlist and "known tool" lookups match on file hash, or code-signing signer plus path, never on name or path alone. Names and paths are attacker-controlled. Where the alert lacks hash or signer, fetch them from the same process's creation event by process GUID; if still unavailable, the answer is unknown.

## 10. Recipes (designed, not built)
A recipe is how one capability is measured on one customer's tools. It has two layers.

Template: the generic way to measure a capability on a type of tool. Templates ship in the bank as YAML and are reviewed like questions.
- Event searches are Sigma rules, compiled by pySigma to the SIEM's query language (SPL, KQL, ES|QL or EQL, AQL, and so on) with a per-customer pipeline (index or table, source type, field names). Backend maturity varies by SIEM; which backends are solid is an open assumption (`docs/assumptions.md`). A SIEM without a solid backend gets hand-written, tested templates.
- Lookups and API calls (lists, threat intel, change records, alert history) are small typed templates with the same lifecycle.

Customer recipe: the template bound to one customer. It holds the pipeline, the compiled query (a frozen copy), the translations, known-answer tests, status and version. Recipes are stored in the customer's database on premises and looked up by exact key (capability + customer + tool). There is no vector store at runtime; vector search may help a specialist find the closest template while building.

Lifecycle:
1. Build mode (agentic). At onboarding the specialist binds the template, compiles it and runs known-answer tests. A known value must return the expected result, and the data source must show recent events, so an empty result is never mistaken for "no". Status: shadow.
2. Shadow. Queries may change freely; humans review every answer.
3. Promotion freezes the recipes the detection uses. Runtime runs only frozen recipes.
4. Known-answer tests run daily. On a failure, the Use Case Manager has the specialist repair the recipe, and that capability returns to Shadow.
5. Live fallback. With no recipe, or a broken one, the specialist may answer agentically, but that answer can only raise scrutiny (flag or escalate). It never supports a close.
6. Runtime values (hash, host, user) are inserted escaped, as parameters, never concatenated into query text.

Translations: the broker may use a model to propose a translation of a raw vendor value (for example an antivirus action string) into the fixed short list only in build mode. A proposal (`kind: proposed`) must be checked and frozen before use; at runtime an unchecked proposal answers not_checked, and a model never translates live. Checking a proposal goes to the Use Case Manager for approval; a checked proposal becomes an unverified row until the customer verifies it.

## 11. Phase 0: foundation readiness (designed, not built)
A hard gate before triage starts, and before Shadow in onboarding. Triage on a broken foundation produces confident wrong answers, so the foundation is checked first. The checks are run by the SIEM specialist inside the Tool Broker, read-only, under the `detection_engineering` scope profile (rule-wide and historical, §4).

Per SIEM:
- Splunk (version 1): CIM compliance per rule; CIM data models enabled and accelerated, with acceleration completeness; Enterprise Security asset and identity lookups populated
- Microsoft Sentinel: entity mappings on the analytics rules; asset watchlists
- Elastic: ECS compliance; asset data
- QRadar: the asset database; the network hierarchy
- FortiSIEM and CrowdStrike Next-Gen SIEM: checklists written when the first customer on them is scoped (designed, not built)

Common to every SIEM:
- alert volume per rule, with historical dispositions (feeds the addressable-volume report, §12)
- search or query concurrency headroom (feeds the throughput limits, §21)
- EDR agent coverage across hosts
- entity resolution quality: the share of alerts mapped to an asset ID and to an identity (§6)
- read-only API access to each EDR granted (yes/no), with the API's rate limits. Without it, the detections that need endpoint answers (for example the AV/EDR family's run status) are capped at Recommend: the SIEM copy is a fallback that can only raise
- field coverage per capability (for example, the share of process events that carry a hash), ingestion delay and time sync
- whether risk-based alerting is in use
- asset-ID availability in AV and EDR alerts (without it, AV precedents rate medium)

Minimum bar (parameters):
- at least 90% of alerts resolve their host to an asset with a priority
- crown jewels and privileged users are listed
- the pilot detections populate their required entities (otherwise they flag `entity_missing`, §4)

Below the bar: no triage, or Shadow only. Asset and identity data incomplete: capped at Recommend.

The output is a data health report plus a fix list. Remediation is a Reno professional services step before the pilot. The data health report also decides which capabilities can be built at all and feeds the coverage report. The full checklist is at the end of `docs/capability-spec.md`.

## 12. Addressable volume (designed, not built)
At onboarding, from the customer's 6–12 months of alert history, compute per rule:
- its share of total alert volume
- its historical share closed as false positive or benign. This is the ceiling the system can ever reach on that rule: the flows can only close what analysts would have closed.
- its bank coverage: rule-level, technique-only or none

Addressable volume = the sum, over covered rules, of volume share × ceiling. It is an upper bound: it assumes past benign dispositions were right. The report lists, per rule, the share of blank or unclear dispositions, and the Shadow close rate on live alerts confirms the number before it is used in any sales claim. It is the only number used in sales claims. It also orders the customer's onboarding and decides what to build next. The value metrics are analyst hours saved and entities to review per day, not the auto-close percentage alone.

## 13. Thresholds and parameters (designed, not built)
- Thresholds live on the Triage agent side, in parameters. Precedence: customer + detection > customer default > detection default > global default (`bank/triage/parameters.yaml`).
- Every parameter has a default, bounds and the direction that reduces scrutiny in `bank/triage/parameters.yaml`; validation rejects values outside the bounds, and any customer override in the reduce-scrutiny direction without approver, owner and expiry. Detections set detection-level defaults under `parameters:` (for example `precedent_validity_hours`).
- A change that adds scrutiny may apply directly. A change that removes scrutiny needs human approval, with an owner and an expiry.
- Time windows and lookbacks travel with the request to the Tool Broker, but their values come from the same parameter table.
- Measurements are stored. In Shadow, the Use Case Manager replays stored measurements against candidate thresholds and proposes changes with that evidence.
- The promotion gate (the audited false-close rate, §19) belongs to the mode controller, not to flows.
- No model-generated confidence scores. "High confidence" means every answer on the close path came from a frozen recipe with a low attacker-influence rating.

## 14. Bank structure
- Layout: `bank/contract/` (question IDs, answer types, status, trust, envelope), `bank/triage/` (detections by family, questions, context questions, parameters, semantics, reason codes, customer modes), `bank/broker/` (capabilities, question map, translations, verifications, context lists, seeds, broker parameters), `bank/intake/` (rule map, use cases, pilot). See §9.
- One executor: `engine/executor.py` is the only code that walks a flow; the replay gate, the validator and every other gate import it. It talks to the Tool Broker only through the contract envelope (an injected answerer; the clean-room one is `tests/replay/clean_room.py`), takes the current time as a required input, names no detection or context question (the crown-jewel and entity-class rules are declared in `bank/triage/context_rules.yaml`), and is held to the triage-neutrality gate. Test data lives outside code: when each source rule fires (`tests/replay/fires_on/`), which detections are replayable (`tests/replay/coverage.yaml`), pinned sources (`tests/replay/sources.lock`), and the regression cases (`tests/cases/`). A bank PR may add tests and raise expected outcomes, never lower them or change the engine, contract or gates (`tools/check_scope.sh`).
- Two levels: detection flows with neutral IDs (D-0001…) grouped by family (endpoint, identity, endpoint_malware, network, email, data_protection), each mapped from its source rules (ESCU, Sigma, Elastic; Sentinel from batch 2; product alerts) in `bank/intake/rule-map.yaml`, and technique-level fallback flows per ATT&CK technique (family technique_fallback). The gates' batches are these families.
- Field names: a detection declares `required_roles`, the canonical roles of the normalized alert it needs (§4, `docs/intake/normalized-alert-v1.md`), never a SIEM's field names. Questions refer to roles (`role:host.asset_id`, `role:process.command_line`), never to fields; `validate` rejects CIM, ECS, Sysmon and vendor field names in detections and questions. Vendor value patterns and lists (antivirus classes, action values) live in the broker's per-vendor translations under `bank/broker/translations/`, each row with a kind; the Triage agent sees only the answer and its trust.
- Technique-only rules and technique fallbacks are capped at Recommend mode: they have no true-positive replay data. `validate` enforces the cap, in the bank and in every customer's modes.
- Auto exclusions (`bank/triage/auto_exclusions.yaml`, round 6, S5, S8, §5.2). A detection or one close step can be kept out of Auto with a code; the Auto-eligible count excludes it, and in Shadow and Recommend the close stands, marked. Detection level (`max_mode: recommend` + `auto_excluded_reason`): `destructive_or_anti_forensic` (D-0001 antivirus exclusion, D-0004 shadow-copy deletion, D-0016 event-log clearing; every detection on T1490, T1685 or T1685.005, enforced by `validate`; D-0016 also has Q0 off) and `no_tp_replay_data` (every family without true-positive replay data: email D-0031, D-0032; data_protection D-0033 to D-0035; network D-0029, D-0030; every technique fallback). The replay gate fails a detection it cannot replay unless it carries `no_tp_replay_data`, and a family run on zero events passes only when every detection in it is so capped. Step level: `attacker_reachable_sender` (D-0032 step 3, the approved-sender close) and `lateral_movement_change` (none left: S6 turned those closes into flags).
- No questions (usually a custom rule): no verdict; the agent sends a context pack, the analyst triages, the Use Case Manager drafts questions from the analyst's reasoning for human approval, and the rule starts in Shadow.
- Flows: at most 5 steps per flow in total, Q0 counting as step 1; early exit; each step has on_yes / on_no / on_unknown → next | close:<disposition>:<reason_code> | escalate | flag.
- Guards: a step may carry guards, extra checks that run when the step reaches a close or, where a guard says so, a flag outcome. Each names a question, the answers that trigger it and the result (flag or escalate); an unknown guard answer raises to at least flag. Guards only raise: a close becomes a flag or an escalation, a flag becomes an escalation, never the reverse, and no guard attaches to an escalate outcome. All applicable guards run and the strongest result wins (escalate > flag), whatever their order. A guard may apply only to some matched list entry types (for example analysis hosts versus approved tools). A guard that fires on no means a close needs a yes from it. Guards never create a close, and their calls count against the call budget on their path.
- Attacker influence: none, low, medium (control-recorded but forgeable in transit, such as alerts forwarded over syslog), high. Every close path must rest on a yes rated none or low. A question may rate itself per source profile (direct API or forwarded); the profile is recorded per vendor family at onboarding, and a close left without a none/low yes under the customer's profile flags.
  - Rating rules (enforced by `validate` and the close-path gate): a question cannot be rated lower than its capability's rating in `docs/capability-spec.md` (`rating_floor` in `bank/broker/capabilities.yaml`) without a written reason (`below_floor_reason`). Baselines default to high. `change.window` is low, and only for approved changes whose approver is not the implementer. An answer about who performed the action (`actor_identity`: group membership, an actor account on a list, a change implementer) is never the only hard-to-fake yes on a close path (round 6, S6); `validate` requires the tag on every list or change question about an actor or implementer, and the close-path gate enforces it.
- Q0 precedent check first in every flow, answered from the context questions (`bank/triage/context_rules.yaml`): the fingerprint (rule + entity + key attributes) has a close that passed audit, or (in Shadow and Recommend only) at least 2 independent human closes (C-04), inside the validity window (default 24h, maximum 72h, a bounded parameter); only human evidence counts (below); no other alert on the entity has a higher normalized severity than this one (C-03); at most one distinct detection fired on the entity in the grouping window (C-02, round 6, S2); the precedent entity is not a crown jewel (C-06) → close citing the precedent. In Shadow and Recommend the precedent is shown to the analyst instead. In Auto a precedent needs at least one audited close.
- **Human evidence** (`bank/contract/evidence.yaml`, round 6, B3): a manual close in Shadow, an analyst override, or an audited close. An accepted recommendation, an Auto close and a precedent match never count. Every count of closes uses this one definition, and declares it: C-04 and Q0, case memory, routine-pair proposals, list-entry proposals, closure mining and threshold proposals (`bank/triage/proposals.yaml`); `validate` rejects any count that does not. The replay gate checks that two accepted recommendations make no precedent.
  - Each detection names its precedent entity and rates each fingerprint field's attacker influence. Q0's rating is the least attacker-chosen field's. If every field is attacker-chosen (sender, subject, message id), the precedent never closes or flags by itself: the flow proceeds and the match is shown as context. If the best field is medium (spoofable source addresses), the close also needs a low-rated yes from a guard, such as "every connection was denied".
  - A precedent closed as mitigated true positive is inherited only when the current alert was also blocked.
  - Three or more earlier alerts with the same fingerprint in the triage window turn the precedent close into a flag.
- Two layers: public base bank plus a customer layer (runbooks, mined closures) that overrides base entries by ID. Mined closures are evidence, not truth, and go through curation.

## 15. Repeat alerts (designed, not built)
An alert matching an open case's fingerprint is attached to it without new triage. An attached alert triggers re-triage when the case's count spikes or the alert brings a new attribute value. A rule firing hundreds of times on one entity becomes a tuning ticket (throttling or risk-based alerting).

## 16. Storage
- Question bank: YAML in git, loaded into SQL tables. Exact, repeatable, auditable, reviewed through PRs.
- Custom-rule matching: pgvector in the same Postgres, offline only.
- Customer recipes, translations, stored measurements and decision logs: the customer's database on premises, keyed exactly (capability + customer + tool) (designed, not built).
- Investigation (later phase): graph database. The YAML already has typed nodes, typed edges and stable IDs, so it loads into a graph DB unchanged.
- Runtime is a loop: load the detection's steps, answer each with one measurement and its threshold, follow yes/no/unknown, stop at the first close or escalate.

## 17. Detection Engineer (custom rules) (designed, not built)
Runs once per rule, at onboarding and on rule change, never per alert.

Inputs:
- the rule's query (SPL, KQL, EQL or ES|QL, AQL, and so on)
- the results of running it, read-only, over the last 30 days with a row cap (parameter), plus field coverage. The Detection Engineer asks the Tool Broker for these under the `detection_engineering` profile; it never runs searches or writes queries itself.
- a sample of its alerts

A rule that never fired uses the query only.

Steps:
1. Parse the query. The intent comes mainly from the query logic: results show what fires, not what the author intended.
2. The local per-rule model (§18) writes the intent ("Detects <behavior> on <entity> from <data source>"), classifies the rule (threat, policy/compliance or operational noise) and proposes ATT&CK techniques. Only threat rules go to triage.
   - The results sharpen these.
   - The sampled alerts record which fields are actually populated. Step 5 uses this list, not fields guessed from the query.
3. Vector search, then the reranker (§28), returns the 3 closest known detections. A strong match is one where the techniques and the closest detections agree.
4. Strong match → inherit questions as drafts. Technique only → capped at Recommend. Neither → context pack. Every mapping starts in Shadow.
5. Drop inherited questions that need fields the alerts don't populate.

Also once per rule, for a rule from a public library: it compares the deployed query with the library's reference query and records the library context (description, techniques, data sources, known false positives). These replace the per-alert `rule_intent` and `escu_context` of the old context contract (§5).
6. The Use Case Manager asks the customer's rule owner to confirm in plain language, for example: "This rule detects X. In 30 days it fired 400 times, 92% from the patch servers. Is that what you intended?" The mapping is stored in SQL once confirmed. No vector search at runtime.
   - If the rule has no active owner (`identity.status`), the Use Case Manager asks the SOC lead instead.
   - If nobody confirms within 14 days (parameter `intent_confirm_days`), the mapping may run but is capped at Recommend. It can never reach Auto until someone confirms it.
   - The Use Case Manager re-asks monthly and lists unconfirmed mappings in its metrics.

Data and safety:
- Everything the Detection Engineer does runs on the customer's premises.
- Results and sampled alerts pass the injection classifier (§28) before the model reads them.

Boundary:
- The Detection Engineer is read-only and never changes a rule.
- Noise patterns it finds go to the Use Case Manager as a fact proposal or a tuning ticket (§15), and a human decides between them. A fact keeps the alerts visible and closes them. Tuning stops them firing, which blinds detection on those entities.

Safety net: a wrong intent leaves the rule in Shadow. Analysts disagree with its verdicts, so it never reaches the promotion threshold, and it never wrongly closes anything.

Later phase: the Detection Engineer gains rule changes (the detection engineering module, §29).

Each known detection carries `sigma_logsource` ({product, category} or {product, service}, from Sigma's own taxonomy) and `sigma_refs` (equivalent or closest SigmaHQ rules). These are offline metadata that let this service match custom rules to known detections across SIEMs; they are never used at runtime. The bank holds no OCSF. If a customer's data is in OCSF, the mapping lives in the Tool Broker's per-customer adapter.

## 18. Model roles (designed, not built)
Deployment principle: every model that touches customer data runs on the customer's premises. That covers the runtime models, the domain specialists, the Detection Engineer's model, the Use Case Manager, the injection classifier and the reranker. The only model outside the customer is the offline drafting model, and it sees public sources only.

Offline (Reno's build pipeline, public sources only):
- A frontier model drafts questions, explanations and facts from public sources.
- Gates (validate, the attacker-influence check, replay) and an external review check them.
- A human approves before anything leaves draft.
- This model never sees customer data.

Runtime decisions use no language model:
- Question selection is a bank lookup: detection ID (or the approved custom-rule mapping, §17) → flow.
- Each answer comes from one capability measurement through the Tool Broker, run by a frozen recipe (§9, §10), with the threshold applied by the Triage agent (§13).
- The verdict is where the flow stops.

Local model roles (on the customer's premises):
- The bank and the flows don't depend on which model fills a role. Each deployment picks a model per role from an evaluation harness run on our test sets, within the customer's hardware. Check each model's license before use.
- Per-alert roles need speed, so they use a small model. Candidates: Cisco Foundation-sec-8B (an instruction-tuned variant), gpt-oss-20b, a small Gemma.
- Per-rule roles run once per rule and need reasoning, so they use the largest model the hardware fits. Candidates: gpt-oss-120b, a larger Gemma.
- No model has tool access in any runtime role, and no model calls a tool directly (§4). The domain specialists' build mode and live fallback, inside the Tool Broker, are the only agentic tool use, read-only through the MCP gateway, and neither can support a close.

Roles:
1. Explanation writer (per alert): turns the answered checks into the analyst-facing explanation. It cannot change the verdict, the priority or the mode.
2. Close reviewer (per alert, raise-only):
   - It reads every alert the flow would close, with its answers and their provenance (raw evidence stays a link, `docs/broker-questions.md`), and returns keep, or flag with a one-line reason.
   - It can turn a close into a flag. It can never turn a flag or an escalation into a close.
   - If it is wrong, the worst case is that an analyst reviews one extra alert. It can never cause a missed attack.
   - In Shadow, measure how often it flags and how often analysts agree its flags were worth a look. Below a per-customer threshold (parameter `model_review_min_precision`, draft default 0.3), it is switched off for that detection.
   - Its calls do not count against the 6-call Tool Broker budget.
3. Detection Engineer (per rule, §17).
4. Use Case Manager drafting (§27): proposal and runbook text.
5. Domain specialists (§7, §10):
   - Build mode (per customer, at onboarding and in Shadow): the largest local model the hardware fits binds templates, compiles and tests recipes.
   - Run mode (per question): no model. A frozen recipe runs.
   - Live fallback (no recipe or a broken one): a local model answers agentically; the answer is raise-only.
   - Value translation (first sighting of a raw vendor value): a small local model may propose one, in build mode only; it is checked and frozen before use, and at runtime an unchecked proposal answers not_checked. A model never translates live.
6. Investigation (later phase).

Audit sampling, for the 5–10% audit of automatic closes (§19):
- Half the sample is the closes the close reviewer ranks oddest.
- The other half is random, so the audit is not blind to what the model misses.
- Humans do every audit.

Proposals for new questions, facts or exceptions come only from the Use Case Manager (§27), never from a per-alert role.

Supporting models: the injection classifier and the reranker (§28), on the customer's premises.

## 19. Modes and guardrails (designed, not built)
Per detection: Shadow (verdict hidden) → Recommend (analyst accepts or overrides) → Auto (close benign, escalate suspicious). Auto mode requires process telemetry with hashes (Sysmon or EDR); customers on Security 4688 only stay in Recommend. Every mode above Shadow requires the Phase 0 bar (§11); incomplete asset and identity data caps a customer at Recommend. Permanent: no auto-close on crown jewels (in every mode, any close on a crown-jewel entity becomes a flag; this is how the AV review's "crown-jewel host → flag" is met for every detection); audit 5–10% of auto-closures; escalation is never suppressed.

### Promotion gate: the audited false-close rate
- The gate is the audited false-close rate. A senior reviewer (the Reno Product Operator, then the subscription auditor after handover, §8) checks a sample of the detection's closes, with the Falsifier's findings (§7) attached.
- Sample: stratified by detection; at least 200 closes for high-volume detections, and every close for low-volume ones.
- Zero confirmed false closes are required to promote.
- The arithmetic: if a detection's true false-close rate were p, the chance of seeing no false close in 200 independent closes is (1 − p)^200. Setting that to 5% gives p ≈ 3/200 = 1.5% (the rule of three). So zero misses in 200 means the true miss rate is below about 1.5%, with 95% confidence. A smaller sample proves less: zero in 50 only bounds it below about 6%.
- Outcome checks (below) also count against the gate: a confirmed miss found there counts exactly like one found in the sample.
- Agreement with analysts stays a diagnostic only, reported per detection, never the gate. Analysts close the same easy alerts the flow does; agreement cannot show the closes that both got wrong.
- The customer's named owner co-signs every promotion to Auto (§8).

### Outcome checks
When an incident is confirmed, every close on the same entities in the previous 30 days (parameter) is re-checked. Each miss counts against the gate of the detection that closed it, and opens a review of that flow.

### Proof status for close paths
- **Path ID.** Every close path has an ID made of the detection, its version and every step answer on the path (`D-0006@v10:1:Q-0000=no > 2:Q-0001=yes`; guards are not part of it). Changing a detection's version or steps changes its path IDs, so an old proof no longer matches.
- **Proven** (`bank/contract/proof.yaml`) needs all three:
  - a reviewed record in `bank/triage/proofs/` lists the path's current ID, with a reviewer and a review date;
  - true-positive replay for the detection has at least `proof_min_tp_events` events, none of them closed on this path;
  - every aimed case the record lists passes.
- A draft never counts. Only a human marks a record reviewed.
- **In Auto** a close on an unproven path becomes a flag (`blocked_by: unproven_path`). In Shadow and Recommend the close stays, and its explanation is marked `unproven path: <id>`.
- **Path groups.** One record covers the paths that share the same close step and the same set of yes answers. It names the cheapest attacker position that makes every yes true, the guard that catches that attacker, and the residual risk in one line.

### The proof bar: why 5 events, not 20
- `proof_min_tp_events` defaults to 5, bounded to 5–200 (higher raises scrutiny); `validate` rejects anything below 5.
- With zero closes, N attack events only bound a path's miss rate below about 3/N at 95% confidence (the rule of three, as in the promotion gate above): 20 events give about 15%, 5 give about 60%. Neither proves a path is safe.
- So the floor proves only that the detection has a real attack corpus.
- Path safety comes from three other things:
  - the reviewed attacker's-view record;
  - an aimed case per path group;
  - the audited false-close rate at the customer (the promotion gate).

### Aimed cases
- Every proof record lists at least one aimed case: a replay alert in `tests/cases/<D-ID>/aimed/`, built so that the attacker in the record's position satisfies exactly the group's yes answers. It may be synthetic.
- Aimed cases and records link both ways.
- The replay gate runs each aimed case in Shadow, Recommend and Auto. It must flag or escalate in every mode, never close.
- An aimed case that closes means the path has a real hole. The case is not changed; the bank is fixed, raise-only: a guard the attacker trips, a rating, or a close turned into a flag with a suggested disposition.
- The aimed case answers the guard question with the attacker's real value (a baseline count of 0, a dump-capable signer), never with unknown. An unknown flags by itself and would prove nothing.
- Round 9 reviewed the 207 paths that passed every rule except proof (70 groups):
  - 35 groups (59 paths) still close, each with a draft record and a passing aimed case. Run on the bank before round 9, 33 of those aimed cases closed; the other 2 were already caught by an existing guard.
  - 41 groups had no question that catches the cheapest attacker. They became flags with a suggested disposition, or Q0 off for the detection, and are kept as `round9-hole-*` regression cases.

### Suggested disposition on flags
- When the executor turns a close into a flag, the decision record carries the close it would have been (`suggests`) and what blocked it (`blocked_by`: rule and one-line reason). The blockers are an unproven path, the trust rule, the entity guard, missing context, a guard, a source_unavailable or sources_disagree answer, or an Auto exclusion.
- A bank flag may declare one itself (`flag_suggests` on a flag edge): a real close disposition with its reason code (never a precedent), and a reason. Every flag created by the actor-identity rule carries one. Example: "probable approved change; who-did-it is the only hard-to-fake evidence; verify the implementer".
- Shadow hides the suggestion with the rest of the verdict (`suggestion_shown: false`). Escalations carry none.

### Human evidence for flags
- A close an analyst writes on a flag counts as human evidence only in two cases:
  - no suggestion was shown (`flag_own_close`, for example in Shadow);
  - the analyst chose a different disposition (`flag_override`).
- Accepting the suggestion (`flag_accepted_suggestion`) never counts, as accepted recommendations never count.
- Distinct analysts are counted per kind (`independent_kinds` in `bank/contract/evidence.yaml`).

## 20. SIEM integration (designed, not built)
- Each disposition is written back to the source alert through the Tool Broker's write recipe for that SIEM (§4): status, owner, comment, priority, ticket, and a link to the evidence. These are the broker's only SIEM write actions, on a fixed allowlist; any other write is refused and logged.
- Priority = the SIEM's own urgency or severity × asset priority, adjusted by the verdict and by the entity being hot (§6). For Splunk ES this is the notable's urgency. SLA clocks run per priority (parameters).
- Escalation target and ticketing are configured at onboarding. They use the customer's existing SIEM → ServiceNow or Jira integration, and escalate to a named IR queue.
- The analyst works in the SIEM's own alert screen (for Splunk, ES Incident Review or Mission Control; for Sentinel, Incidents; for Elastic, Alerts), grouped by entity, where our comment and evidence link appear on the alert.

## 21. Throughput (designed, not built)
- A measurement cache keyed by (capability, entity, window), with a time-to-live, shared across all alerts on the entity (§6) and filled first by the context questions (§5), asked in one batch per entity.
- Alert-history lookups batched.
- A concurrency cap per source (parameter): SIEM searches, EDR and other tool APIs, SOAR actions (§9).
- The backlog is processed in priority order.
- A load test on the customer's SIEM (and on each tool API at the expected alert rate) is an onboarding gate before Shadow.

## 22. Decision log and compliance (designed, not built)
- Per alert, the log holds:
  - the normalized alert's schema version and its inputs (§4)
  - the measurements, each with its source and source status (§5, §9)
  - the recipe, flow, parameter and model versions used
  - every answer and the verdict
  - the entity-guard state (hot or not, and why)
  - who or what made each change (agent, operator, approver)
- Retention is a per-regulator parameter.
- All service-account access is logged.
- Pattern: smartops-soc-app's telemetry run records, one append-only JSON line per step under the run (`engine/src/smartops/telemetry.py`, `record()`, on main at `a2d0eb0`). See `docs/reuse-map.md`.

## 23. Degraded mode (designed, not built)
Triggers:
- more than a threshold share of capabilities unavailable (parameter)
- failing recipe tests
- an approval backlog over its limit (parameter)

Response: the affected detections drop to Recommend (or to Shadow), and a daily report lists what is degraded and why. They return automatically once the cause clears and the recipe tests pass.

## 24. SOC manager metrics (designed, not built)
- addressable volume, and actual against it (§12)
- analyst hours saved
- entities to review per day
- share of entities hot per day (§6)
- time to triage
- auto-close rate
- split by disposition
- audited false-close rate
- backlog and SLA breaches
- approval queue age

## 25. HA, DR and backup (gap)
Case memory, recipes, translations, parameters and decision logs need backup and restore. High availability and disaster recovery are not designed yet; this is a known gap.

## 26. Sources and licenses
- splunk/security_content (ESCU), Apache-2.0: known_false_positives, ATT&CK mapping, data source
- elastic/detection-rules, Elastic License 2.0: "Triage and analysis", "False positive analysis"
- SigmaHQ/sigma, Detection Rule License (attribution): falsepositives
- LOLBAS, GTFOBins, LOLDrivers: legitimate uses of binaries and drivers
- Azure/Azure-Sentinel, MIT: primary source for the identity and cloud domain (Entra ID, M365, Azure). It has no false-positive field; benign hints live in query comments and descriptions. Its `entityMappings` are the model for which entities a detection's alert exposes.
- MITRE ATT&CK v20.0 (mitre-attack/attack-stix-data): techniques, detection strategies. v19 (April 2026) revoked T1562.001 → T1685 and T1070.001 → T1685.005; use current IDs.
- smartops-soc-app (Reno, internal): read-only from this repo. Code is reused by copying it with the source file and commit cited (`docs/reuse-map.md`), never by importing or editing that repo.

Record source and license on every question; non-Apache text needs legal review before commercial use.

## 27. Use Case Manager (designed, not built)
The Use Case Manager keeps the triage knowledge current: context facts, allowlists, exceptions, questions and runbooks. It runs continuously, so triage quality does not depend on people following documentation or on who is still on the team. The triage agent decides; the Use Case Manager keeps the knowledge it decides with up to date.

Duties:
1. Fact freshness: finds facts near expiry, or whose owner is disabled or has left (identity capabilities), and asks the right person to re-confirm. Expired facts stop being used.
2. Closure mining: turns recurring analyst closure reasons into proposals: a new exception, a new fact or a new benign question.
3. Cleanup: proposes removing allowlist and exception entries unused for 90 days (per-customer parameter).
4. New patterns: drafts a new question when a benign cause recurs and no question covers it.
5. Rule changes: new or edited detections are re-mapped by the Detection Engineer (§17) and start in Shadow; the Use Case Manager tracks each one until it is mapped, has questions and has a mode.
6. Runbook sync: generates human-readable runbooks from the bank, so the documentation always matches what the triage agent does.
7. Turnover resilience: all knowledge lives in the bank and the context store, with owner, reason, evidence and history, never only in people's heads.
8. Recipe repair: when a recipe's daily known-answer tests fail, it has the owning specialist repair the recipe, and that capability returns to Shadow (§10).
9. Threshold proposals: replays stored measurements against candidate thresholds in Shadow and proposes changes with that evidence (§13).
10. Value tables: approves or rejects each new raw-value translation (§10).

Guardrails:
- It proposes, and never decides, anything that reduces scrutiny: an allowlist entry, an exception, a trusted entity, or a question that adds a close path. Each needs human approval, an owner and an expiry, with a full audit trail.
- It may apply increase-scrutiny changes on its own (a watchlist entry, removing an expired entry), and must notify the fact's owner.
- Anti-poisoning: a reduce-scrutiny proposal needs evidence from at least 3 closures that are human evidence (`bank/contract/evidence.yaml`: manual closes in Shadow, analyst overrides, audited closes), by at least 2 different analysts, on at least 3 distinct days (bounded parameters `proposal_min_human_closes`, `proposal_min_analysts`, `proposal_min_days`; `bank/triage/proposals.yaml`). The triage agent's own closes, and analysts' accepted recommendations, never count as evidence, so the two agents cannot reinforce each other. A proposal driven by alerts from a single source, or by a burst inside one window, is rejected.
- It reads only through the Tool Broker, under its own read-only scope profile (§4), and writes only through the broker's `list.propose_update` and fact-update capabilities. It never touches customer tools directly.
- It runs on the same deployment as the triage agent, on the customer's premises.

Metrics: proposals made, accepted and rejected; unconfirmed rule mappings (§17); stale facts; average fact age; unused entries removed; time from a recurring pattern to an approved fact; runbook drift (should be zero).

Capabilities it needs (specification only; to be added to `bank/broker/capabilities.yaml` in a Use Case Manager group with `flow_use: forbidden`, so no triage flow can call them):
- `fact.metadata`: a fact's owner, expiry and last use.
- `list.usage`: hit counts and last hit per list entry.
- `identity.status`: whether an owner's account is active.
- `closure.history`: analyst closures with reason and analyst id.
- `rule.inventory`: enabled detections and their change dates.

## 28. Model guardrails (designed, not built)
The structure is the primary defence. No language model decides a verdict: verdicts come from yes/no capability lookups rated for attacker influence (§9, §14). The controls below are defence in depth on top of that structure, not a replacement for it.

### Prompt-injection classifier
It runs on every input a language model reads that contains alert or customer-sourced content:
- the explanation writer (§18; it never changes the verdict)
- the close reviewer (§18)
- the Use Case Manager's closure mining (§27)
- the domain specialists' build mode, live fallback and value translation (§10), on tool output
- the Detection Engineer's model (§17), on rule queries, rule descriptions, search results and past alerts
- the Falsifier (§7), on the alerts, logs and records it reads
- investigation (later phase)

On a hit, what happens depends on where the text came from. In every case the text never reaches the model, and the hit is logged with its score.
- In an alert (explanation writer, close reviewer, investigation), with reason code `injection_suspected`:
  - Shadow and Recommend: a hit flags.
  - Auto: a hit flags, deduplicated, with a per-source rate limit so a flood of crafted alerts cannot bury the queue. It escalates only with a second signal: another alert on the entity, or a reputation hit.
  - A hit is never benign evidence; it can never support a close.
- In the Detection Engineer (§17):
  - A hit in the rule query or the rule description stops the mapping, and the rule goes to a human.
  - A hit in a past alert or search result excludes that item from the model's inputs, and the item is opened as a review case for the SOC.
- In the Use Case Manager's closure mining (§27): the closure is not counted as evidence for any proposal, and the note goes to the SOC lead.

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

## 29. Later phases
Cross-customer analytics with anonymized counts only (question ID, outcome, sector). Tier-2 analyst agent (investigation) using an attack-path graph (e.g. MITRE Attack Flow) and a per-incident evidence graph.

Detection engineering module: the Detection Engineer gains rule changes. It tunes, fixes and writes the customer's detections from evidence it and the Use Case Manager gather. It needs change control and testing, and is out of scope until triage is proven.
