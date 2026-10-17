# What may be asked of the Tool Broker

Status: (designed, not built). The rules below are the contract the Tool Broker enforces. Today's bank does not meet all of them yet; the gaps are listed at the end and are tracked on the bank-migration issue (#12). Design reference: `docs/design-decisions.md` §4 (one way in, one way out; scope profiles), §5 (context questions), §9 (Tool Broker).

The Tool Broker is the only way out to any tool (§4). Everything an agent or model wants to know from a tool is a broker question, and every broker question follows these rules.

## Rules
Every broker question, context or triage, must:

1. **Have an ID in the bank**: `C-xx` for context questions, `Q-xxxx` for triage questions. No ad-hoc questions at runtime. A request the broker cannot match to a bank ID is refused and logged.
2. **Be about one entity, the alert's fingerprint, or the alert itself**, inside the caller's scope profile (`triage`, `falsifier`, `detection_engineering`, or the Use Case Manager's read-only profile; §4). A call outside the profile is refused and logged.
3. **Return exactly one answer type**: yes/no, count, number, a value from a fixed list, or a time. Plus:
   - `status`: `answered` | `unknown` | `source_unavailable` | `sources_disagree`
   - `provenance`: `source`, `observed_at`, `ttl`, `recipe_version`, `evidence_link`
4. **Carry no threshold.** The broker returns the count; the Triage agent applies the threshold parameter (§13). Yes/no only where the fact itself is yes/no (list membership, an open case). The bank question the flow asks stays yes/no: it is the typed answer after the Triage agent applies its parameter.
5. **Be read-only and answered by a frozen recipe per source** (§10). A live answer, where no frozen recipe exists, can only raise scrutiny.
6. **Keep raw evidence as a link** for the analyst and the decision log (§22). Raw text never reaches the Triage agent or a model through a triage or context question.

### Answer statuses

| Status | Meaning | Effect |
|---|---|---|
| `answered` | The authoritative source (or its fallback) answered. | The Triage agent applies the parameter. |
| `unknown` | The source answered but the fact is not determinable (no data, no implementer on the change, no CVE for the signature). | The step's `on_unknown`. |
| `source_unavailable` | Down, timed out, or failing its recipe tests. Never "no hit". | Never closes; the alert flags (§9). |
| `sources_disagree` | Two sources gave different answers. | Never closes; the alert flags (§9). |

## Source authority
The SIEM alert only starts triage. For each capability the broker answers from the authoritative source set at onboarding, usually the tool's own API. The SIEM is authoritative only for alert history and log searches. Each capability in `bank/capabilities.yaml` declares `source_authority: {authoritative, fallback}`; `validate` rejects a capability whose authoritative source is the SIEM outside alert history and log searches, and names the endpoint API when one exists.
- A fallback source is used only when the authoritative one is unavailable or not granted.
- **Raise-only answers.** An answer from a fallback source, or from an unverified value-table row, may only raise scrutiny. "Ran" or "malicious" stands. "pre_execution", "benign" or any other answer that could lead to a close becomes unknown. The rule holds per value-table row (`verified: false`) and per source (`fallback: true`, set on every SIEM-copy table), and `validate` enforces both: every alert class and enum declares its `raise_only` values (`bank/capabilities.yaml`), a raise-only value may never lead a step or a guard to a close, and a SIEM-copy table must carry `fallback: true`. A class default (no row matched) is the bank's own value and stands. Until onboarding verifies the rows, most vendor-family closes therefore flag.
- Endpoint answers come from the endpoint product's API. Example, Q-0049 (was the file stopped before it ran?) on Defender: the broker finds the Defender alert by the vendor alert ID the normalizer filled; if that is missing, by device, file hash and a bounded time window (`edr_alert_match_window_minutes`). No match or several matches answer unknown. The run-status value table belongs to the Defender API recipe. The SIEM's copy of the alert (for example event log 1117 "Block") is used only when the API is unavailable or not granted, and its pre_execution answers unknown (raise-only), verified or not; its "ran" stands. CrowdStrike and every other endpoint product work the same way (rows unverified; lab tests #20 and #9).
- Without read-only endpoint API access (a Phase 0 check), the detections that need endpoint answers are capped at Recommend.

## Classification: vendor meaning or customer policy
Two different things turn a raw value into an answer, and they live in different places:
- **What a vendor's value means** (Defender's `prevented` means the file did not run; event 1116 means detected) lives in value tables under `bank/recipes/value_tables/`, one per source and product, each row verified or not. Unverified rows cap the family at Recommend.
- **What the customer accepts** (which categories are low risk, which device classes are allowed, their address ranges) lives on the Triage side, in bounded parameters with a direction tag (`reduces_scrutiny_when`) or in the customer's context lists. A change that reduces scrutiny needs human approval.

`validate` rejects a customer-policy key (`param`, `cidr_param`, `policy`, and similar) inside a value table, and a vendor-meaning mapping (a dict default, `map`, `rows`, `match` or `pattern`) inside a parameter.

Statistic settings are not thresholds. `org.prevalence` returns the k-th lowest weekly distinct-host count over `of_weeks` weeks, with k = of_weeks − min_weeks + 1 (default 4 and 3, so k = 2). `of_weeks` and `min_weeks` are recipe statistic settings (`category: recipe_statistic`, bounded); the threshold `org_prevalence_min_hosts` stays with the Triage agent. "k-th lowest ≥ N" is exactly "at least min_weeks of the of_weeks weeks have ≥ N hosts" (`tools/test_prevalence.py` checks every case over 4 weeks, quiet weeks included, N 1–10).

## Missing context
If a context question (C-01…C-08) is unknown or its source is unavailable, the alert cannot close on anything that depends on it, and the outcome is a flag with reason `context_unknown`, naming the C-ID. Missing context never escalates by itself, and no unknown answer is replaced by a worst-case value. Each context question declares `on_unknown: flag` and `unknown_reason: context_unknown` (`bank/context/`); `validate` rejects a worst-case default (`unanswered_value`, "treated as") and a step or guard on which an unknown context answer escalates. Defaults per question: `docs/intake/context-questions.md`.

## How to sort a question

| Kind | Test | Examples |
|---|---|---|
| Context question | Nearly every detection needs it; it is about the entity, not the detection's logic; it can only raise scrutiny or set priority. Asked once per entity per window. | C-01 to C-08 (`docs/intake/context-questions.md`) |
| Triage question | Specific to a detection's flow; asked only when the flow reaches it; it may lead to a close. | "Is the parent binary a sanctioned deployment tool, by hash or signer plus path?" |
| Not a broker question | Free-form enrichment, threat-intel narratives, rule intent. | "Summarize what OpenCTI knows about this hash"; "What was this rule meant to detect?" |

The Detection Engineer's own reads (running a rule over 30 days, sampling its alerts, field coverage) are broker calls under the `detection_engineering` profile. They are per rule, never per alert, and they are not triage or context questions. The Falsifier's forward-looking and raw-log reads are broker calls under the `falsifier` profile. Under those two profiles results may include raw records; anything a model reads from them passes the injection classifier first (§28).

## The bank's questions sorted by capability
73 questions in `bank/questions/` today, by capability.

| Capability | Questions today | Kind | Reason |
|---|---|---|---|
| `alert.field` (now `alert.class` and `alert.measure`) | 20 | Triage | The normalized alert is a broker source (`source: alert`, no tool call). The broker answers through a recipe and a value table and returns a typed answer, so the Triage agent never sees field names. Detection-specific; can lead to a close. |
| `list.lookup` | 25 | Triage | Membership in a detection-specific list (sanctioned tools, approved scanners, exceptions) decides a close. The exception is crown-jewel and asset lists (`CF-0007`, `CF-0029`), which become context questions C-05 and C-06. |
| `entity.baseline` | 6 | Triage | "Has this entity done this before?" is about the detection's behavior and can lead to a close. |
| `org.prevalence` | 3 | Triage | Pattern-specific and can lead to a close. |
| `alert.history` | 3 | Context, with triage guards | The entity's alert count and distinct detections are C-02; fingerprint and source-key burst counts used as guards in specific flows stay triage. Either way it only raises. |
| `case.precedent` | 1 | Context | Q0's precedent check runs for every detection. C-04 supplies the audited and independent close counts; the Q0 step itself stays in each flow. |
| `file.signer` | 2 | Triage | Signer plus path is the basis of an allowlist close. |
| `file.hash` | 0 | Triage | Hash comparison for a close; also resolved inside `list.lookup`. |
| `change.window` | 2 | Triage | An approved change covering the host, time and implementer can lead to a close. |
| `identity.groups` | 1 | Triage, and context for C-07 | Detection-specific group membership is triage; "is the user privileged" is C-07. Never the only low-rated answer on a close path (§14). |
| `file.reputation` | 2 | Triage (escalate-only) | Asked only by the flows that need it; a hit raises, a miss is never benign evidence. |
| `ip.reputation` | 1 | Triage (escalate-only) | Same as `file.reputation`. |
| `url.reputation` | 1 | Triage (escalate-only) | Same as `file.reputation`. |
| `identity.risk` | 0 | Triage (escalate-only) | Anomaly signal; only raises. |
| `vuln.not_applicable` | 1 | Triage | Exploit flows only; can lead to a close. |
| `email.message_status` | 1 | Triage | Email flows only; can lead to a close. |
| `email.no_interaction` | 1 | Triage | Email flows only. |
| `email.auth` | 1 | Triage | Email flows only. |
| `traffic.denied_only` | 1 | Triage | Network flows only; can lead to a mitigated close. |
| `scan.job_active` | 1 | Triage | Scanner flows only. |
| `list.propose_update` | 0 (`flow_use: forbidden`) | Not a question | A write proposal to the context store, never asked in a flow. |
| (new) asset priority, crown jewel, open case | 0 | Context | C-05, C-06, C-01. Capabilities `asset.lookup` and `case.open` (designed, not built). |

## Where the bank used to break these rules
Fixed by the bank migration (PR "Bank migration: roles, typed answers, parameters, context questions", #12); `validate` now rejects each of these:
- **Thresholds in questions.** `alert.history` passes `min_count`, `org.prevalence` passes `min_hosts` (`min_weeks` and `of_weeks` are now recipe statistic settings, not thresholds: see Classification), and `entity.baseline` passes `min_days` to the broker (rule 4). They should ask for the count and apply the parameter on the Triage side.
- **Answer type.** `bank/capabilities.yaml` returns `answer: yes | no | unknown` from the broker. It should return the typed measurement with `status` and `provenance` (rule 3).
- **No context/triage tag**, and no C-xx questions.
- **No scope profiles.** `bank/capabilities.yaml` `scope` also says "±24h alert window"; the triage profile is look-back only (§3).
