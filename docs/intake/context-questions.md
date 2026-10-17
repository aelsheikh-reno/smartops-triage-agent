# Context questions

Status: in the bank as `bank/triage/context/C-01.yaml`…`C-08.yaml` and `bank/triage/context_rules.yaml` (draft), with their answer types in `bank/contract/questions.yaml` and the capability and context list that answer each one on the broker side (`bank/broker/question_map.yaml`); the runtime that asks them is (designed, not built). Design reference: `docs/design-decisions.md` §5. Rules every broker question follows: `docs/broker-questions.md`.

There is no separate context service. Context is a small fixed set of broker questions that the Triage agent asks once per entity per grouping window, at the "Group by entity" step (§6). The Tool Broker batches them, answers them from frozen recipes, and caches the answers per entity (§21). Every alert on the entity in the window reads the same cached answers.

Context questions feed the entity guard (§6), Q0 (§14) and priority (§20). They can only raise scrutiny or set priority. None of them closes an alert on its own.

## The set

| ID | Question | Answer type | Key | Capability | Feeds |
|---|---|---|---|---|---|
| C-01 | Is there an open escalation or case on the entity? | yes/no | entity | `case.open` | entity guard: hot if yes; repeat attach (§15) |
| C-02 | How many alerts fired on the entity in the window, and from how many distinct detections? | count, count | entity, window | `entity.alerts` | entity guard: N alerts from ≥2 detections; noisy-entity routine list applied by the Triage agent |
| C-03 | What is the highest severity of any other alert on the entity in the last 24h? | value from a fixed list: informational, low, medium, high, critical, none | entity, 24h | `entity.max_severity` | Q0: no alert of higher severity on the entity in the window. The Triage agent compares it with this alert's severity. |
| C-04 | How many audited closes, and how many independent analyst closes, does this fingerprint have in the validity window? | count, count | fingerprint | `case.precedent` | Q0: inherit only audited closes, or at least 2 independent analyst closes |
| C-05 | What is the asset's priority? | value from a fixed list: critical, high, medium, low | host asset ID | `asset.priority` | priority (§20) |
| C-06 | Is the asset a crown jewel? | yes/no | host asset ID | `asset.crown_jewel` (list CF-0007) | no auto-close on crown jewels (§19); Q0 |
| C-07 | Is the user privileged? | yes/no | user identity ID | `identity.privileged` (list CF-0002) | priority (§20) |
| C-08 | What class of asset is it? | value from a fixed list: server, workstation, network, other, unknown | host asset ID | `asset.class` | entity guard: N and window per class (§6); Q-0067 |
| C-09 | When did the alert happen, in the customer's business calendar? (designed, not built) | value from a fixed list: business_hours, after_hours, weekend, public_holiday, change_freeze | alert time (and the entity's site) | `calendar.business_time` (designed) | guards only (`guard_only`): an admin action after hours or in a change freeze flags |

C-03 deviates from a plain yes/no on purpose. "Higher than this alert" depends on the alert, so a yes/no could not be cached once per entity. The broker returns the highest severity, which is the same for every alert on the entity, and the Triage agent compares it with each alert's own severity. That comparison is not a threshold, so there is still no threshold in the recipe.

C-04 is keyed on the fingerprint (rule plus entity plus key attributes, §14), so it is cached per fingerprint rather than per entity.

## Answers
Context questions for one entity grouping window carry its `entity_window_id` (design-decisions §9, Parallel runs and asynchronous answers). Every alert run in the window reads the same cached answers, and each run records which context measurements (`measurement_id`) it used. Like every broker answer, a context answer carries a status and a trust (`bank/contract/answer.yaml`).

Each answer follows the broker answer contract in `docs/broker-questions.md`:
- `status`: `answered`, `unknown`, `source_unavailable` or `sources_disagree`
- `provenance`: source, `observed_at`, time-to-live, recipe version, evidence link

"Source down" never reads as "no hit". If C-01 or C-02 comes back `source_unavailable` or `sources_disagree`, the entity guard cannot rule the entity out, so every close on it flags. The rule for every context question: If a context question (C-01…C-08) is unknown or its source is unavailable, the alert cannot close on anything that depends on it, and the outcome is a flag with reason `context_unknown`, naming the C-ID. Missing context never escalates by itself, and no unknown answer is replaced by a worst-case value.

| Unknown or unavailable | What happens | Reason |
|---|---|---|
| C-01, C-02 | The entity cannot be ruled out: every close on it flags. | `context_unknown` (C-01 / C-02) |
| C-03, C-04 | Q0 cannot close; it answers unknown and the flow continues. Other closes do not depend on them. | recorded as `context_unknown` |
| C-05 | Priority stays at the SIEM's own urgency (not raised). Any close that depends on asset priority (Auto autonomy, §19) flags. | `context_unknown` (C-05) |
| C-06 | Every close flags: Q0 needs a known non-crown-jewel, and no auto-close on a crown jewel. Q-0067 flags. | `context_unknown` (C-06) |
| C-07 | Priority is not raised for the user. No close depends on it. | recorded as `context_unknown` |
| C-08 | Q-0067 flags. The entity guard uses the global defaults (3 alerts from 2 detections in 10 minutes). | `context_unknown` (C-08) |

Before round 3 these were worst-case defaults (treat as critical, as a crown jewel, as privileged, as a server). A worst-case default could escalate on missing data; now missing data flags and an analyst decides.

Q-0067 (removable media: is the host a server or crown jewel?) is not a broker call of its own: it is a Triage-side rule over the cached answers C-06 and C-08 (`bank/triage/context_rules.yaml` `q0067`, capability `context.rule`). It answers yes when C-06 is yes or C-08 is server, and its guard escalates. If the answer depends on an unknown C-06 or C-08, it answers unknown and the guard flags (`context_unknown`); a known crown jewel or a known server answers yes even when the other is unknown. Before this it was a list lookup.

## C-09: business time (designed, not built)

C-09 is guard-only (`bank/contract/questions.yaml`): only a guard may read it, never Q0, the entity guard, priority, `closes_need_known` or a flow step. The broker answers it from the customer's business calendar (`CF-0033`):
- working days per customer or site (Sunday to Thursday, or Monday to Friday);
- working hours, including reduced-hours periods such as Ramadan;
- public holidays;
- approved change-freeze periods.

Precedence: change_freeze, public_holiday, weekend, after_hours, else business_hours. Unknown (no calendar) flags with `context_unknown`. Business hours are never evidence that an action is benign.

It stays designed until the contract PR moves C-09 out of `designed:`. The first guard it gets is raise-only: on admin-activity flows, after_hours or change_freeze → flag.

## What is not a context question
Asked only when a flow step reaches it, as a triage question with its own bank ID: threat intel, baselines, prevalence, EDR detail (process tree, signer, hash).

Moved out of the per-alert path, from smartops-soc-app `context_service/templates/context_contract.py` (branch `feature/context-contract-template`, commit `40e399d`):

| Template key | Fate |
|---|---|
| `investigation_id`, `iteration` | Dropped. Context questions are asked once per entity per window, not in a loop. The decision log (§22) keys on the alert and entity. |
| `normalized_seed` | Replaced by the normalized alert (`docs/intake/normalized-alert-v1.md`), which comes in through the normalizer, the only way in (§4). |
| `rule_intent` (`intent`, `semantic_alignment`: deployed SPL compared with the reference SPL) | Moved to the Detection Engineer (§17), once per rule, through the broker under the `detection_engineering` profile. |
| `escu_context` (`description`, `mitre_techniques`, `data_sources`, `known_false_positives`, `analytic_story`) | Moved to the Detection Engineer, once per rule. Its content is already in the bank. |
| `opencti_threat_intelligence` (`indicators`, `malware`, `threat_actors`, `campaigns`, `relationships`) | Moved to the threat-intel specialist, on demand, as typed reputation answers (`file.reputation`, `ip.reputation`, `url.reputation`). Narratives are not broker answers. |

## Rules
- Scope: the `triage` profile: the alert's entities and fingerprint, 24h look-back only (§3, §4).
- Read-only, frozen recipe per source, no threshold in the recipe.
- Batched: all context questions for all entities in a grouping window go to each source in as few queries as the source allows, under its concurrency cap (§9, §21).
- Attacker-controlled values are bound as parameters, never concatenated (§10).
