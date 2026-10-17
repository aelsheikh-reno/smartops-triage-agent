# CLAUDE.md

This repo holds the SmartOps triage agent's design notes and question bank. The question bank is the current focus.

**Version 1 scope.** Version 1 builds and tests one SIEM adapter: Splunk ES. All lab tests and the first pilots run on Splunk. The design stays vendor-agnostic: nothing outside the Splunk adapter and Splunk recipes may depend on Splunk.

## Read first
- `docs/design-decisions.md`: settled design. Follow it; don't re-open decisions without being asked.
- `docs/build-question-bank-prompt.md`: the task brief for building the bank.

## Rules
- YAML under `bank/` is the source of truth. Everything else is generated from it.
- `bank/` has three parts plus intake: `contract/` (question IDs and answer types, status, trust, message envelope, the human-evidence definition and the normalized severity scale; nothing else), `triage/` (detections and flows, questions, context questions, parameters, guards, modes, reason codes), `broker/` (capabilities and their implementations, sources and source authority, translations and their kinds, verifications, scope profiles, fallback rules), `intake/` (the rule map, use cases, pilot). triage/ reads contract/ only, never broker/; broker/ implements contract/.
- The Triage agent sees only questions and answers with status and trust. Vendors, libraries and translations belong to the broker or to intake.
- Every broker request and answer carries request_id and run_id; unmatched or late answers are discarded. No answer by the deadline is source_unavailable, which never supports a close. Overload or rate limiting defers the request (served in priority order, bounded by defer_max_wait_seconds, then source_unavailable); it is never answered unknown. source_unavailable is never cached; only completed measurements are idempotent per request_id. The attempt number in request_id grows only on a deliberate re-ask.
- Every question has its ID and answer type in `bank/contract/questions.yaml`, is tagged `kind: context` or `kind: triage`, and is answered by exactly one capability on the broker side (`bank/broker/question_map.yaml`, `bank/broker/capabilities.yaml`). The broker returns a typed answer (bool, count, number, enum, time); each flow step on a non-bool question carries a rule that turns it into yes/no against a bounded parameter. No tool names or query language in the bank; the Tool Broker maps capabilities to the customer's tools.
- No schema field names in the bank (CIM, ECS, Sysmon or vendor; list in `tools/field_names.py`). Detections declare `required_roles`, and questions refer to roles (`role:host.asset_id`, `tools/roles.py`). Vendor value patterns and lists live in the broker's translations under `bank/broker/translations/`, each row with a kind (verified is per customer).
- No vendor, product or rule-library name and no reference to the broker's internals anywhere in `bank/triage/` or `bank/contract/` (lists in `tools/vendors.py`); `derived_from` metadata is the only exception. Operating-system concepts (Windows, LSASS, the registry, the event log, PowerShell) are allowed; company names, including the major platform vendors, are not (write "the operating-system vendor"). Detections have neutral IDs (D-0001…) grouped by family; source rule IDs live only in `bank/intake/rule-map.yaml`. Broker translations, seeds and intake may name vendors; none of them is in the triage bundle.
- Question text describes only what to check about an entity, never where or with which tool.
- The runtime bundles (`tools/export_bundle.py`: triage, broker) exclude offline metadata (`derived_from`, `data_source`, `sigma_logsource`, `sigma_refs`, `source`, `license`) and contain no vendor names; the triage bundle holds contract/ and triage/ only. `validate` enforces all three.
- Any allowlist or "known tool" question matches on file hash, or code-signing signer plus path. Never on name or path alone.
- Flows: at most 5 steps in total, Q0 counting as step 1; early exit, `on_yes` / `on_no` / `on_unknown` on every step.
- Every question records its source and license under `derived_from`. Flag text copied from non-Apache sources for legal review.
- New questions start as `status: draft`. Only a human marks them `approved`.
- The Use Case Manager proposes; a human approves anything that reduces scrutiny. The Triage agent's own closes, and analysts' accepted recommendations, are never evidence for a Use Case Manager proposal.
- The broker measures, the Triage agent judges; no threshold lives in a recipe.
- Runtime runs only frozen recipes; a live or unproven answer can only raise scrutiny.
- Every parameter has bounds; removing scrutiny needs human approval.
- Nothing in the triage layer or the shared bank assumes a specific SIEM, tool or field name.
- Vendor-specific content (query languages, SIEM product terms, CIM/ECS/vendor field names, vendor API calls) lives only in adapter folders, broker recipes and translations. Core, triage logic, questions, flows, capabilities and parameters never contain it. Gates enforce this.
- The SIEM alert only starts triage. The broker answers each capability from the authoritative source set at onboarding, usually the tool's own API; the SIEM is authoritative only for alert history and log searches. A fallback-source answer is always not_checked.
- Every broker answer has a status and a trust (checked | not_checked); the broker sets trust. A not_checked answer may support a close in Shadow and Recommend (marked in the explanation), never in Auto; in Auto the outcome is the stricter of that rule and the same flow with every not_checked answer read as unknown. On the broker side every translation row has a kind: ambiguous (status unknown in every mode), unverified or proposed (not_checked), standards-defined (checked, e.g. RFC 9110); verified is per customer (cited doc, spot check of at least 20 real alerts, checker, date, product version, expiry; a version change re-opens it). A model may propose a translation in build mode only; it never translates live. A detection is Auto-eligible for a customer only when every translation row on its close paths is verified for that customer; fallback translations don't count, since their answers are always not_checked.
- Technique fallbacks, and every detection without true-positive replay data, are capped at Recommend until they have some; so are destructive and anti-forensic detections. Each cap, and each close step kept out of Auto, carries a code from `bank/triage/auto_exclusions.yaml`, and the Auto-eligible count excludes them.
- Human evidence (`bank/contract/evidence.yaml`) is a manual close in Shadow, an analyst override or an audited close; accepted recommendations and Auto closes never count. Every count of closes (Q0 and C-04, routine pairs, list entries, closure mining, threshold proposals) uses that one definition. In Auto, Q0 needs an audited close.
- An answer about who performed the action (`actor_identity`: group membership, an actor account on a list, a change implementer) is never the only hard-to-fake yes on a close path.
- Every severity comparison uses the normalized scale (`bank/contract/severity.yaml`); each SIEM's severity maps to it in intake, and an unmapped value flags (severity_unmapped).
- Every window looks back from the alert time; nothing looks after it at triage time.
- Missing context never closes and never escalates: an unknown or unavailable context question (C-01…C-08) turns any close that depends on it into a flag with reason `context_unknown`, naming the C-ID. No worst-case defaults.
- The call budget counts calls to outside tools only; our own cached context, list store and case memory don't count. Flows stay at most 5 steps in total, Q0 counting as step 1.
- Gates never pass on nothing: `tools/gates.sh` with no argument runs every family (endpoint, identity, endpoint_malware, network, email, data_protection, technique_fallback); an unknown family or a gate that loads zero detections, flows or replay events fails. The one exception: a family run with no true-positive replay data passes on zero events only if every detection in it is capped at Recommend (`no_tp_replay_data`).
- Translations hold what a vendor's values mean (per source, each row with a kind; verified per customer); what the customer accepts lives in Triage-side parameters (bounded, with a direction tag) or context lists. Never mix them.
- One way in, one way out: alerts enter only through the normalizer; every tool read and every write-back goes through the Tool Broker. No agent or model calls a tool directly.
- Every broker question has a bank ID, a fixed answer type, a status and provenance, and no threshold.
- Decisions are per alert; work, caching and the entity guard are per entity.
- An entity the normalizer can't fill flags, with a fix ticket; never guess.
- The promotion gate is the audited false-close rate, never agreement.
- The falsifier can only reopen or flag. SOAR is read-only.
- smartops-soc-app is read-only from this repo; reuse is by copying with the source commit cited.
- Unbuilt items are labelled "(designed, not built)".
- No language model output decides a verdict.
- Every language-model step that reads alert or customer content goes through the injection classifier first. A hit flags; in Auto it escalates only with a second signal. The text never reaches a model.
- At runtime a language model may only raise scrutiny (close → flag), never lower it.
- Every model that touches customer data runs on the customer's premises. The design names model roles, never one fixed model.
- Public source repos are cloned into `sources/`, which is git-ignored. Never commit them.
- Work on a feature branch, push it, and open a draft PR. Never commit to `main` directly.
  Exception: docs-only changes (README, CLAUDE.md, docs/) may be committed directly to main. Anything under bank/ or tools/ goes through a branch and PR.
- Stop and show the user after each step of the brief. Keep replies concise.
