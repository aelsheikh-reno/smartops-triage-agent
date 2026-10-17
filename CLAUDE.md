# CLAUDE.md

This repo holds the SmartOps triage agent's design notes and question bank. The question bank is the current focus.

## Read first
- `docs/design-decisions.md`: settled design. Follow it; don't re-open decisions without being asked.
- `docs/build-question-bank-prompt.md`: the task brief for building the bank.

## Rules
- YAML under `bank/` is the source of truth. Everything else is generated from it.
- Every question is yes/no and declares exactly one capability from `bank/capabilities.yaml`. No tool names or SPL in the bank; the Tool Broker maps capabilities to the customer's tools.
- No vendor or product names anywhere in the bank (list in `tools/vendors.py`). Only `data_source`, `sigma_logsource`, `sigma_refs`, `source` and `license` may name them; seed data lives in `bank/seeds/` and is never in the runtime bundle.
- Question text describes only what to check about an entity, never where or with which tool.
- The runtime bundle (`tools/export_bundle.py`) excludes offline metadata (`data_source`, `sigma_logsource`, `sigma_refs`, `source`, `license`) and must contain no vendor names; `validate` enforces both.
- Any allowlist or "known tool" question matches on file hash, or code-signing signer plus path. Never on name or path alone.
- Flows: at most 5 steps, early exit, `on_yes` / `on_no` / `on_unknown` on every step.
- Every question records `source` and `license`. Flag text copied from non-Apache sources for legal review.
- New questions start as `status: draft`. Only a human marks them `approved`.
- The Use Case Manager proposes; a human approves anything that reduces scrutiny. The Triage agent's own auto-closures are never evidence for a Use Case Manager proposal.
- The broker measures, the Triage agent judges; no threshold lives in a recipe.
- Runtime runs only frozen recipes; a live or unproven answer can only raise scrutiny.
- Every parameter has bounds; removing scrutiny needs human approval.
- Nothing in the triage layer or the shared bank assumes a specific SIEM, tool or field name.
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
