# CLAUDE.md

This repo holds the SmartOps triage agent's design notes and question bank. The question bank is the current focus.

## Read first
- `docs/design-decisions.md`: settled design. Follow it; don't re-open decisions without being asked.
- `docs/build-question-bank-prompt.md`: the task brief for building the bank.

## Rules
- YAML under `bank/` is the source of truth. Everything else is generated from it.
- Every question is yes/no and declares exactly one capability from `bank/capabilities.yaml`. No tool names or SPL in the bank; the MCP server maps capabilities to the customer's tools.
- No vendor or product names anywhere in the bank (list in `tools/vendors.py`). Only `data_source`, `sigma_logsource`, `sigma_refs`, `source` and `license` may name them; seed data lives in `bank/seeds/` and is never in the runtime bundle.
- Question text describes only what to check about an entity, never where or with which tool.
- The runtime bundle (`tools/export_bundle.py`) excludes offline metadata (`data_source`, `sigma_logsource`, `sigma_refs`, `source`, `license`) and must contain no vendor names; `validate` enforces both.
- Any allowlist or "known tool" question matches on file hash, or code-signing signer plus path. Never on name or path alone.
- Flows: at most 5 steps, early exit, `on_yes` / `on_no` / `on_unknown` on every step.
- Every question records `source` and `license`. Flag text copied from non-Apache sources for legal review.
- New questions start as `status: draft`. Only a human marks them `approved`.
- The Knowledge Steward agent proposes; a human approves anything that reduces scrutiny. The triage agent's own auto-closures are never evidence for a steward proposal.
- Public source repos are cloned into `sources/`, which is git-ignored. Never commit them.
- Work on a feature branch, push it, and open a draft PR. Never commit to `main` directly.
  Exception: docs-only changes (README, CLAUDE.md, docs/) may be committed directly to main. Anything under bank/ or tools/ goes through a branch and PR.
- Stop and show the user after each step of the brief. Keep replies concise.
