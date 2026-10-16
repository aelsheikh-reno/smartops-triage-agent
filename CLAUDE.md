# CLAUDE.md

This repo holds the SmartOps triage agent's design notes and question bank. The question bank is the current focus.

## Read first
- `docs/design-decisions.md`: settled design. Follow it; don't re-open decisions without being asked.
- `docs/build-question-bank-prompt.md`: the task brief for building the bank.

## Rules
- YAML under `bank/` is the source of truth. Everything else is generated from it.
- Every question is yes/no and answerable by one lookup (context, baseline, case_memory or alert_field).
- Any allowlist or "known tool" question matches on file hash, or code-signing signer plus path. Never on name or path alone.
- Flows: at most 5 steps, early exit, `on_yes` / `on_no` / `on_unknown` on every step.
- Every question records `source` and `license`. Flag text copied from non-Apache sources for legal review.
- New questions start as `status: draft`. Only a human marks them `approved`.
- Public source repos are cloned into `sources/`, which is git-ignored. Never commit them.
- Work on a feature branch, push it, and open a draft PR. Never commit to `main` directly.
  Exception: docs-only changes (README, CLAUDE.md, docs/) may be committed directly to main. Anything under bank/ or tools/ goes through a branch and PR.
- Stop and show the user after each step of the brief. Keep replies concise.
