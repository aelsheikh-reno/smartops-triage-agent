# SmartOps Triage Agent

Two agents: the Triage agent decides; the Knowledge Steward keeps its knowledge current.

Design, workflows and question bank for the SmartOps triage agent. The question bank is the core: for each detection, the few yes/no questions that rule out its common benign explanations, plus the customer context needed to answer them.

| Path | What it is |
|---|---|
| `docs/design-decisions.md` | Settled design: triage method, boundaries, bank structure, storage, operating modes |
| `docs/build-question-bank-prompt.md` | Brief for building the bank in a Claude Code session |
| `bank/` | The question bank (YAML, built from the brief) |
| `tools/` | Validation, SQL loader and context-fact ranking |

Workflow pages: `docs/workflows/triage-workflow.html` (alert-level) and `docs/workflows/onboarding-workflow.html` (customer onboarding). The repo files are the source of truth. Earlier published copies on claude.ai may be out of date:
- Alert-level workflow: https://claude.ai/artifact/1MtZNSiYtydwf6SQd4JKWo
- Customer onboarding: https://claude.ai/artifact/WTXaT6y6N7ot174GVRGaBX

Status: design settled; bank not yet built. Next step is the pilot in `docs/build-question-bank-prompt.md`.
