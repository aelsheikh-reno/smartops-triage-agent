# SmartOps Triage Agent

Agents (see `docs/design-decisions.md` §7):
- **Triage agent** (every alert): runs the fixed flow and applies thresholds; a local model writes the explanation and reviews closes (raise-only).
- **Tool Broker** (every question): routes each question to a domain specialist and returns a measurement plus evidence.
- **Domain specialists** (under the Tool Broker): endpoint, network, identity, email, threat intel and SIEM (one per SIEM); build recipes at onboarding and in Shadow, run them per question.
- **Detection Engineer** (onboarding and rule change): works out what each detection is for; read-only for now.
- **Use Case Manager** (continuously): keeps facts, lists, questions, runbooks and recipes current; proposes threshold changes.
- **Falsifier** (after the fact): tries to prove sampled closes wrong and prepares approval packets; can only reopen or flag.
- **Tier-2 analyst** (later phase): agentic investigation; a human reads the result.

All agents are (designed, not built). A Reno Product Operator runs the system for the first six months (`docs/design-decisions.md` §8); pilot terms are in `docs/pilot-terms.md`.

Design, workflows and question bank for the SmartOps triage agent. The question bank is the core: for each detection, the few yes/no questions that rule out its common benign explanations, plus the customer context needed to answer them.

| Path | What it is |
|---|---|
| `docs/design-decisions.md` | Settled design: triage method, boundaries, bank structure, storage, operating modes |
| `docs/build-question-bank-prompt.md` | Brief for building the bank in a Claude Code session |
| `docs/intake/normalized-alert-v1.md` | The SIEM-agnostic alert every normalizer produces, field by field |
| `docs/intake/context-prefetch.md` | What the context prefetch puts in the Tool Broker's cache |
| `docs/reuse-map.md` | What is ported from smartops-soc-app (file and commit), and what is not |
| `docs/assumptions.md` | Assumptions register: what the design depends on and how each is tested |
| `docs/pilot-terms.md` | Proposed pilot terms |
| `bank/` | The question bank (YAML, built from the brief) |
| `tools/` | Validation, SQL loader and context-fact ranking |

Workflow pages: `docs/workflows/triage-workflow.html` (alert-level) and `docs/workflows/onboarding-workflow.html` (customer onboarding). The repo files are the source of truth. Earlier published copies on claude.ai may be out of date:
- Alert-level workflow: https://claude.ai/artifact/1MtZNSiYtydwf6SQd4JKWo
- Customer onboarding: https://claude.ai/artifact/WTXaT6y6N7ot174GVRGaBX

Status: the question bank (pilot plus batch 1 vendor alerts) and its offline gates are built. The runtime agents, Tool Broker, recipes and integrations are (designed, not built).
