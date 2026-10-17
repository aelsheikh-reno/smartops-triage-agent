# SmartOps Triage Agent

**Version 1 scope.** Version 1 builds and tests one SIEM adapter: Splunk ES. All lab tests and the first pilots run on Splunk. The design stays vendor-agnostic: nothing outside the Splunk adapter and Splunk recipes may depend on Splunk.

Agents (see `docs/design-decisions.md` §7):
- **Triage agent** (every alert): runs the fixed flow and applies thresholds; a local model writes the explanation and reviews closes (raise-only).
- **Tool Broker** (every question): the only way out to any tool, for every agent and model, and the only path for SIEM write-back; routes each question to a domain specialist and returns a typed answer with status and provenance.
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
| `docs/intake/context-questions.md` | The context questions C-01…C-08, asked once per entity through the Tool Broker |
| `docs/broker-questions.md` | What may be asked of the Tool Broker, and which bank questions are context or triage |
| `docs/reuse-map.md` | What is ported from smartops-soc-app (file and commit), and what is not |
| `docs/assumptions.md` | Assumptions register: what the design depends on and how each is tested |
| `docs/pilot-terms.md` | Proposed pilot terms |
| `docs/testing/attack-corpus-plan.md` | Attack-corpus plan for the lab, per detection (generated from `tests/corpus/plan.yaml`) |
| `bank/contract/` | The interface the Triage agent and the Tool Broker share: question IDs and answer types, status and trust values, the message envelope (IDs for parallel runs and asynchronous answers) |
| `bank/triage/` | What the Triage agent uses: detections (neutral D-IDs, one folder per family) and their flows, questions, context questions C-01…C-08 and their rules, parameters, semantics, reason codes, customer modes, and the attacker's-view proof records for close paths (`proofs/`, drafts until a human reviews them) |
| `bank/broker/` | What the Tool Broker uses: capabilities, the question map, sources and source authority, translations (each row with a kind; verified per customer under `bank/broker/customers/`), context lists and seeds |
| `bank/intake/` | What the normalizer and the Detection Engineer use: the rule map (source rule IDs to D-IDs), the use-case catalog, the pilot list |
| `engine/` | The flow executor (`executor.py`): the only code that walks a flow (rules, guards, statuses and defer, trust and mode, Q0 and the entity guard, human evidence). It talks to the Tool Broker only through the contract envelope and names no vendor, detection, file format or field |
| `tests/` | Executor tests on synthetic flows (`tests/engine/`), the clean-room broker and replay data (`tests/replay/`: when each detection's source rule fires, which detections are replayable, pinned sources), the regression cases and alert sequences (`tests/cases/`), the aimed cases each proof record lists (`tests/cases/<D-ID>/aimed/`: they must never close), and the lab attack-corpus plan (`tests/corpus/`) |
| `tools/` | Validation (`validate.py`, with the role registry `roles.py` and the field-name list `field_names.py`), close-path gate, strict true-positive replay (single alerts and alert sequences), Auto trust-rule equivalence check (`equivalence.py`), gate self-test, SQL loader and context-fact ranking, the change-scope rule (`check_scope.sh`) and a decision snapshot for refactors (`snapshot.py`); `gates.sh` runs them all |

Workflow pages: `docs/workflows/triage-workflow.html` (alert-level) and `docs/workflows/onboarding-workflow.html` (customer onboarding). The repo files are the source of truth. Earlier published copies on claude.ai may be out of date:
- Alert-level workflow: https://claude.ai/artifact/1MtZNSiYtydwf6SQd4JKWo
- Customer onboarding: https://claude.ai/artifact/WTXaT6y6N7ot174GVRGaBX

Status: the question bank (pilot plus batch 1 vendor alerts) and its offline gates are built. The runtime agents, Tool Broker, recipes and integrations are (designed, not built).
