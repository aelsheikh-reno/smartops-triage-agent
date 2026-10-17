# Pilot terms

Status: (designed, not built). These are the terms Reno proposes for a first customer pilot. The software they describe is not built yet; see the build status at the top of `docs/design-decisions.md`.

## Scope
- **Shadow and Recommend only.** No detection runs in Auto during the pilot. Nothing is closed without an analyst.
- **3–5 detections**, chosen after a Shadow close-rate measurement: the detections where the flows would close the most alerts on the customer's own data, among those with complete context facts and frozen recipes.
- **A search-load test before go-live.** Our searches run against the customer's search head under a concurrency cap; the test shows the cap leaves the customer's own searches unaffected (design-decisions §17).

## Operating model
- **A Reno Product Operator** runs the pilot at the customer: onboarding, recipe building, the approval desk, audits and tuning (§5).
- **A named customer shadow** works alongside the operator throughout, and co-signs every reduce-scrutiny change.
- **A defined priority and ticket path**, agreed before go-live:
  - ES urgency (severity × asset priority), adjusted by the verdict.
  - SLA clocks per priority.
  - Escalation to a named IR queue, through the customer's existing ES-to-ServiceNow or Jira integration (§16).

## Measurement
- **Promotion only by the audited false-close gate** (§15). A senior reviewer checks a stratified sample of each detection's closes: at least 200 for high-volume detections, and all closes for low-volume ones. Zero confirmed false closes are required. Agreement with analysts is reported as a diagnostic, never as the gate.
- **Outcome checks.** Any confirmed incident during the pilot triggers a re-check of every close on the same entities in the previous 30 days; a miss counts against the gate.
- **Reported weekly** (§20):
  - time to triage
  - share of alerts the flows would close, by disposition
  - analyst hours saved
  - audited false-close rate
  - backlog and SLA breaches
  - approval-queue age

## Exit criteria
The pilot ends with one of three outcomes, agreed in advance:
1. **Continue to production.** At least one detection has passed the audited false-close gate, and the customer chooses to promote it under the production terms.
2. **Extend.** The gate has not yet been reached on enough closes; extend by an agreed period with the same detections.
3. **Stop.** The gate failed, or the close rate is too low to save meaningful analyst time; Reno hands back a report of what was measured.

## After the pilot
A subscription covers:
- the base bank releases
- recipe maintenance
- remote senior auditing: review of the Falsifier's findings plus the audit sample, after the customer operator takes over (§5)

Handover to the customer operator follows the exit test in §5: the weekly cycle run alone for 4 consecutive weeks, the approval queue cleared within its SLA, and one audit passed with no confirmed false close.
