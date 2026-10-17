# Pilot terms

Status: (designed, not built). These are the terms Reno proposes for a first customer pilot. The software they describe is not built yet; see the build status at the top of `docs/design-decisions.md`.

## Scope
- **A Phase 0 data health report first** (design-decisions §11), before scoping: foundation checks for the customer's SIEM, the minimum bar (at least 90% of alerts resolve their host to an asset with a priority; crown jewels and privileged users listed; the pilot detections populate their required entities) and a fix list. Remediation is a Reno professional services step before the pilot. Below the bar the pilot is Shadow only; incomplete asset and identity data caps it at Recommend.
- **An addressable-volume report**, also before scoping, built from the customer's own 6–12 months of alert history (design-decisions §12). For each rule it shows volume share, historical benign or false-positive share (the ceiling) and bank coverage. Its total is the only volume-reduction figure used in the proposal.
- **Shadow and Recommend only.** No detection runs in Auto during the pilot. Nothing is closed without an analyst.
- **3–5 detections**, chosen from the addressable-volume report (high volume share × high ceiling, with bank coverage) and confirmed by a Shadow close-rate measurement on live alerts.
- **A load test before go-live.** Our queries run against the customer's SIEM and tool APIs under a per-source concurrency cap; the test shows the cap leaves the customer's own searches unaffected (design-decisions §21).

## Operating model
- **A Reno Product Operator** runs the pilot at the customer: onboarding, recipe building, the approval desk, audits and tuning (§8).
- **A named customer shadow** works alongside the operator throughout, and co-signs every reduce-scrutiny change.
- **A defined priority and ticket path**, agreed before go-live:
  - The SIEM's own urgency or severity × asset priority, adjusted by the verdict and by the entity being hot.
  - SLA clocks per priority.
  - Escalation to a named IR queue, through the customer's existing SIEM-to-ServiceNow or Jira integration (§20).

## Measurement
- **Promotion only by the audited false-close gate** (§19). A senior reviewer checks a stratified sample of each detection's closes: at least 200 for high-volume detections, and all closes for low-volume ones. Zero confirmed false closes are required. Agreement with analysts is reported as a diagnostic, never as the gate.
- **Outcome checks.** Any confirmed incident during the pilot triggers a re-check of every close on the same entities in the previous 30 days; a miss counts against the gate.
- **Reported weekly** (§24):
  - addressable volume, and actual against it
  - entities to review per day
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
- remote senior auditing: review of the Falsifier's findings plus the audit sample, after the customer operator takes over (§8)

Handover to the customer operator follows the exit test in §8: the weekly cycle run alone for 4 consecutive weeks, the approval queue cleared within its SLA, and one audit passed with no confirmed false close.
