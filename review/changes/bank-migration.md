Bank migration (#12): roles instead of field names, typed broker answers with Triage-side rules, bounded parameters, context questions.

**Rating changes** (attacker influence, now enforced against each capability's floor):

| Question | Was | Now | Why |
|---|---|---|---|
| Q-0003 (user ran this binary on this host before) | low | high | entity.baseline defaults to high: an attacker can build history |
| Q-0007 (binary opened LSASS on this host before) | low | high | same |
| Q-0010 (binary ran on this host before) | low | high | same |
| Q-0004 (approved change covers host and user) | none | low | change.window is low, and only for changes whose approver is not an implementer (self-approved answers unknown) |
| Q-0055 (approved change names this source) | none | low | same |

**Flow outcome changes** (structural; every other path is unchanged):
- 14 flows (escu: creation_of_shadow_copy, detect_psexec_with_accepteula_flag, process_execution_via_wmi, remote_process_instantiation_via_winrm_and_powershell, windows_service_creation_on_remote_endpoint; techniques T1021.001, T1021.002, T1021.006, T1047, T1069.001, T1069.002, T1087.001, T1087.002, T1482): the step-4 "admin activity baselined" close becomes a flag (4 paths each, 56 in all). Its only none/low yes was identity group membership, which can no longer carry a close on its own.

**Behaviour changes not visible as path changes:**
- Precedent validity is capped at 72h: 11 detections had 7 days.
- Q0 inherits only audited closes or at least 2 independent analyst closes, and only when no alert on the entity has a higher severity (was: no other alert).
- org.prevalence needs the host count in every week of the lookback (was 3 of 4 weeks): stricter.
- change.window: a change approved by one of its own implementers answers unknown (was yes).
- Defender event-log 1117 "Block" now maps to unknown (was blocked before execution): flags instead of a possible mitigated close, until the lab test (#20).
- vendor:ids_alert is now capped at Recommend per customer until its IDS classification rows are verified.
