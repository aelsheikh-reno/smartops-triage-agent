# Review packet: bank-migration

35 detections, 76 distinct questions, 22 capabilities. Everything is `status: draft`.

How to read a flow: steps run top to bottom; each answer leads to the next step, a close (with disposition and reason code), an escalation, or a flag to an analyst with no verdict. An unknown answer never closes. Q-0000 (precedent) runs first everywhere.

Guards run when a step reaches a close (or, where marked, a flag): each names a question and the answers that raise the outcome; guards only raise, and the strongest result wins (an unknown guard answer always flags, so the table lists only the triggering answers). A guard that fires on no means the close needs a yes from it.

Each question asks the Tool Broker for a typed answer (bool, count, number, enum); where it is not bool, the step's rule [in brackets] turns it into yes or no on the Triage side, against a parameter with bounds. Questions refer to roles of the normalized alert, never to fields.

Attacker influence rates how easily the activity under triage could produce a yes: **none** (records the attacker cannot touch, such as change tickets), **low** (OS-verified or control-recorded facts), **medium** (control-recorded facts that can be forged in transit, such as alerts forwarded over syslog), **high** (attacker-chosen strings such as process names, sender addresses or command lines). Every path to a close must rest on at least one yes rated none or low. Q-0000's rating is set per detection from its fingerprint fields.

## Changes since review

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
- 14 flows (D-0003, D-0006, D-0010, D-0012, D-0023; techniques T1021.001, T1021.002, T1021.006, T1047, T1069.001, T1069.002, T1087.001, T1087.002, T1482): the step-4 "admin activity baselined" close becomes a flag (4 paths each, 56 in all). Its only none/low yes was identity group membership, which can no longer carry a close on its own.

**Behaviour changes not visible as path changes:**
- Precedent validity is capped at 72h: 11 detections had 7 days.
- Q0 inherits only audited closes or at least 2 independent analyst closes, and only when no alert on the entity has a higher severity (was: no other alert).
- org.prevalence: the host count in at least 3 of 4 weeks, as before the migration (round 1 had briefly required every week). The broker returns the k-th lowest weekly count; the threshold stays Triage-side.
- change.window: a change approved by one of its own implementers answers unknown (was yes).
- Defender event-log 1117 "Block" now maps to unknown (was blocked before execution): flags instead of a possible mitigated close, until the lab test (#20).
- Round 2: Q-0049 reads the endpoint API first (vendor alert ID, else device + hash + window); the SIEM copy is a fallback. Q-0067 is a Triage-side rule over C-06 and C-08.
- Round 4, row kinds and modes (replaces round 3's raise-only rule): ambiguous rows (5 then: Defender event 1117 Block and 1117 Quarantine/Remove/Clean, CrowdStrike quarantine in its API and SIEM-copy tables, generic post-execution remediation states) answer unknown in every mode; unverified rows (110) may support a close in Shadow and Recommend, marked, never in Auto; verified is per customer. A detection is Auto-eligible for a customer only when every row on its close paths is verified for that customer (replaces vendor_mapping_verified). Technique fallbacks stay capped at Recommend (#26).
- Round 3, missing context: an unknown or unavailable context question flags with context_unknown and never escalates. Q-0067 with C-08 unknown flags (was: escalate, treated as a server).
- D-0028 is now capped at Recommend per customer until its IDS classification rows are verified.
- Round 5, triage/broker split: bank/ is now contract/ (question IDs, answer types, status, trust, envelope), triage/, broker/ and intake/. Detections have neutral IDs D-0001…D-0035 by family; source rule IDs moved to intake/rule-map.yaml. The Triage agent sees each answer's status and trust only; a not_checked answer never supports an Auto close. No triage outcome changed except the round 5 decisions: an email quarantine supports a close only before delivery (Q-0074 replaces Q-0027 in D-0031); HTTP status translations are standards-defined (checked); fallback translations don't count against Auto eligibility.

## Gate results

- validate: PASS (35 detections, 26 technique fallbacks, 76 questions, 8 context questions, 32 context facts, 33 capabilities, 39 parameters, 7 translations: 0 errors, 0 warnings)
- attacker influence: PASS (61 flows, 523 close paths checked, 0 failing, in 0 flows; 50 closes flag under the forwarded profile, 1 under fingerprint fallback)
- replay: PASS (replay: 655 TP events in 28 detections, 44/44 regression cases; 0 benign/FP closes, 0 mitigated closes -> PASS)

## Detections

### Add or Set Antivirus Exclusion via MpPreference (`D-0001`)

Detects Add-MpPreference or Set-MpPreference adding an antivirus, Controlled Folder Access or ASR exclusion from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.command_line (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0022: Is every exclusion value in the command line on the customer's approved antivirus exclusion list for this host? | `list.lookup` | low | close (benign true positive: approved_av_exclusion) | next step | next step | – |
| 4 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### BITSAdmin Download File (`D-0002`)

Detects bitsadmin.exe /transfer or /addfile downloading a file from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.parent_name (high), derived:url_host (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0017: Is every URL host in the command line an internal or approved download domain? | `list.lookup` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: activity_baselined_on_host) | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | close (benign true positive: approved_change) | **escalate** | flag to analyst | – |

### Creation of Shadow Copy (`D-0003`)

Detects vssadmin or wmic creating a volume shadow copy from process creation logs.

Note: The source rule maps this to T1003.003 (NTDS): shadow copies are used to copy ntds.dit. On domain controllers the crown-jewel guardrail blocks auto-close.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.parent_name (high), role:process.sha256 (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0021: Is the parent process sanctioned backup software, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_backup_tool) | next step | next step | – |
| 3 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | flag to analyst | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Deleting Shadow Copies (`D-0004`)

Detects vssadmin or wmic deleting volume shadow copies from process creation logs.

Note: Contrast case: benign deletion is rare and the behavior precedes ransomware. Unknown answers escalate instead of flagging.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.parent_name (high), role:process.sha256 (low). Precedent entity: role:host.name. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0021: Is the parent process sanctioned backup software, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_backup_tool) | next step | next step | – |
| 3 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | **escalate** | – |

### Detect MSHTA Url in Command Line (`D-0005`)

Detects mshta.exe with an http(s) URL in the command line from process creation logs.

Required roles: event, host, process. Fingerprint: role:host.name (low), role:process.parent_name (high), derived:url_host (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0017: Is every URL host in the command line an internal or approved download domain? | `list.lookup` | low | next step | **escalate** | flag to analyst | – |
| 3 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: activity_baselined_on_host) | next step | next step | – |
| 4 | Q-0015: Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | close (benign true positive: prevalent_in_org) | **escalate** | flag to analyst | – |

### Detect PsExec With accepteula Flag (`D-0006`)

Detects PsExec run with -accepteula (likely first use) on an endpoint from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:user.name (low), role:process.parent_name (high), role:process.sha256 (low), derived:target_host (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0003: Has this user run this same binary (same hash, or same signer and path) on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | flag to analyst | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Detect Remote Access Software Usage Process (`D-0007`)

Detects execution of a known remote access tool (the source rule's remote-access tool list) on an endpoint from process creation logs.

Required roles: host, user, process, event. Fingerprint: role:host.name (low), role:process.name (high), role:process.sha256 (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0008: Is the remote access tool on the customer's sanctioned list, matched on hash or on signer plus install path? | `list.lookup` | low | next step | **escalate** | flag to analyst | – |
| 3 | Q-0009: Was the remote access tool launched by one of its expected parents (its own service or a sanctioned deployment tool), matched on the parent's hash or signer plus path? | `list.lookup` | low | next step | **escalate** | next step | – |
| 4 | Q-0010: Has this same binary (same hash, or same signer and path) run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: sanctioned_rmm_baselined) | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | close (benign true positive: approved_change) | **escalate** | flag to analyst | – |

### Detect SharpHound Usage (`D-0008`)

Detects SharpHound (BloodHound collector) execution by process or original file name from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:user.name (low), role:process.sha256 (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0026: Does an authorized security test engagement cover this host or user at the alert time? | `list.lookup` | low | close (benign true positive: authorized_security_test) | **escalate** | flag to analyst | – |

### Malicious PowerShell Process - Execution Policy Bypass (`D-0009`)

Detects PowerShell started with -ExecutionPolicy Bypass from process creation logs.

Required roles: event, host, process. Fingerprint: role:host.name (low), role:process.parent_name (high), role:process.command_line (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0019: Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | next step | flag to analyst | flag to analyst | – |
| 4 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: activity_baselined_on_host) | next step | next step | – |
| 5 | Q-0015: Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | close (benign true positive: prevalent_in_org) | **escalate** | flag to analyst | – |

### Process Execution via WMI (`D-0010`)

Detects a process spawned by WmiPrvSE.exe (local or remote WMI execution) from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.sha256 (low), role:process.command_line (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0013: Is the acting process a sanctioned deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_management_tool) | next step | next step | – |
| 3 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | flag to analyst | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Registry Keys Used For Persistence (`D-0011`)

Detects writes to Run/RunOnce and other autostart registry keys on an endpoint from registry events.

Note: Command-line and registry-value baselines are attacker-chosen strings (attacker_influence high), so on their own they flag instead of closing.

Required roles: event, host, process, registry, user. Fingerprint: role:host.name (low), role:registry.path (high), role:registry.value_name (high), role:registry.value_data (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0013: Is the acting process a sanctioned deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_management_tool) | next step | next step | – |
| 3 | Q-0019: Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | close (benign true positive: trusted_signed_software) | next step | next step | – |
| 4 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | next step | next step | – |
| 5 | Q-0018: Has the same registry value name with the same normalized data been written on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | flag to analyst | **escalate** | flag to analyst | – |

### Remote Process Instantiation via WinRM and PowerShell (`D-0012`)

Detects PowerShell Invoke-Command -ComputerName starting a process on a remote host from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:user.name (low), derived:target_host (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0012: Has this user run the same normalized command line on any host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | flag to analyst | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Suspicious Regsvr32 Register Suspicious Path (`D-0013`)

Detects regsvr32.exe registering a non-DLL file from AppData, ProgramData or Windows\Temp from process creation logs.

Note: fp_quality none: The source rule gives no benign cause. The tested cause (signed per-user installers) comes from analyst practice and needs review. The registered file is resolved as entity:module; without module identity from the server the gate answers unknown and the alert flags.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.command_line (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0019: Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | next step | **escalate** | flag to analyst | – |
| 3 | Q-0015: Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | close (benign true positive: prevalent_in_org) | next step | next step | – |
| 4 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | close (benign true positive: approved_change) | **escalate** | flag to analyst | – |

### Suspicious Rundll32 no Command Line Arguments (`D-0014`)

Detects rundll32.exe running with no arguments (typical injection target) from process creation logs.

Required roles: event, host, process. Fingerprint: role:host.name (low), role:process.parent_name (high), role:process.path (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0019: Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | next step | **escalate** | flag to analyst | – |
| 3 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: activity_baselined_on_host) | next step | next step | – |
| 4 | Q-0015: Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | close (benign true positive: prevalent_in_org) | **escalate** | flag to analyst | – |

### Suspicious Scheduled Task from Public Directory (`D-0015`)

Detects schtasks.exe /create with an action in a public directory (Users\Public, ProgramData, Windows\Temp) from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.parent_name (high), role:process.command_line (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | next step | next step | – |
| 4 | Q-0019: Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | next step | flag to analyst | flag to analyst | – |
| 5 | Q-0015: Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | close (benign true positive: prevalent_in_org) | **escalate** | flag to analyst | – |

### Windows Event Log Cleared (`D-0016`)

Detects the Security log (1102) or System log (104) being cleared on an endpoint from Windows event logs.

Required roles: event, host, user. Fingerprint: role:host.name (low), role:user.name (low), role:event.type_id (low). Precedent entity: role:host.name. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | next step | next step | next step | – |
| 2 | Q-0023: Is the host in a rebuilding or decommissioning state in the asset inventory at the alert time? | `list.lookup` | none | close (benign true positive: host_rebuild) | next step | next step | – |
| 3 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Windows File Download Via CertUtil (`D-0017`)

Detects certutil.exe downloading a file (-urlcache/-verifyctl -f or -URL) from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.parent_name (high), derived:url_host (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0017: Is every URL host in the command line an internal or approved download domain? | `list.lookup` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: activity_baselined_on_host) | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | close (benign true positive: approved_change) | **escalate** | flag to analyst | – |

### Windows File Download Via PowerShell (`D-0018`)

Detects PowerShell downloading content (Invoke-WebRequest, wget, curl, DownloadFile/String/Data) from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.parent_name (high), derived:url_host (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0017: Is every URL host in the command line an internal or approved download domain? | `list.lookup` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: activity_baselined_on_host) | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | close (benign true positive: approved_change) | **escalate** | flag to analyst | – |

### Windows Office Product Spawned Uncommon Process (`D-0019`)

Detects an Office application spawning a shell, script host or LOLBin (cmd, PowerShell, wscript, cscript, mshta, rundll32, regsvr32, certutil, bitsadmin, wmic) from process creation logs.

Note: fp_quality none: The source rule gives no benign cause. The tested causes (routine business macros and add-ins) come from analyst practice and need review. Command-line and registry-value baselines are attacker-chosen strings (attacker_influence high), so on their own they flag instead of closing.

Required roles: event, host, process. Fingerprint: role:host.name (low), role:process.parent_name (high), role:process.name (high), role:process.command_line (high). Precedent entity: role:host.name. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0014: Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | flag to analyst | next step | next step | – |
| 3 | Q-0015: Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | flag to analyst | **escalate** | flag to analyst | – |

### Windows Possible Credential Dumping (`D-0020`)

Detects a non-SYSTEM process opening LSASS with query-limited or duplicate-handle access on an endpoint from process access events.

Note: The source rule's search already drops SYSTEM and NETWORK SERVICE sources, so most EDR/AV agents never reach triage. The remaining benign cases are user-context tools. Coverage gap: SYSTEM-context dumping is excluded by the source rule's search; needs a separate detection.


Required roles: host, user, process, target_process, process_access, event. Fingerprint: role:host.name (low), role:process.path (high), role:process.sha256 (low), role:process_access.rights (high). Precedent entity: role:host.name. Precedent valid for 24h. Detection parameters: entity_baseline_min_days 5.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0005: Is the process that opened LSASS on the customer's sanctioned LSASS accessor list, matched on hash or on signer plus path? | `list.lookup` | low | close (false positive: sanctioned_lsass_accessor) | next step | next step | – |
| 3 | Q-0006: Does the process that opened LSASS match a known benign LSASS accessor on hash or on signer plus expected install path? | `list.lookup` | low | close (false positive: known_benign_lsass_accessor) | next step | next step | – |
| 4 | Q-0007: Has this same binary (path and hash) opened LSASS on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | next step | **escalate** | flag to analyst | – |
| 5 | Q-0011: Is the binary that opened LSASS validly signed by a trusted publisher and not on the dump-capable exclusion list? | `file.signer` | low | close (false positive: lsass_access_baselined) | flag to analyst | flag to analyst | – |

### Windows Remote Services Rdp Enable (`D-0021`)

Detects fDenyTSConnections set to 0 (RDP enabled) on an endpoint from registry events.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.sha256 (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0013: Is the acting process a sanctioned deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_management_tool) | next step | next step | – |
| 3 | Q-0016: Is the host on the customer's list of hosts whose role requires RDP? | `list.lookup` | none | close (benign true positive: rdp_expected_on_host) | next step | next step | – |
| 4 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Windows Schtasks Create Run As System (`D-0022`)

Detects schtasks.exe /create /ru SYSTEM from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:process.parent_name (high), role:process.command_line (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | next step | next step | – |
| 4 | Q-0019: Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | next step | flag to analyst | flag to analyst | – |
| 5 | Q-0015: Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? [gte org_prevalence_min_hosts] | `org.prevalence` | high | close (benign true positive: prevalent_in_org) | **escalate** | flag to analyst | – |

### Windows Service Creation on Remote Endpoint (`D-0023`)

Detects sc.exe creating a service on a remote host (\\host create binpath=) from process creation logs.

Required roles: event, host, process, user. Fingerprint: role:host.name (low), role:user.name (low), role:process.sha256 (low), derived:target_host (high). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0001: Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | close (benign true positive: sanctioned_deployment_tool) | next step | next step | – |
| 3 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0012: Has this user run the same normalized command line on any host on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | flag to analyst | next step | next step | – |
| 5 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Windows Vulnerable Driver Installed (`D-0024`)

Detects a kernel driver service install (7045) whose file name matches a vulnerable-driver catalogue, from Windows System logs.

Note: The source rule matches the driver catalogue on file name only. A hash miss in the driver catalogue plus a trusted signer is not enough to call it a name collision (vulnerable drivers are trusted-signed and the catalogue is incomplete), so that case flags.

Required roles: file, event, host. Fingerprint: role:host.name (low), role:file.path (high), role:file.sha256 (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0025: Is there an unexpired approved exception for this driver's SHA256 on this host? | `list.lookup` | low | close (benign true positive: approved_driver_exception) | next step | next step | – |
| 3 | Q-0024: Does the driver's SHA256 match a known vulnerable or malicious driver sample? | `file.reputation` | low | **escalate** | next step | next step | – |
| 4 | Q-0019: Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | flag to analyst | **escalate** | flag to analyst | – |

### Detect New Local Admin account (`D-0025`)

Detects a new local account (4720) that is added to local Administrators (4732) within 180 minutes, from Windows Security logs.

Required roles: event, host, actor, user. Fingerprint: role:host.name (low), role:actor.name (low), role:user.name (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag |
| 2 | Q-0020: Was the account created or added to local Administrators by a provisioning service account? | `list.lookup` | low | flag to analyst | next step | next step | – |
| 3 | Q-0002: Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | next step | **escalate** | flag to analyst | – |
| 4 | Q-0004: Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | flag to analyst | **escalate** | flag to analyst | – |

### Antivirus or EDR malware detection (`D-0026`)

Generic: an antivirus or EDR product reports a malware detection on a host (normalized malware alert, any product).

Note: High-risk families escalate even when blocked. Only a block before execution can close, and only for low-risk classes; post-execution remediation, pending reboot and partial remediation flag. Test files flag. A block reported over forwarded syslog cannot close alone. Crown-jewel hosts flag through the permanent guardrail. Approved tooling and analysis hosts match on asset ID, never hostname. A sample from an analysis host seen on any other host in the window escalates; an approved tool's hash seen outside its approved hosts flags. A quarantined or unreadable file with no hash cannot close as approved tooling; the flow continues. The fingerprint uses the asset ID; without one it falls back to the hostname and the precedent is rated medium. Whether a file ran is a question to the Tool Broker (Q-0049); a not_checked answer never supports an Auto close.

Required roles: host, user, reporting_control, file, event. Fingerprint: role:host.asset_id (low), role:reporting_control.signature (low), role:file.sha256 (low). Precedent entity: role:host.asset_id. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag; Q-0029 [yes high_risk; unknown unknown] yes → escalate |
| 2 | Q-0048: Is the detected file approved security tooling on this host (by hash, or signer plus path while the file is readable), or is the host an approved sandbox or analysis host? | `list.lookup` | low | close (benign true positive: approved_security_tooling) | next step | next step | Q-0073 [gte org_prevalence_escape_min_hosts] yes → escalate (if analysis_host); Q-0073 [gte org_prevalence_escape_min_hosts] yes → flag (if tool) |
| 3 | Q-0029: Is the detection in a high-risk family (hack tool, credential dumper, ransomware, web shell, exploit framework, remote access trojan or remote-admin tool, miner, proxyware, crack)? [yes high_risk; unknown unknown] | `alert.class` | low, forwarded medium | **escalate** | next step | next step | – |
| 4 | Q-0049: Was the file blocked before it executed? [yes pre_execution; unknown unknown] | `endpoint.run_status` | low, forwarded medium | next step | **escalate** | flag to analyst | – |
| 5 | Q-0028: Is the detection in a low-risk class (potentially unwanted software, adware, grayware), and not a test file? [yes low_risk; unknown unknown] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_low_risk_detection) | flag to analyst | flag to analyst | Q-0046 [gte alert_history_min_count] yes → flag; Q-0030 yes → escalate |

### Firewall deny or port-scan alert (`D-0027`)

Generic: a firewall reports denied connections or a scan pattern from a source (normalized network-traffic alert, any product).

Note: Internal sources never close on denied traffic; they flag. The denied check covers every connection from the source, to any destination. An approved scanner closes only while a scan job targeting the destination was running; an approved tester only under a covering change or engagement record. Allowed connections elsewhere from the source flag rather than escalate: they show the source is not only probing, not that the denied connection got through.

Required roles: src, dest, network, reporting_control, event. Fingerprint: role:src.ip (medium), role:dest.ip (high), role:dest.port (high), role:network.rule (high). Precedent entity: role:src.ip. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | medium | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag; Q-0050 yes → flag; Q-0042 no → flag |
| 2 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step | Q-0052 no → flag (if scanner); Q-0055 no → flag (if tester) |
| 3 | Q-0056: Is the source an approved infrastructure source (monitoring, backup, replication, health check) for this destination and port? | `list.lookup` | medium | close (benign true positive: approved_infrastructure) | next step | next step | Q-0042 no → flag; Q-0046 [gte alert_history_min_count] yes → flag |
| 4 | Q-0055: Does an approved change or test-engagement record name this source address and cover the alert time? | `change.window` | low | close (benign true positive: approved_change) | next step | next step | – |
| 5 | Q-0042: Was every connection from the source address in the last 24 hours, up to the alert time, denied, with none allowed or established, to any destination? | `traffic.denied_only` | low | close (mitigated true positive: denied_no_successful_connection) | flag to analyst | flag to analyst | Q-0050 yes → flag; Q-0032 yes → escalate |

### IDS or IPS signature alert (`D-0028`)

Generic: a network IDS or IPS reports a signature match between a source and a target (normalized intrusion alert, any product).

Note: Internal sources never close on blocked or patched (not applicable); tuned-signature and approved-scanner closes still apply to them. An approved scanner closes only while its scan job targets this destination; an approved tester only under a covering change or engagement record (unknown flags). Alert history applies to the blocked and not-applicable closes only. Exploit, intrusion and malware classes flag when blocked; only reconnaissance and policy classes close on a block. Signatures with no vulnerability mapping answer unknown at the vulnerability step and flag. A not_checked signature-class answer never supports an Auto close.

Required roles: src, dest, reporting_control, event. Fingerprint: role:src.ip (medium), role:dest.ip (high), role:reporting_control.signature_id (high). Precedent entity: role:src.ip. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | medium | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag; Q-0050 yes → flag; Q-0046 [gte ids_history_min_count] yes → flag; Q-0053 [yes ids_exploit_class_values] yes → flag; Q-0027 [yes blocked_action_values] no → flag |
| 2 | Q-0051: Is this signature or rule on the customer's tuned list for this source and destination (or application)? | `list.lookup` | none | close (false positive: tuned_signature) | next step | next step | – |
| 3 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step | Q-0052 no → flag (if scanner); Q-0055 no → flag (if tester) |
| 4 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? [yes blocked_action_values] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0053 [yes ids_exploit_class_values] yes → flag; Q-0050 yes → flag; Q-0046 [gte ids_history_min_count] yes → flag; Q-0032 yes → escalate |
| 5 | Q-0033: Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | flag to analyst | **escalate** | flag to analyst | Q-0032 yes → escalate (on flag) |

### Web proxy or URL-filter block (`D-0029`)

Generic: a web proxy or URL filter blocks a request from a user or host (normalized web alert, any product).

Note: High-risk categories escalate even when blocked. A non-browser or empty user agent flags, and so do ten or more blocks from one host to one domain in the window (proxy_history_min_count) (repeat requests suggest a beacon). Uncategorised sites close only when the host visited them on at least 3 earlier days with a browser.

Required roles: src, user, web, dest, reporting_control, event. Fingerprint: role:src.ip (low), role:dest.domain (high), role:web.category (low). Precedent entity: role:src.ip. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte proxy_history_min_count] yes → flag; Q-0057 [yes web_high_risk_categories] yes → escalate; Q-0058 [yes browser] no → flag |
| 2 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? [yes blocked_action_values] | `alert.class` | low, forwarded medium | next step | **escalate** | flag to analyst | – |
| 3 | Q-0057: Is the blocked site in a high-risk web category (malware, phishing, command and control, botnet, newly registered and similar listed categories)? [yes web_high_risk_categories] | `alert.class` | low, forwarded medium | **escalate** | next step | next step | – |
| 4 | Q-0041: Is the blocked site in a low-risk web category (advertising, streaming media, social networking, games, shopping, entertainment, sports, travel, news and media)? [yes web_low_risk_categories] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_low_risk_category) | next step | next step | Q-0058 [yes browser] no → flag; Q-0046 [gte proxy_history_min_count] yes → flag; Q-0034 yes → escalate |
| 5 | Q-0060: Has this host requested this domain on at least the customer's minimum number of distinct days in the lookback before the alert window? [gte entity_baseline_min_days] | `entity.baseline` | high | close (benign true positive: established_uncategorized_site) | flag to analyst | flag to analyst | Q-0059 [yes_unless web_uncategorized_values] yes → flag; Q-0058 [yes browser] no → flag; Q-0046 [gte proxy_history_min_count] yes → flag; Q-0034 yes → escalate |

### Web application firewall alert (`D-0030`)

Generic: a web application firewall reports a rule match on a request to a protected application (normalized web alert, any product).

Note: Uses the client address, not the edge address. A block with a success status flags. Internal clients never close on a block. Five or more distinct rules from one client flag the blocked close. QA and penetration-test sources close under a covering change or engagement record. The vulnerability step was dropped: generic rules have no CVE mapping, so it never closed them; an unblocked request flags.

Required roles: src, web, dest, reporting_control, event. Fingerprint: derived:client_ip (medium), role:web.app (high), role:reporting_control.signature (high). Precedent entity: derived:client_ip. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | medium | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag; Q-0050 yes → flag; Q-0047 [gte waf_distinct_signatures_min] yes → flag; Q-0054 [yes success] yes → flag; Q-0027 [yes blocked_action_values] no → flag |
| 2 | Q-0051: Is this signature or rule on the customer's tuned list for this source and destination (or application)? | `list.lookup` | none | close (false positive: tuned_signature) | next step | next step | – |
| 3 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step | Q-0052 no → flag (if scanner); Q-0055 no → flag (if tester) |
| 4 | Q-0055: Does an approved change or test-engagement record name this source address and cover the alert time? | `change.window` | low | close (benign true positive: authorized_security_test) | next step | next step | – |
| 5 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? [yes blocked_action_values] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | flag to analyst | flag to analyst | Q-0054 [yes success] yes → flag; Q-0050 yes → flag; Q-0047 [gte waf_distinct_signatures_min] yes → flag |

### Email gateway threat alert (`D-0031`)

Generic: an email security gateway reports a malicious or suspicious message, delivered or not (normalized email alert, any product).

Note: Every fingerprint field is sender-chosen, so a precedent never closes or flags by itself; the flow proceeds and the precedent is shown as context. A block closes only when the message is out of every mailbox and no reputation source marks its URL or attachment. Delivered-then-removed closes only with no recorded click or open.

Required roles: email, file, reporting_control, event. Fingerprint: role:email.sender (high), role:email.subject (high), role:file.sha256 (high). Precedent entity: role:email.recipient. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | high | next step | next step | next step | – |
| 2 | Q-0037: Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker inside the campaign window? | `list.lookup` | low | close (benign true positive: authorized_phishing_simulation) | next step | next step | Q-0070 no → flag |
| 3 | Q-0035: Is the message quarantined or removed from every recipient mailbox? | `email.message_status` | low | next step | flag to analyst | flag to analyst | – |
| 4 | Q-0074: Did the email control stop the message before it reached the recipient (blocked, rejected, or quarantined before delivery)? [yes email_blocked_action_values] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0034 yes → flag; Q-0030 yes → flag |
| 5 | Q-0036: Do click and open records show that no recipient followed a link or opened an attachment from the message (unknown when it carried an attachment and attachment opens are not recorded on every recipient's host)? | `email.no_interaction` | medium | close (mitigated true positive: contained_without_interaction) | **escalate** | flag to analyst | Q-0076 [yes_unless none] yes → flag |

### User-reported phishing email (`D-0032`)

Generic: a user reports an email as phishing through the report button or a reporting mailbox.

Note: The message id is sender-chosen, so a precedent never closes or flags by itself. Approved senders (customer-controlled or transactional-notification domains, with an aligned DMARC pass) are checked first; a remaining message with no URL and no attachment flags as possible business-email compromise. Simulation and approved-sender closes need an aligned DMARC pass. Repeat reports of one campaign (sender domain plus URL domain) flag.

Required roles: email, user, event. Fingerprint: role:email.message_id (high). Precedent entity: role:email.message_id. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | high | next step | next step | next step | – |
| 2 | Q-0037: Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker inside the campaign window? | `list.lookup` | low | close (benign true positive: authorized_phishing_simulation) | next step | next step | Q-0070 no → flag |
| 3 | Q-0071: Is the From domain on the customer's approved-sender list (external transactional-notification senders only; the customer's own domains never count)? | `list.lookup` | high | close (false positive: false_report) | next step | next step | Q-0075 yes → flag; Q-0070 no → flag; Q-0034 yes → escalate; Q-0046 [gte alert_history_min_count] yes → flag |
| 4 | Q-0072: Does the message contain no URL and no attachment? [lte 0] | `alert.measure` | low | flag to analyst | next step | next step | – |
| 5 | Q-0036: Do click and open records show that no recipient followed a link or opened an attachment from the message (unknown when it carried an attachment and attachment opens are not recorded on every recipient's host)? | `email.no_interaction` | medium | close (mitigated true positive: contained_without_interaction) | **escalate** | flag to analyst | Q-0076 [yes_unless none] yes → flag; Q-0035 no → flag; Q-0046 [gte alert_history_min_count] yes → flag |

### DLP policy match (`D-0033`)

Generic: a DLP control reports regulated data leaving through email, web, cloud storage or print (normalized DLP alert, any product).

Note: Held, quarantined and pending-release actions answer unknown and flag: a later release would undo them. High severity or a large record count flags even to approved destinations. Three or more DLP alerts for the same user in the window turn a benign close into a flag and a block into an escalation, and escalate an unblocked match to an unapproved destination (which otherwise flags).

Required roles: user, dest, reporting_control, dlp, event. Fingerprint: role:user.name (low), role:reporting_control.signature (low), derived:destination_domain (high). Precedent entity: role:user.name. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag; Q-0063 [yes dlp_high_severity_values; unknown other] yes → flag; Q-0064 [gte dlp_record_count_flag] yes → flag; Q-0046 [gte alert_history_min_count] yes → flag |
| 2 | Q-0061: Is the flagged content a known DLP test file or template, by content hash? | `list.lookup` | low | close (false positive: known_test_data) | next step | next step | Q-0046 [gte alert_history_min_count] yes → flag |
| 3 | Q-0062: Is the DLP action final (blocked or deleted), rather than held, quarantined or pending release? [yes dlp_final_block_values; unknown dlp_pending_values] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | flag to analyst | Q-0046 [gte alert_history_min_count] yes → escalate |
| 4 | Q-0038: Does an approved, unexpired DLP exception cover this user, policy and destination? | `list.lookup` | none | close (benign true positive: approved_business_exception) | next step | next step | Q-0063 [yes dlp_high_severity_values; unknown other] yes → flag; Q-0064 [gte dlp_record_count_flag] yes → flag; Q-0046 [gte alert_history_min_count] yes → flag |
| 5 | Q-0039: Is the destination an internal or tenant domain, or an approved partner domain for this data class? | `list.lookup` | low | close (benign true positive: approved_recipient) | flag to analyst | flag to analyst | Q-0063 [yes dlp_high_severity_values; unknown other] yes → flag; Q-0064 [gte dlp_record_count_flag] yes → flag; Q-0046 [gte alert_history_min_count] yes → escalate (on close/flag) |

### Removable media (device control) alert (`D-0034`)

Generic: an endpoint device-control or DLP product reports removable storage connected (any product). File writes have their own detection.

Note: Connection events only; a write event flags here and belongs to vendor:removable_media_write. A non-storage device class flags first (possible keystroke injector). Servers and crown jewels escalate. A missing file count answers unknown and flags. Device serial numbers can be spoofed, so no approved-device list closes. The zero-files-written close needs the customer's coverage report to show write events from the same product; otherwise it flags.

Required roles: host, user, device, reporting_control, event. Fingerprint: role:host.name (low), role:user.name (low), role:device.id (high), role:device.event_type (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag; Q-0065 [yes connect] no → flag; Q-0066 [yes usb_non_storage_classes] yes → flag; Q-0067 yes → escalate |
| 2 | Q-0066: Is the device a non-storage class (keyboard, mouse, composite, network adapter)? [yes usb_non_storage_classes] | `alert.class` | low | flag to analyst | next step | flag to analyst | – |
| 3 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? [yes blocked_action_values] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0065 [yes connect] no → flag; Q-0067 yes → escalate; Q-0046 [gte alert_history_min_count] yes → flag |
| 4 | Q-0043: Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | close (benign true positive: approved_business_exception) | next step | next step | Q-0065 [yes connect] no → flag; Q-0067 yes → escalate; Q-0068 [gte usb_files_written_flag] yes → flag |
| 5 | Q-0044: Did the alert record no file written to the device? [lte 0] | `alert.measure` | low | close (benign true positive: no_data_transferred) | **escalate** | flag to analyst | Q-0065 [yes connect] no → flag; Q-0067 yes → escalate |

### Removable media file write (device control) alert (`D-0035`)

Generic: an endpoint device-control or DLP product reports files written to removable storage (any product).

Note: Write events only. Blocked writes and approved exceptions close; more files than the customer's threshold flag even with an exception. Non-storage devices flag; servers and crown jewels escalate.

Required roles: host, user, device, reporting_control, event. Fingerprint: role:host.name (low), role:user.name (low), role:device.id (high), role:device.event_type (low). Precedent entity: role:host.name. Precedent valid for 72h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | close (inherit: precedent_match) | next step | next step | Q-0045 [gte alert_history_min_count] yes → flag; Q-0069 [yes write] no → flag; Q-0066 [yes usb_non_storage_classes] yes → flag; Q-0067 yes → escalate |
| 2 | Q-0066: Is the device a non-storage class (keyboard, mouse, composite, network adapter)? [yes usb_non_storage_classes] | `alert.class` | low | flag to analyst | next step | flag to analyst | – |
| 3 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? [yes blocked_action_values] | `alert.class` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0069 [yes write] no → flag; Q-0067 yes → escalate; Q-0046 [gte alert_history_min_count] yes → flag |
| 4 | Q-0043: Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | close (benign true positive: approved_business_exception) | **escalate** | flag to analyst | Q-0069 [yes write] no → flag; Q-0067 yes → escalate; Q-0068 [gte usb_files_written_flag] yes → flag |

## Questions used

| Question | Text | Capability | Influence | Why |
|---|---|---|---|---|
| Q-0000 | Is there a qualifying precedent for this fingerprint: an audited close, or (outside Auto) at least the customer's minimum number of independent human closes, inside the validity window, with the precedent entity not a crown jewel, no other alert on it of higher severity than this one, and no other detection on it in the grouping window (a mitigated precedent only when this alert was also stopped)? | `precedent.check` | low | Default only; each detection rates Q0 from its fingerprint fields (step-level attacker_influence). |
| Q-0001 | Is the parent process a sanctioned software deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | Matched on hash or OS-verified signer plus path; the attacker would have to run under the sanctioned tool itself. |
| Q-0002 | Is the user an IT admin account, directly or through an admin group? | `identity.groups` | low | Group membership is set by directory administrators, not by the alerting activity. |
| Q-0003 | Has this user run this same binary (same hash, or same signer and path) on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? | `entity.baseline` | high | An attacker who already runs code as this user can build the history by running the same binary on several days; baselines default to high (capability-spec). |
| Q-0004 | Does an approved change cover this host at the alert time and list the alert's user, or a group they belong to, as an implementer? | `change.window` | low | Approved change records the activity cannot touch; a yes needs an approver who is not an implementer, so a self-approved change cannot carry a close. |
| Q-0005 | Is the process that opened LSASS on the customer's sanctioned LSASS accessor list, matched on hash or on signer plus path? | `list.lookup` | low | Matched on hash or OS-verified signer plus path. |
| Q-0006 | Does the process that opened LSASS match a known benign LSASS accessor on hash or on signer plus expected install path? | `list.lookup` | low | Matched on hash or OS-verified signer plus path. |
| Q-0007 | Has this same binary (path and hash) opened LSASS on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? | `entity.baseline` | high | An attacker with a foothold can open LSASS with the same binary on several days to build history; baselines default to high (capability-spec). |
| Q-0008 | Is the remote access tool on the customer's sanctioned list, matched on hash or on signer plus install path? | `list.lookup` | low | Matched on hash or OS-verified signer plus path. |
| Q-0009 | Was the remote access tool launched by one of its expected parents (its own service or a sanctioned deployment tool), matched on the parent's hash or signer plus path? | `list.lookup` | low | Parent identity matched on hash or OS-verified signer plus path. |
| Q-0010 | Has this same binary (same hash, or same signer and path) run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? | `entity.baseline` | high | An attacker's own binary can be run on several days to build history; baselines default to high (capability-spec). |
| Q-0011 | Is the binary that opened LSASS validly signed by a trusted publisher and not on the dump-capable exclusion list? | `file.signer` | low | OS-verified code signature; dump-capable signed binaries are excluded. |
| Q-0012 | Has this user run the same normalized command line on any host on at least the customer's minimum number of distinct days in the lookback before the alert window? | `entity.baseline` | high | The command line is attacker-chosen; copying a routine one is enough. |
| Q-0013 | Is the acting process a sanctioned deployment or management tool, matched on hash or on signer plus path? | `list.lookup` | low | Matched on hash or OS-verified signer plus path. |
| Q-0014 | Has the same normalized command line, with the same parent binary (hash or signer plus path), run on this host on at least the customer's minimum number of distinct days in the lookback before the alert window? | `entity.baseline` | high | The command line is attacker-chosen; a routine command can be replayed or its script tampered with. |
| Q-0015 | Has the same normalized command line, from the same parent binary, run on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? | `org.prevalence` | high | The command line is attacker-chosen; a fleet-wide routine command can be reused or its script tampered with. |
| Q-0016 | Is the host on the customer's list of hosts whose role requires RDP? | `list.lookup` | none | Asset-role record maintained by IT. |
| Q-0017 | Is every URL host in the command line an internal or approved download domain? | `list.lookup` | low | The attacker chooses the URL but must host content on an approved domain; keep the list to customer-controlled domains. |
| Q-0018 | Has the same registry value name with the same normalized data been written on at least the customer's minimum number of hosts in at least the customer's minimum number of the weeks examined before the alert window? | `org.prevalence` | high | Registry value name and data are attacker-chosen; copying a common autostart entry is enough. |
| Q-0019 | Is the subject binary validly signed by a trusted publisher and not on the excluded-binaries list? | `file.signer` | low | OS-verified code signature; LOLBins, script hosts and dump tools are excluded. |
| Q-0020 | Was the account created or added to local Administrators by a provisioning service account? | `list.lookup` | low | The acting account is recorded by the directory, but a compromised provisioning account would match. |
| Q-0021 | Is the parent process sanctioned backup software, matched on hash or on signer plus path? | `list.lookup` | low | Matched on hash or OS-verified signer plus path. |
| Q-0022 | Is every exclusion value in the command line on the customer's approved antivirus exclusion list for this host? | `list.lookup` | low | The exclusion value is attacker-chosen, but a match means the exclusion is already approved. |
| Q-0023 | Is the host in a rebuilding or decommissioning state in the asset inventory at the alert time? | `list.lookup` | none | Asset lifecycle record maintained by IT. |
| Q-0024 | Does the driver's SHA256 match a known vulnerable or malicious driver sample? | `file.reputation` | low | Driver hash comes from the OS driver-load record. |
| Q-0025 | Is there an unexpired approved exception for this driver's SHA256 on this host? | `list.lookup` | low | Exception keyed on driver hash and host. |
| Q-0026 | Does an authorized security test engagement cover this host or user at the alert time? | `list.lookup` | low | Approved engagement record, but a real attacker active on an in-scope host during the window would also match. |
| Q-0027 | Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.class` | low, forwarded medium | Set by the security control, not by the activity. |
| Q-0028 | Is the detection in a low-risk class (potentially unwanted software, adware, grayware), and not a test file? | `alert.class` | low, forwarded medium | Class assigned by the product; high-risk families are excluded by the earlier step. |
| Q-0029 | Is the detection in a high-risk family (hack tool, credential dumper, ransomware, web shell, exploit framework, remote access trojan or remote-admin tool, miner, proxyware, crack)? | `alert.class` | low, forwarded medium | Class and name assigned by the product. |
| Q-0030 | Is the alert's file hash known bad in a reputation source? | `file.reputation` | low | Hash comes from the product's own record of the file. |
| Q-0031 | Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | Source address of an established session is hard to spoof; single-packet (UDP or ICMP) signatures can be spoofed, and a compromised scanner would match. |
| Q-0032 | Is the source address known bad in a reputation source? | `ip.reputation` | low | Address comes from the network record. |
| Q-0033 | Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | Vulnerability data is collected independently of the attack; it can be stale or miss unmanaged software. |
| Q-0034 | Is any URL or domain in the alert known bad in a reputation source? | `url.reputation` | low | URL comes from the alert record. |
| Q-0035 | Is the message quarantined or removed from every recipient mailbox? | `email.message_status` | low | Mailbox state comes from the mail platform; the sender cannot change it. |
| Q-0036 | Do click and open records show that no recipient followed a link or opened an attachment from the message (unknown when it carried an attachment and attachment opens are not recorded on every recipient's host)? | `email.no_interaction` | medium | Click and open records come from the mail platform; clicks outside its rewriting (copied links, other devices) and attachments opened from a local copy are missed, so an absence of records is not evidence on its own (round 6, B2). |
| Q-0037 | Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker inside the campaign window? | `list.lookup` | low | Requires both the simulation's sending address and its secret marker header; sender domain alone never matches. |
| Q-0038 | Does an approved, unexpired DLP exception cover this user, policy and destination? | `list.lookup` | none | Approved exception record with an owner and expiry. |
| Q-0039 | Is the destination an internal or tenant domain, or an approved partner domain for this data class? | `list.lookup` | low | The sender picks the destination, but it must be an approved partner domain. |
| Q-0041 | Is the blocked site in a low-risk web category (advertising, streaming media, social networking, games, shopping, entertainment, sports, travel, news and media)? | `alert.class` | low, forwarded medium | Category assigned by the filtering service; the block is checked first. |
| Q-0042 | Was every connection from the source address in the last 24 hours, up to the alert time, denied, with none allowed or established, to any destination? | `traffic.denied_only` | low | Session outcomes come from the network control's own records. |
| Q-0043 | Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | Approved exception record with an owner and expiry. |
| Q-0044 | Did the alert record no file written to the device? | `alert.measure` | low | Recorded by the endpoint control, not by the user. |
| Q-0045 | Have at least the customer's threshold of earlier alerts with this fingerprint already fired in the triage window? | `alert.history` | none | Counts alerts already raised; the activity cannot remove them. |
| Q-0046 | Have at least the customer's threshold of earlier alerts with the same key already fired in the triage window? | `alert.history` | none | Counts alerts already raised; the activity cannot remove them. |
| Q-0047 | Has this client hit at least the customer's threshold of distinct rules in the triage window? | `alert.history` | none | Counts alerts already raised. |
| Q-0048 | Is the detected file approved security tooling on this host (by hash, or signer plus path while the file is readable), or is the host an approved sandbox or analysis host? | `list.lookup` | low | Matched on hash or signer plus path and scoped by asset ID, which a host rename cannot change; analysis hosts are a deliberate, listed exception. |
| Q-0049 | Was the file blocked before it executed? | `endpoint.run_status` | low, forwarded medium | Recorded by the endpoint product. |
| Q-0050 | Is the source address inside the customer's internal networks? | `list.lookup` | none | Compared with the customer's own address plan. |
| Q-0051 | Is this signature or rule on the customer's tuned list for this source and destination (or application)? | `list.lookup` | none | Approved tuning record with reason and expiry; never matched on signature alone. |
| Q-0052 | Was an approved scan job from this scanner targeting this address running at the alert time? | `scan.job_active` | none | Scan job records come from the scanner platform, not from the traffic. |
| Q-0053 | Is the signature in an exploit, intrusion or malware class? | `alert.class` | low, forwarded medium | Class assigned by the signature vendor. |
| Q-0054 | Did the application answer the request with a success status? | `alert.class` | low, forwarded medium | Recorded by the WAF. |
| Q-0055 | Does an approved change or test-engagement record name this source address and cover the alert time? | `change.window` | low | Approved change or test-engagement records the traffic cannot touch; a yes needs an approver who is not an implementer. |
| Q-0056 | Is the source an approved infrastructure source (monitoring, backup, replication, health check) for this destination and port? | `list.lookup` | medium | The source address of a deny alert can be spoofed, and an attacker who holds an approved infrastructure host probes from a listed source (round 6, S3). It cannot carry a close on its own: the close also needs every connection from the source denied (Q-0042), with no burst (Q-0046). |
| Q-0057 | Is the blocked site in a high-risk web category (malware, phishing, command and control, botnet, newly registered and similar listed categories)? | `alert.class` | low, forwarded medium | Category assigned by the filtering service. |
| Q-0058 | Is the user agent a mainstream browser? | `alert.class` | high | The user agent is set by the client; malware copies browser strings. |
| Q-0059 | Is the site's category anything other than uncategorised? | `alert.class` | low | Category assigned by the filtering service. |
| Q-0060 | Has this host requested this domain on at least the customer's minimum number of distinct days in the lookback before the alert window? | `entity.baseline` | high | Beaconing malware builds this history; the block and browser checks carry the close. |
| Q-0061 | Is the flagged content a known DLP test file or template, by content hash? | `list.lookup` | low | Content hash; sending the exact test file gains nothing. |
| Q-0062 | Is the DLP action final (blocked or deleted), rather than held, quarantined or pending release? | `alert.class` | low, forwarded medium | Recorded by the DLP control. |
| Q-0063 | Is the DLP severity high or critical? | `alert.class` | low | Set by the DLP policy. |
| Q-0064 | Does the event carry at least the customer's record-count threshold of matches? | `alert.measure` | low | Counted by the DLP control. |
| Q-0065 | Is the device-control event a device connection (not a file write)? | `alert.class` | low | Recorded by the endpoint control. |
| Q-0066 | Is the device a non-storage class (keyboard, mouse, composite, network adapter)? | `alert.class` | low | Reported by the device; a malicious device can lie about its class, which is why a yes flags. |
| Q-0067 | Is the host a server or a crown-jewel asset? | `context.rule` | low | Crown-jewel list and asset class from the customer's asset data; an unanswered asset class counts as a server, so a gap raises, never lowers. |
| Q-0068 | Were at least the customer's threshold of files written in this event? | `alert.measure` | low | Counted by the endpoint control. |
| Q-0069 | Is the device-control event a file write to the device? | `alert.class` | low | Recorded by the endpoint control. |
| Q-0070 | Did the message pass DMARC with an aligned SPF or DKIM pass for its From domain? | `email.auth` | low | Authentication is checked by the receiving mail system; a compromised legitimate sender still passes. |
| Q-0071 | Is the From domain on the customer's approved-sender list (external transactional-notification senders only; the customer's own domains never count)? | `list.lookup` | high | The From domain is chosen by the sender; only the authentication guard makes it trustworthy, and an approved sender's compromised mailbox still passes it (kept high, stricter than the medium the round 6 review asked for). |
| Q-0072 | Does the message contain no URL and no attachment? | `alert.measure` | low | Counted from the message as delivered. |
| Q-0073 | Was the file's hash seen in the last 24 hours, up to the alert time, on any host outside the approved security-tooling and analysis hosts? | `org.prevalence` | low | Hash sightings across the fleet come from sensors; used only as a guard that escalates. |
| Q-0074 | Did the email control stop the message before it reached the recipient (blocked, rejected, or quarantined before delivery)? | `alert.class` | low, forwarded medium | Set by the security control, not by the activity. |
| Q-0075 | Is the From domain one of the customer's own email domains? | `list.lookup` | high | The From domain is chosen by the sender. Used only as a guard that flags; a yes never supports a close. |
| Q-0076 | What is the highest severity of any other alert on a host of any recipient of the message in the last 24 hours? | `alert.recipient_hosts_severity` | none | Severity of alerts already raised. Used only as a guard that flags; it never supports a close. |

## Context facts used

Supply effort is how hard a low-maturity customer finds it to provide the fact. These ratings are a draft judgement by the bank author, not measured; first onboardings should correct them.

| Fact | Name | Supply effort (draft) | Why |
|---|---|---|---|
| CF-0001 | sanctioned_deployment_tools | medium | Needs each tool's hash, or signer plus install path. |
| CF-0002 | it_admin_accounts | low | Export of directory groups. |
| CF-0003 | change_windows | high | Needs change records that name the hosts and the implementer; many customers have none. |
| CF-0004 | sanctioned_lsass_accessors | medium | Needs signer plus path for each security tool that opens LSASS. |
| CF-0005 | known_benign_lsass_accessors | low | Supplied by the bank; the customer only confirms the entries. |
| CF-0006 | sanctioned_remote_access_tools | medium | Needs signer plus path for each approved remote-access tool. |
| CF-0007 | crown_jewel_assets | low | Static list of hosts and accounts; Phase 0 requires crown jewels to be listed before triage starts, and context question C-06 reads it. |
| CF-0008 | trusted_code_signers | low | Short list of trusted publishers. |
| CF-0009 | rdp_allowed_hosts | low | Static host list. |
| CF-0010 | approved_download_domains | low | Static domain list. |
| CF-0011 | sanctioned_backup_tools | medium | Needs signer plus path for each backup tool. |
| CF-0012 | approved_av_exclusions | medium | Exclusions are exported from the console, but approvals are often undocumented. |
| CF-0013 | provisioning_service_accounts | low | Static account list. |
| CF-0014 | authorized_security_tests | medium | Per-engagement scope and window, kept current. |
| CF-0015 | asset_lifecycle_status | high | Needs a maintained asset inventory with lifecycle state. |
| CF-0016 | known_bad_driver_samples | low | Supplied by the bank. |
| CF-0017 | approved_driver_exceptions | medium | Needs a hash and host per accepted driver. |
| CF-0018 | approved_scanners | low | Static scanner addresses and schedule. |
| CF-0019 | phishing_simulations | medium | Needs sending address, campaign marker and window per campaign. |
| CF-0020 | dlp_exceptions | medium | Needs approval records with owner and expiry. |
| CF-0021 | approved_partner_domains | low | Static domain list. |
| CF-0022 | removable_media_exceptions | medium | Needs approval records with device class and expiry. |
| CF-0023 | approved_security_tooling | medium | Needs hashes or signer plus path, and asset IDs. |
| CF-0024 | tuned_signatures | medium | Built up from tuning decisions; starts empty. |
| CF-0025 | approved_infrastructure_sources | low | Static source addresses with destinations and ports. |
| CF-0026 | approved_senders | low | Short list of sender domains. |
| CF-0027 | dlp_test_data | low | Hashes of a few test files. |
| CF-0028 | internal_domains | low | Static domain list. |
| CF-0031 | internal_networks | low | Network teams keep this list; the private ranges are a sensible default until they confirm it. |
| CF-0032 | own_email_domains | low | The mail platform's accepted-domain list, read at onboarding. |

## Capabilities used

| Capability | Answer | Meaning | Escalate only |
|---|---|---|---|
| `alert.class` | enum | The class of an alert value, from the reporting control's value table (bank/broker/translations/): the table maps the product's raw value to one of the class's fixed values (alert_classes below). A raw value no table row matches maps to the class's default. | no |
| `alert.history` | count | Earlier alerts that already fired inside the triage window and share the key (or, with distinct, the number of distinct values of that role among them). | no |
| `alert.measure` | number | A number the reporting control recorded on the alert (for example files written, records matched, indicators in a message). | no |
| `alert.recipient_hosts_severity` | enum | The highest normalized severity (bank/contract/severity.yaml) of any other alert, over the look-back ending at the alert time, on any host of any recipient of the message (the hosts the directory or asset inventory links to each recipient); none when there is none. Unknown when a recipient's hosts cannot be resolved (round 6, B2). | no |
| `change.window` | bool | An approved change covers one of the entities at at_time and lists user, or a group user belongs to, as an implementer, and the change's approver is not one of its implementers. | no |
| `context.rule` | bool | The question's context_rule holds over the cached context answers it reads (for example C-06 or C-08). An unanswered context question takes its when_not_answered value, which always raises. | no |
| `email.auth` | bool | The message passed DMARC with an aligned SPF or DKIM pass for its From domain. | no |
| `email.message_status` | bool | The message is quarantined or removed from every recipient mailbox now. | no |
| `email.no_interaction` | bool | Click and attachment-open records show no recipient followed a link or opened an attachment from the message. | no |
| `endpoint.run_status` | enum | Whether the detected file was stopped before it ran, from the endpoint product's own record of the alert. The broker finds the vendor's alert by vendor_alert_id; if that is missing, by endpoint_device (or host), file hash and a time window of match_window_minutes around at_time. No match, or more than one, answers unknown. The vendor's run-status values map through its API value table (bank/broker/translations/, source edr_api). | no |
| `entity.baseline` | count | Distinct days in the lookback, ending before the triage window, on which the entity showed the same behavior. | no |
| `file.reputation` | bool | A reputation source (including bank seed lists such as known-bad driver samples) marks the file's hash as known vulnerable or malicious. | yes |
| `file.signer` | bool | The file has a valid code signature from a publisher on trusted_list and the binary is not on that list's excluded_binaries. | no |
| `identity.groups` | bool | The account is one of, or a direct or nested member of, the named accounts or groups. | no |
| `ip.reputation` | bool | A reputation source marks the IP as malicious. | yes |
| `list.lookup` | bool | The entity matches an entry of the named context list under that list's match_rule (file entities match on sha256, or signer plus path), the entry's host scope includes host when given, and the entry is in force at at_time when the list is time-bound. | no |
| `org.prevalence` | count | With of_weeks and min_weeks: the k-th lowest weekly count of distinct hosts showing the pattern over the of_weeks weeks before the alert window, with k = of_weeks - min_weeks + 1 (default 4 and 3, so the 2nd lowest). It is at least N exactly when at least min_weeks of the of_weeks weeks reach N hosts, so the Triage agent compares it with org_prevalence_min_hosts and no threshold reaches the broker. of_weeks and min_weeks set the statistic, not a threshold. With lookback_hours: distinct hosts showing it over the look-back ending at the alert time. Hosts in exclude_list (a context list's host scopes, by asset ID) are not counted. | no |
| `precedent.check` | bool | Q0, answered by the Triage agent from context questions C-02, C-03, C-04 and C-06 (bank/triage/context_rules.yaml q0): the fingerprint has an audited close, or (outside Auto) at least q0_min_independent_closes independent human closes, inside the validity window (human evidence only, bank/contract/evidence.yaml); no other alert on the entity has a higher normalized severity than this one; at most one distinct detection fired on the entity in the grouping window; the precedent entity is not a crown jewel. A mitigated precedent counts only when this alert was also stopped. | no |
| `scan.job_active` | bool | An approved scan job from this scanner address that targets this address was running at at_time. | no |
| `traffic.denied_only` | bool | Every connection from the source (to the destination, when given) over the look-back ending at the alert time was denied; none was allowed or established. | no |
| `url.reputation` | bool | A reputation source marks a URL or domain in the entity as malicious. | yes |
| `vuln.not_applicable` | bool | Vulnerability data no older than max_age shows the host is not affected by the vulnerability the signature targets (product or version absent, or patched). | no |
