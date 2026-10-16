# Review packet: batch-1-vendor-alerts

10 detections, 47 distinct questions, 16 capabilities. Everything is `status: draft`.

How to read a flow: steps run top to bottom; each answer leads to the next step, a close (with disposition and reason code), an escalation, or a flag to an analyst with no verdict. An unknown answer never closes. Q-0000 (precedent) runs first everywhere.

Guards run only when a step would close: each names a question and the answers that turn the close into a flag or an escalation (an unknown guard answer always flags, so the table lists only the triggering answers). A guard that fires on no means the close needs a yes from it.

Attacker influence rates how easily the activity under triage could produce a yes: **none** (records the attacker cannot touch, such as change tickets), **low** (OS-verified or control-recorded facts), **medium** (control-recorded facts that can be forged in transit, such as alerts forwarded over syslog), **high** (attacker-chosen strings such as process names, sender addresses or command lines). Every path to a close must rest on at least one yes rated none or low. Q-0000's rating is set per detection from its fingerprint fields.

## Changes since review

Applied from the decisions and the external review (first review of draft PR #6).

**Shared changes (pilot and batch 1)**
- New close grammar: **guards** on closing steps (flag or escalate; an unknown guard answer flags; a guard that fires on no means the close needs that yes). The call budget is now counted on the worst single path, steps plus guards.
- New attacker-influence level **medium**, and per-source ratings: alert-field checks drop to medium when the family's alerts arrive forwarded over syslog. Closes left without a none/low yes under that profile flag (42 close paths).
- **Q0**: every detection names a precedent entity and rates each fingerprint field. Q0's rating follows the least attacker-chosen field. email_gateway and user_reported_phishing are high, so the precedent flags. firewall_deny, ids_alert and waf_alert are medium, so the precedent close also needs a low yes from a guard (all denied, or blocked). A mitigated precedent is inherited only if the current alert was also blocked. Three or more earlier alerts with the same fingerprint → flag (all 61 flows).
- New capability **alert.history** (Q-0045/46/47): counts earlier alerts in the triage window by key; ≥ threshold → flag.
- **Internal sources** (customer internal_networks parameter, checked locally): firewall, IDS and WAF never close on denied, blocked or patched for them. IDS internal sources flag whatever the answer.
- **vuln.not_applicable** answers unknown when the signature maps to no CVE. Replay: 489 of 491 IDS events answered unknown with no_cve_mapping and flagged.
- Mitigated true positive never applies to high-risk families. Replay: test files (EICAR) flag or escalate and never close. Replay counts mitigated closes separately and fails on them only with --strict.
- Coverage value **generic** for vendor families covered only by vendor: detections (9 use cases). The onboarding step "Check vendor alerts are normalized" and the gate B check went to main (e9893a1). The note that synthetic-customer replay comes in batch 2 is in the brief.

**Per detection**
- av_detection: approved security tooling or analysis host first (hash or signer plus path, host-scoped). The high-risk pattern now covers remote-admin, miner, proxy and crack subfamilies and matches class plus name. A block before execution continues; post-execution, pending-reboot and partial states answer unknown and flag (mapping in docs/normalization.md). A forwarded block cannot close alone. ≥3 alerts on the host in the window → flag. A reputation hit escalates. Crown-jewel hosts flag through the permanent guardrail.
- dlp_match: known test data first. Only final blocks close; held or pending answers unknown and flags. ≥3 blocks for the user → flag. High severity or a record count over the threshold flags, even for exceptions and approved destinations. Internal and tenant domains were added to the approved-destination check.
- email_gateway: a block closes only if the message is out of every mailbox and no URL or attachment reputation hit exists (a hit flags). Delivered-then-removed needs the no-interaction check (a click escalates). The phishing-simulation check needs an aligned DMARC pass.
- firewall_deny: dest added to the fingerprint. The denied check covers the whole source. The approved scanner closes only while a scan job targeting dest runs (new **scan.job_active**). Approved infrastructure sources and a change ticket naming the source were added. Allowed connections elsewhere flag (previously escalated).
- ids_alert: tuned signatures (signature plus source and destination) were added. The block check comes before the vulnerability check. Exploit-class blocks flag. ≥5 alerts from the source → flag. Internal sources flag.
- proxy_block: high-risk categories escalate. A non-browser or empty user agent flags. ≥3 blocks from one host to one domain → flag. Uncategorised sites close only with a ≥3-day host-to-domain baseline and a browser user agent. The category lists are explicit parameters.
- removable_media: now connect events only; a new **vendor:removable_media_write** covers writes. A non-storage device class flags first. Servers and crown jewels escalate. A missing file count answers unknown. A file count over the threshold flags even with an exception. ≥3 blocks for the user → flag. The event type was added to the fingerprint.
- user_reported_phishing: no URL and no attachment → flag (possible business-email compromise). The simulation close needs an aligned DMARC pass (new **email.auth**), with the campaign marker and window matched. Approved senders with a DMARC pass close as a false report. A campaign key (sender domain plus URL domain) drives alert.history.
- waf_alert: uses the client address (forwarded-for hop appended by the customer's edge), not the edge. A block with a 2xx status flags. ≥5 distinct rules from one client → flag. Tuned rules (rule plus app) were added. QA and pentest sources need a change ticket. Generic rules get unknown at the vulnerability step and flag.

**Not applied**
- email_gateway approved sample mailboxes: no step left within five, and the call budget would be exceeded. Samples sent to an approved mailbox flag.
- DLP final-status lookup: no capability reads DLP release state yet. Held or pending items flag instead of being looked up.
- A business-email-compromise reply check: flags instead. A new capability for reply detection waits on a customer data source.
- "Regular-interval" repeats for proxy: alert.history counts repeats but does not test periodicity.
- The DLP user-to-destination baseline (Q-0040) was dropped to make room. An unapproved, unblocked destination now escalates.
- History on the AV host is not applied to the approved-analysis-host close: sandboxes are expected to produce bursts.

**Second review (of fc5fc4f)**
- IDS: "internal source → flag" now applies only to the blocked and patched (not applicable) closes and to the precedent close, which rests on a block. Tuned-signature and approved-scanner closes apply to internal sources again. The scanner close still needs scan.job_active = yes for this source and destination at alert time; unknown flags.
- DLP: an unblocked match to an unapproved destination now flags (was escalate). Three or more DLP alerts for the same user in the window now escalate, on every close (the earlier user-history guard flagged on the block close only).
- **Q-0040 deleted.** The DLP user-to-destination baseline was never approved and no flow used it.
- AV: approved tooling and analysis hosts now match on asset ID (`dest_asset_id`), never hostname. A new guard, Q-0073 (`org.prevalence`), escalates if the file's hash was seen in the alert window on any host outside CF-0023's approved hosts. A missing hash answers unknown and flags. `org.prevalence` gained `window` and `exclude_list` inputs for this; no new capability.
- Vendor value mapping: each row in docs/normalization.md is marked verified true or false; only the Defender rows are true. A detection whose family mapping has unverified rows is capped at Recommend (§4, enforced by validate), so vendor:av_detection has `max_mode: recommend` until the CrowdStrike rows are verified.
- Every context fact now has `supply_effort` (low, medium or high), a draft judgement listed under "Context facts used". rank_facts prints a "Quick wins first" table of low-effort facts, which is the onboarding form order for first customers.

## Gate results

- validate: PASS (35 detections, 26 technique fallbacks, 73 questions, 29 context facts, 21 capabilities: 0 errors, 0 warnings)
- attacker influence: PASS (781 close paths checked, 0 failing, in 0 flows; 42 closes flag under the forwarded profile)
- replay: PASS (replay: 533 TP events in 3 detections; 0 benign/FP closes, 0 mitigated closes -> PASS)

## Detections

### Antivirus or EDR malware detection (`vendor:av_detection`)

Generic: an antivirus or EDR product reports a malware detection on a host (normalized malware alert, any product).

Note: High-risk families escalate even when blocked. Only a block before execution can close, and only for low-risk classes; post-execution remediation, pending reboot and partial remediation flag. Test files flag. A block reported over forwarded syslog cannot close alone. Crown-jewel hosts flag through the permanent guardrail. Approved tooling and analysis hosts match on asset ID, never hostname; the file's hash seen on any other host in the window escalates.

Alert fields: dest, dest_asset_id, user, signature, category, action, file_hash, file_name, file_path, _time. Fingerprint: dest (low), signature (low), file_hash (low). Precedent entity: dest. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0029 yes → escalate |
| 2 | Q-0048: Is the detected file approved security tooling on this host (by hash, or signer plus path), or is the host an approved sandbox or analysis host? | `list.lookup` | low | close (benign true positive: approved_security_tooling) | next step | next step | Q-0073 yes → escalate |
| 3 | Q-0029: Is the detection in a high-risk family (hack tool, credential dumper, ransomware, web shell, exploit framework, remote access trojan or remote-admin tool, miner, proxyware, crack)? | `alert.field` | low, forwarded medium | **escalate** | next step | next step | – |
| 4 | Q-0049: Was the file blocked before it executed? | `alert.field` | low, forwarded medium | next step | **escalate** | flag to analyst | – |
| 5 | Q-0028: Is the detection in a low-risk class (potentially unwanted software, adware, grayware), and not a test file? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_low_risk_detection) | flag to analyst | flag to analyst | Q-0046 yes → flag; Q-0030 yes → escalate |

### DLP policy match (`vendor:dlp_match`)

Generic: a DLP control reports regulated data leaving through email, web, cloud storage or print (normalized DLP alert, any product).

Note: Held, quarantined and pending-release actions answer unknown and flag: a later release would undo them. High severity or a large record count flags even to approved destinations. Three or more DLP alerts for the same user in the window escalate. An unblocked match to an unapproved destination flags for an analyst.

Alert fields: src_user, dest, signature, object, action, severity, record_count, object_hash, _time. Fingerprint: src_user (low), signature (low), recipient_domain (high). Precedent entity: src_user. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0063 yes → flag; Q-0064 yes → flag; Q-0046 yes → escalate |
| 2 | Q-0061: Is the flagged content a known DLP test file or template, by content hash? | `list.lookup` | low | close (false positive: known_test_data) | next step | next step | Q-0046 yes → escalate |
| 3 | Q-0062: Is the DLP action final (blocked or deleted), rather than held, quarantined or pending release? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | flag to analyst | Q-0046 yes → escalate |
| 4 | Q-0038: Does an approved, unexpired DLP exception cover this user, policy and destination? | `list.lookup` | none | close (benign true positive: approved_business_exception) | next step | next step | Q-0063 yes → flag; Q-0064 yes → flag; Q-0046 yes → escalate |
| 5 | Q-0039: Is the destination an internal or tenant domain, or an approved partner domain for this data class? | `list.lookup` | low | close (benign true positive: approved_recipient) | flag to analyst | flag to analyst | Q-0063 yes → flag; Q-0064 yes → flag; Q-0046 yes → escalate |

### Email gateway threat alert (`vendor:email_gateway`)

Generic: an email security gateway reports a malicious or suspicious message, delivered or not (normalized email alert, any product).

Note: Every fingerprint field is sender-chosen, so a precedent only flags. A block closes only when the message is out of every mailbox and no reputation source marks its URL or attachment. Delivered-then-removed closes only with no recorded click or open.

Alert fields: src_user, recipient, subject, message_id, url, file_hash, action, _time. Fingerprint: src_user (high), subject (high), file_hash (high). Precedent entity: recipient. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | high | flag to analyst | next step | next step | – |
| 2 | Q-0037: Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker inside the campaign window? | `list.lookup` | low | close (benign true positive: authorized_phishing_simulation) | next step | next step | Q-0070 no → flag |
| 3 | Q-0035: Is the message quarantined or removed from every recipient mailbox? | `email.message_status` | low | next step | flag to analyst | flag to analyst | – |
| 4 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0034 yes → flag; Q-0030 yes → flag |
| 5 | Q-0036: Do click and open records show that no recipient followed a link or opened an attachment from the message? | `email.no_interaction` | low | close (mitigated true positive: contained_without_interaction) | **escalate** | flag to analyst | – |

### Firewall deny or port-scan alert (`vendor:firewall_deny`)

Generic: a firewall reports denied connections or a scan pattern from a source (normalized network-traffic alert, any product).

Note: Internal sources never close on denied traffic; they flag. The denied check covers every connection from the source, to any destination. An approved scanner closes only while a scan job targeting the destination was running. Allowed connections elsewhere from the source flag rather than escalate: they show the source is not only probing, not that the denied connection got through.

Alert fields: src, dest, dest_port, transport, action, rule, _time. Fingerprint: src (medium), dest (high), dest_port (high), rule (high). Precedent entity: src. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | medium | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0050 yes → flag; Q-0042 no → flag |
| 2 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step | Q-0052 no → flag |
| 3 | Q-0056: Is the source an approved infrastructure source (monitoring, backup, replication, health check) for this destination and port? | `list.lookup` | low | close (benign true positive: approved_infrastructure) | next step | next step | – |
| 4 | Q-0055: Does an approved change name this source address and cover the alert time? | `change.window` | none | close (benign true positive: approved_change) | next step | next step | – |
| 5 | Q-0042: Was every connection from the source address in the alert window denied, with none allowed or established, to any destination? | `traffic.denied_only` | low | close (mitigated true positive: denied_no_successful_connection) | flag to analyst | flag to analyst | Q-0050 yes → flag; Q-0032 yes → escalate |

### IDS or IPS signature alert (`vendor:ids_alert`)

Generic: a network IDS or IPS reports a signature match between a source and a target (normalized intrusion alert, any product).

Note: Internal sources never close on blocked or patched (not applicable); tuned-signature and approved-scanner closes still apply to them. The approved scanner closes only while its scan job targets this destination (unknown flags). Exploit, intrusion and malware classes flag when blocked; only reconnaissance and policy classes close on a block. Signatures with no vulnerability mapping answer unknown at the vulnerability step and flag.

Alert fields: src, dest, dest_port, signature, signature_id, category, severity, action, _time. Fingerprint: src (medium), dest (high), signature_id (high). Precedent entity: src. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | medium | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0050 yes → flag; Q-0046 yes → flag; Q-0053 yes → flag; Q-0027 no → flag |
| 2 | Q-0051: Is this signature or rule on the customer's tuned list for this source and destination (or application)? | `list.lookup` | none | close (false positive: tuned_signature) | next step | next step | Q-0046 yes → flag |
| 3 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step | Q-0052 no → flag; Q-0046 yes → flag |
| 4 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0053 yes → flag; Q-0050 yes → flag; Q-0046 yes → flag; Q-0032 yes → escalate |
| 5 | Q-0033: Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | close (mitigated true positive: signature_not_applicable) | **escalate** | flag to analyst | Q-0050 yes → flag; Q-0046 yes → flag; Q-0032 yes → escalate |

### Web proxy or URL-filter block (`vendor:proxy_block`)

Generic: a web proxy or URL filter blocks a request from a user or host (normalized web alert, any product).

Note: High-risk categories escalate even when blocked. A non-browser or empty user agent flags, and so do three or more blocks from one host to one domain in the window (repeat requests suggest a beacon). Uncategorised sites close only when the host visited them on at least 3 earlier days with a browser.

Alert fields: src, user, url, dest, category, action, http_user_agent, _time. Fingerprint: src (low), dest (high), category (low). Precedent entity: src. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0057 yes → escalate; Q-0058 no → flag |
| 2 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.field` | low, forwarded medium | next step | **escalate** | flag to analyst | – |
| 3 | Q-0057: Is the blocked site in a high-risk web category (malware, phishing, command and control, botnet, newly registered and similar listed categories)? | `alert.field` | low, forwarded medium | **escalate** | next step | next step | – |
| 4 | Q-0041: Is the blocked site in a low-risk web category (advertising, streaming media, social networking, games, shopping, entertainment, sports, travel, news and media)? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_low_risk_category) | next step | next step | Q-0058 no → flag; Q-0046 yes → flag; Q-0034 yes → escalate |
| 5 | Q-0060: Has this host requested this domain on at least 3 distinct days in the 30 days before the alert window? | `entity.baseline` | high | close (benign true positive: established_uncategorized_site) | flag to analyst | flag to analyst | Q-0059 yes → flag; Q-0058 no → flag; Q-0046 yes → flag; Q-0034 yes → escalate |

### Removable media (device control) alert (`vendor:removable_media`)

Generic: an endpoint device-control or DLP product reports removable storage connected (any product). File writes have their own detection.

Note: Connection events only; a write event flags here and belongs to vendor:removable_media_write. A non-storage device class flags first (possible keystroke injector). Servers and crown jewels escalate. A missing file count answers unknown and flags. Device serial numbers can be spoofed, so no approved-device list closes.

Alert fields: dest, user, device_id, device_class, event_type, action, files_written, _time. Fingerprint: dest (low), user (low), device_id (high), event_type (low). Precedent entity: dest. Precedent valid for 7d.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0065 no → flag; Q-0066 yes → flag; Q-0067 yes → escalate |
| 2 | Q-0066: Is the device a non-storage class (keyboard, mouse, composite, network adapter)? | `alert.field` | low | flag to analyst | next step | flag to analyst | – |
| 3 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0065 no → flag; Q-0067 yes → escalate; Q-0046 yes → flag |
| 4 | Q-0043: Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | close (benign true positive: approved_business_exception) | next step | next step | Q-0065 no → flag; Q-0067 yes → escalate; Q-0068 yes → flag |
| 5 | Q-0044: Did the alert record no file written to the device? | `alert.field` | low | close (benign true positive: no_data_transferred) | **escalate** | flag to analyst | Q-0065 no → flag; Q-0067 yes → escalate |

### Removable media file write (device control) alert (`vendor:removable_media_write`)

Generic: an endpoint device-control or DLP product reports files written to removable storage (any product).

Note: Write events only. Blocked writes and approved exceptions close; more files than the customer's threshold flag even with an exception. Non-storage devices flag; servers and crown jewels escalate.

Alert fields: dest, user, device_id, device_class, event_type, action, files_written, _time. Fingerprint: dest (low), user (low), device_id (high), event_type (low). Precedent entity: dest. Precedent valid for 7d.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0069 no → flag; Q-0066 yes → flag; Q-0067 yes → escalate |
| 2 | Q-0066: Is the device a non-storage class (keyboard, mouse, composite, network adapter)? | `alert.field` | low | flag to analyst | next step | flag to analyst | – |
| 3 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0069 no → flag; Q-0067 yes → escalate; Q-0046 yes → flag |
| 4 | Q-0043: Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | close (benign true positive: approved_business_exception) | **escalate** | flag to analyst | Q-0069 no → flag; Q-0067 yes → escalate; Q-0068 yes → flag |

### User-reported phishing email (`vendor:user_reported_phishing`)

Generic: a user reports an email as phishing through the report button or a reporting mailbox.

Note: The message id is sender-chosen, so a precedent only flags. A message with no URL and no attachment flags as possible business-email compromise. Simulation and approved-sender closes need an aligned DMARC pass. Repeat reports of one campaign (sender domain plus URL domain) flag.

Alert fields: message_id, user, src_user, sender_domain, recipient, subject, url, indicator_count, _time. Fingerprint: message_id (high). Precedent entity: message_id. Precedent valid for 7d.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | high | flag to analyst | next step | next step | – |
| 2 | Q-0037: Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker inside the campaign window? | `list.lookup` | low | close (benign true positive: authorized_phishing_simulation) | next step | next step | Q-0070 no → flag |
| 3 | Q-0072: Does the message contain no URL and no attachment? | `alert.field` | low | flag to analyst | next step | next step | – |
| 4 | Q-0071: Is the From domain on the customer's approved-sender list? | `list.lookup` | high | close (false positive: false_report) | next step | next step | Q-0070 no → flag; Q-0034 yes → escalate; Q-0046 yes → flag |
| 5 | Q-0036: Do click and open records show that no recipient followed a link or opened an attachment from the message? | `email.no_interaction` | low | close (mitigated true positive: contained_without_interaction) | **escalate** | flag to analyst | Q-0035 no → flag; Q-0046 yes → flag |

### Web application firewall alert (`vendor:waf_alert`)

Generic: a web application firewall reports a rule match on a request to a protected application (normalized web alert, any product).

Note: Uses the client address, not the edge address. A block with a success status flags. Internal clients never close on blocked or patched. Generic rules have no vulnerability mapping, so the vulnerability step answers unknown for them and flags. Five or more distinct rules from one client flag.

Alert fields: src, forwarded_for, dest, app, url, http_method, status, signature, action, _time. Fingerprint: client_ip (medium), app (high), signature (high). Precedent entity: client_ip. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |
|---|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | medium | close (inherit: precedent_match) | next step | next step | Q-0045 yes → flag; Q-0050 yes → flag; Q-0047 yes → flag; Q-0054 yes → flag; Q-0027 no → flag |
| 2 | Q-0051: Is this signature or rule on the customer's tuned list for this source and destination (or application)? | `list.lookup` | none | close (false positive: tuned_signature) | next step | next step | Q-0047 yes → flag |
| 3 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step | Q-0055 no → flag; Q-0047 yes → flag |
| 4 | Q-0027: Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.field` | low, forwarded medium | close (mitigated true positive: blocked_by_control) | next step | next step | Q-0054 yes → flag; Q-0050 yes → flag; Q-0047 yes → flag |
| 5 | Q-0033: Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | close (mitigated true positive: signature_not_applicable) | **escalate** | flag to analyst | Q-0050 yes → flag; Q-0047 yes → flag |

## Questions used

| Question | Text | Capability | Influence | Why |
|---|---|---|---|---|
| Q-0000 | Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, with the precedent entity not a crown jewel and no other alert on it in the window (a mitigated precedent only when this alert was also blocked)? | `case.precedent` | low | Default only; each detection rates Q0 from its fingerprint fields (step-level attacker_influence). |
| Q-0027 | Did the control that raised the alert stop the item (the file, connection, request or message) before it took effect? | `alert.field` | low, forwarded medium | Set by the security control, not by the activity. |
| Q-0028 | Is the detection in a low-risk class (potentially unwanted software, adware, grayware), and not a test file? | `alert.field` | low, forwarded medium | Class assigned by the product; high-risk families are excluded by the earlier step. |
| Q-0029 | Is the detection in a high-risk family (hack tool, credential dumper, ransomware, web shell, exploit framework, remote access trojan or remote-admin tool, miner, proxyware, crack)? | `alert.field` | low, forwarded medium | Class and name assigned by the product. |
| Q-0030 | Is the alert's file hash known bad in a reputation source? | `file.reputation` | low | Hash comes from the product's own record of the file. |
| Q-0031 | Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | Source address of an established session is hard to spoof; single-packet (UDP or ICMP) signatures can be spoofed, and a compromised scanner would match. |
| Q-0032 | Is the source address known bad in a reputation source? | `ip.reputation` | low | Address comes from the network record. |
| Q-0033 | Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | Vulnerability data is collected independently of the attack; it can be stale or miss unmanaged software. |
| Q-0034 | Is any URL or domain in the alert known bad in a reputation source? | `url.reputation` | low | URL comes from the alert record. |
| Q-0035 | Is the message quarantined or removed from every recipient mailbox? | `email.message_status` | low | Mailbox state comes from the mail platform; the sender cannot change it. |
| Q-0036 | Do click and open records show that no recipient followed a link or opened an attachment from the message? | `email.no_interaction` | low | Click and open records come from the mail platform; clicks outside its rewriting (copied links, other devices) can be missed. |
| Q-0037 | Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker inside the campaign window? | `list.lookup` | low | Requires both the simulation's sending address and its secret marker header; sender domain alone never matches. |
| Q-0038 | Does an approved, unexpired DLP exception cover this user, policy and destination? | `list.lookup` | none | Approved exception record with an owner and expiry. |
| Q-0039 | Is the destination an internal or tenant domain, or an approved partner domain for this data class? | `list.lookup` | low | The sender picks the destination, but it must be an approved partner domain. |
| Q-0041 | Is the blocked site in a low-risk web category (advertising, streaming media, social networking, games, shopping, entertainment, sports, travel, news and media)? | `alert.field` | low, forwarded medium | Category assigned by the filtering service; the block is checked first. |
| Q-0042 | Was every connection from the source address in the alert window denied, with none allowed or established, to any destination? | `traffic.denied_only` | low | Session outcomes come from the network control's own records. |
| Q-0043 | Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | Approved exception record with an owner and expiry. |
| Q-0044 | Did the alert record no file written to the device? | `alert.field` | low | Recorded by the endpoint control, not by the user. |
| Q-0045 | Have at least the customer's threshold (default 3) of earlier alerts with this fingerprint already fired in the triage window? | `alert.history` | none | Counts alerts already raised; the activity cannot remove them. |
| Q-0046 | Have at least the customer's threshold of earlier alerts with the same key already fired in the triage window? | `alert.history` | none | Counts alerts already raised; the activity cannot remove them. |
| Q-0047 | Has this client hit at least the customer's threshold (default 5) of distinct rules in the triage window? | `alert.history` | none | Counts alerts already raised. |
| Q-0048 | Is the detected file approved security tooling on this host (by hash, or signer plus path), or is the host an approved sandbox or analysis host? | `list.lookup` | low | Matched on hash or signer plus path and scoped by asset ID, which a host rename cannot change; analysis hosts are a deliberate, listed exception. |
| Q-0049 | Was the file blocked before it executed? | `alert.field` | low, forwarded medium | Recorded by the endpoint product. |
| Q-0050 | Is the source address inside the customer's internal networks? | `alert.field` | none | Compared with the customer's own address plan. |
| Q-0051 | Is this signature or rule on the customer's tuned list for this source and destination (or application)? | `list.lookup` | none | Approved tuning record with reason and expiry; never matched on signature alone. |
| Q-0052 | Was an approved scan job from this scanner targeting this address running at the alert time? | `scan.job_active` | none | Scan job records come from the scanner platform, not from the traffic. |
| Q-0053 | Is the signature in an exploit, intrusion or malware class? | `alert.field` | low, forwarded medium | Class assigned by the signature vendor. |
| Q-0054 | Did the application answer the request with a success status? | `alert.field` | low, forwarded medium | Recorded by the WAF. |
| Q-0055 | Does an approved change name this source address and cover the alert time? | `change.window` | none | Approved change record naming the source. |
| Q-0056 | Is the source an approved infrastructure source (monitoring, backup, replication, health check) for this destination and port? | `list.lookup` | low | Source address of a denied connection can be spoofed, but a spoofed probe gains the attacker nothing. |
| Q-0057 | Is the blocked site in a high-risk web category (malware, phishing, command and control, botnet, newly registered and similar listed categories)? | `alert.field` | low, forwarded medium | Category assigned by the filtering service. |
| Q-0058 | Is the user agent a mainstream browser? | `alert.field` | high | The user agent is set by the client; malware copies browser strings. |
| Q-0059 | Is the site's category anything other than uncategorised? | `alert.field` | low | Category assigned by the filtering service. |
| Q-0060 | Has this host requested this domain on at least 3 distinct days in the 30 days before the alert window? | `entity.baseline` | high | Beaconing malware builds this history; the block and browser checks carry the close. |
| Q-0061 | Is the flagged content a known DLP test file or template, by content hash? | `list.lookup` | low | Content hash; sending the exact test file gains nothing. |
| Q-0062 | Is the DLP action final (blocked or deleted), rather than held, quarantined or pending release? | `alert.field` | low, forwarded medium | Recorded by the DLP control. |
| Q-0063 | Is the DLP severity high or critical? | `alert.field` | low | Set by the DLP policy. |
| Q-0064 | Does the event carry at least the customer's record-count threshold of matches? | `alert.field` | low | Counted by the DLP control. |
| Q-0065 | Is the device-control event a device connection (not a file write)? | `alert.field` | low | Recorded by the endpoint control. |
| Q-0066 | Is the device a non-storage class (keyboard, mouse, composite, network adapter)? | `alert.field` | low | Reported by the device; a malicious device can lie about its class, which is why a yes flags. |
| Q-0067 | Is the host a server or a crown-jewel asset? | `list.lookup` | none | Asset inventory records. |
| Q-0068 | Were at least the customer's threshold of files written in this event? | `alert.field` | low | Counted by the endpoint control. |
| Q-0069 | Is the device-control event a file write to the device? | `alert.field` | low | Recorded by the endpoint control. |
| Q-0070 | Did the message pass DMARC with an aligned SPF or DKIM pass for its From domain? | `email.auth` | low | Authentication is checked by the receiving mail system; a compromised legitimate sender still passes. |
| Q-0071 | Is the From domain on the customer's approved-sender list? | `list.lookup` | high | The From domain is chosen by the sender; only the authentication guard makes it trustworthy. |
| Q-0072 | Does the message contain no URL and no attachment? | `alert.field` | low | Counted from the message as delivered. |
| Q-0073 | Was the file's hash seen in the alert window on any host outside the approved security-tooling and analysis hosts? | `org.prevalence` | low | Hash sightings across the fleet come from sensors; used only as a guard that escalates. |

## Context facts used

Supply effort is how hard a low-maturity customer finds it to provide the fact. These ratings are a draft judgement by the bank author, not measured; first onboardings should correct them.

| Fact | Name | Supply effort (draft) | Why |
|---|---|---|---|
| CF-0003 | change_windows | high | Needs change records that name the hosts and the implementer; many customers have none. |
| CF-0007 | crown_jewel_assets | low | Static list of hosts and accounts. |
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
| CF-0029 | server_assets | low | Server list from the asset inventory. |

## Capabilities used

| Capability | Yes means | Escalate only |
|---|---|---|
| `alert.field` | The alert's normalized field satisfies op against values. | no |
| `alert.history` | At least min_count earlier alerts that already fired inside the triage window share the key (the fingerprint, or a source, destination, user or campaign key); with distinct, at least min_count distinct values of that field among them. | no |
| `case.precedent` | An alert with the same fingerprint was closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason inside the validity window, the precedent entity is not a crown jewel, and no other alert hit that entity in the window. A precedent closed as mitigated_true_positive matches only when current_action shows the current alert was also blocked. | no |
| `change.window` | An approved change covers one of the entities at at_time and lists user, or a group user belongs to, as an implementer. | no |
| `email.auth` | The message passed DMARC with an aligned SPF or DKIM pass for its From domain. | no |
| `email.message_status` | The message is quarantined or removed from every recipient mailbox now. | no |
| `email.no_interaction` | Click and attachment-open records show no recipient followed a link or opened an attachment from the message. | no |
| `entity.baseline` | The entity showed the same behavior on at least min_days distinct days in the lookback, which ends before the alert window. | no |
| `file.reputation` | A reputation source (including bank seed lists such as known-bad driver samples) marks the file's hash as known vulnerable or malicious. | yes |
| `ip.reputation` | A reputation source marks the IP as malicious. | yes |
| `list.lookup` | The entity matches an entry of the named context list under that list's match_rule (file entities match on sha256, or signer plus path), the entry's host scope includes host when given, and the entry is in force at at_time when the list is time-bound. | no |
| `org.prevalence` | The pattern occurred on at least min_hosts distinct hosts, and in at least min_weeks of the of_weeks weeks before the alert window. With window alert_window, it counts hosts inside the alert window instead (min_weeks and of_weeks unused). Hosts in exclude_list (a context list's host scopes, by asset ID) are not counted. | no |
| `scan.job_active` | An approved scan job from this scanner address that targets this address was running at at_time. | no |
| `traffic.denied_only` | Every connection from src (to dest, when given) in the alert window was denied; none was allowed or established. | no |
| `url.reputation` | A reputation source marks a URL or domain in the entity as malicious. | yes |
| `vuln.not_applicable` | Vulnerability data no older than max_age shows the host is not affected by the vulnerability the signature targets (product or version absent, or patched). | no |
