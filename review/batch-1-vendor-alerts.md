# Review packet: batch-1-vendor-alerts

9 detections, 19 distinct questions, 11 capabilities. Everything is `status: draft`.

How to read a flow: steps run top to bottom; each answer leads to the next step, a close (with disposition and reason code), an escalation, or a flag to an analyst with no verdict. An unknown answer never closes. Q-0000 (precedent) runs first everywhere.

Attacker influence rates how easily the activity under triage could produce a yes: **none** (records the attacker cannot touch, such as change tickets), **low** (OS-verified or control-recorded facts), **high** (attacker-chosen strings such as process names or command lines). Every path to a close must rest on at least one yes rated none or low.

## Gate results

- validate: PASS (34 detections, 26 technique fallbacks, 45 questions, 22 context facts, 18 capabilities: 0 errors, 0 warnings)
- attacker influence: PASS (718 close paths checked, 0 failing, in 0 flows)
- replay: PASS (replay: 533 TP events in 3 detections; 0 benign/FP closes, 0 mitigated closes -> PASS)

## Detections

### Antivirus or EDR malware detection (`vendor:av_detection`)

Generic: an antivirus or EDR product reports a malware detection on a host (normalized malware alert, any product).

Note: A blocked detection outside the low-risk classes flags rather than closes: the analyst checks where it came from. High-risk classes escalate even when blocked.

Alert fields: dest, user, signature, category, action, file_hash, file_name, file_path, _time. Fingerprint: dest, signature, file_hash. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0027: Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | next step | **escalate** | flag to analyst |
| 3 | Q-0029: Is the detection in a high-risk class (hacktool, credential theft, ransomware, web shell, exploit, remote access trojan, backdoor)? | `alert.field` | low | **escalate** | next step | next step |
| 4 | Q-0028: Is the detection in a low-risk class (potentially unwanted software, adware, grayware)? | `alert.field` | low | close (mitigated true positive: blocked_low_risk_detection) | next step | next step |
| 5 | Q-0030: Is the alert's file hash known bad in a reputation source? | `file.reputation` | low | **escalate** | flag to analyst | flag to analyst |

### DLP policy match (`vendor:dlp_match`)

Generic: a DLP control reports regulated data leaving through email, web, cloud storage or print (normalized DLP alert, any product).

Note: The user's own sending history can only flag, never close: an insider builds that baseline.

Alert fields: src_user, dest, signature, object, action, severity, _time. Fingerprint: src_user, signature, recipient_domain. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0027: Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | close (mitigated true positive: blocked_by_control) | next step | next step |
| 3 | Q-0038: Does an approved, unexpired DLP exception cover this user, policy and destination? | `list.lookup` | none | close (benign true positive: approved_business_exception) | next step | next step |
| 4 | Q-0039: Is the destination domain an approved partner for this data class? | `list.lookup` | low | close (benign true positive: approved_recipient) | next step | next step |
| 5 | Q-0040: Has this user sent the same data class to the same destination on at least 3 distinct days in the 30 days before the alert window? | `entity.baseline` | high | flag to analyst | **escalate** | flag to analyst |

### Email gateway threat alert (`vendor:email_gateway`)

Generic: an email security gateway reports a malicious or suspicious message, delivered or not (normalized email alert, any product).

Alert fields: src_user, recipient, subject, message_id, url, file_hash, action, _time. Fingerprint: src_user, subject, file_hash. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0027: Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | close (mitigated true positive: blocked_by_control) | next step | next step |
| 3 | Q-0034: Is any URL or domain in the alert known bad in a reputation source? | `url.reputation` | low | **escalate** | next step | next step |
| 4 | Q-0030: Is the alert's file hash known bad in a reputation source? | `file.reputation` | low | **escalate** | next step | next step |
| 5 | Q-0035: Is the message quarantined or removed from every recipient mailbox? | `email.message_status` | low | close (mitigated true positive: removed_after_delivery) | flag to analyst | flag to analyst |

### Firewall deny or port-scan alert (`vendor:firewall_deny`)

Generic: a firewall reports denied connections or a scan pattern from a source (normalized network-traffic alert, any product).

Alert fields: src, dest, dest_port, transport, action, rule, _time. Fingerprint: src, dest_port, rule. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step |
| 3 | Q-0032: Is the source address known bad in a reputation source? | `ip.reputation` | low | **escalate** | next step | next step |
| 4 | Q-0042: Was every connection from the source in the alert window denied, with none allowed or established? | `traffic.denied_only` | low | close (mitigated true positive: denied_no_successful_connection) | **escalate** | flag to analyst |

### IDS or IPS signature alert (`vendor:ids_alert`)

Generic: a network IDS or IPS reports a signature match between a source and a target (normalized intrusion alert, any product).

Alert fields: src, dest, dest_port, signature, signature_id, severity, action, _time. Fingerprint: src, dest, signature_id. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step |
| 3 | Q-0032: Is the source address known bad in a reputation source? | `ip.reputation` | low | **escalate** | next step | next step |
| 4 | Q-0033: Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | close (mitigated true positive: signature_not_applicable) | next step | next step |
| 5 | Q-0027: Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | close (mitigated true positive: blocked_by_control) | **escalate** | flag to analyst |

### Web proxy or URL-filter block (`vendor:proxy_block`)

Generic: a web proxy or URL filter blocks a request from a user or host (normalized web alert, any product).

Note: Blocks in high-risk categories (malware, phishing, command and control, newly registered) flag: the host may be infected even though the request was stopped.

Alert fields: src, user, url, dest, category, action, http_user_agent, _time. Fingerprint: src, dest, category. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0027: Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | next step | **escalate** | flag to analyst |
| 3 | Q-0034: Is any URL or domain in the alert known bad in a reputation source? | `url.reputation` | low | **escalate** | next step | next step |
| 4 | Q-0041: Is the blocked site in a low-risk web category (advertising, streaming, social and similar)? | `alert.field` | low | close (mitigated true positive: blocked_low_risk_category) | flag to analyst | flag to analyst |

### Removable media (device control) alert (`vendor:removable_media`)

Generic: an endpoint device-control or DLP product reports removable storage connected or used (any product).

Note: Device serial numbers can be spoofed by programmable USB devices, so an approved-device list is not used to close.

Alert fields: dest, user, device_id, device_class, action, files_written, _time. Fingerprint: dest, user, device_id. Precedent valid for 7d.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0027: Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | close (mitigated true positive: blocked_by_control) | next step | next step |
| 3 | Q-0043: Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | close (benign true positive: approved_business_exception) | next step | next step |
| 4 | Q-0044: Did the alert record no file written to the device? | `alert.field` | low | close (benign true positive: no_data_transferred) | **escalate** | flag to analyst |

### User-reported phishing email (`vendor:user_reported_phishing`)

Generic: a user reports an email as phishing through the report button or a reporting mailbox.

Note: Repeat reports of the same message attach to the open case through the fingerprint. A clean scanning verdict is not used to close: it is the easiest signal for an attacker to game.

Alert fields: message_id, user, src_user, recipient, subject, url, _time. Fingerprint: message_id. Precedent valid for 7d.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0037: Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker? | `list.lookup` | low | close (benign true positive: authorized_phishing_simulation) | next step | next step |
| 3 | Q-0034: Is any URL or domain in the alert known bad in a reputation source? | `url.reputation` | low | **escalate** | next step | next step |
| 4 | Q-0035: Is the message quarantined or removed from every recipient mailbox? | `email.message_status` | low | next step | flag to analyst | flag to analyst |
| 5 | Q-0036: Do click and open records show that no recipient followed a link or opened an attachment from the message? | `email.no_interaction` | low | close (mitigated true positive: contained_without_interaction) | **escalate** | flag to analyst |

### Web application firewall alert (`vendor:waf_alert`)

Generic: a web application firewall reports a rule match on a request to a protected application (normalized web alert, any product).

Alert fields: src, dest, url, http_method, status, signature, action, _time. Fingerprint: src, dest, signature. Precedent valid for 24h.

| Step | Question | Capability | Influence | Yes | No | Unknown |
|---|---|---|---|---|---|---|
| 1 | Q-0000: Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | close (inherit: precedent_match) | next step | next step |
| 2 | Q-0031: Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | close (benign true positive: approved_scanner_activity) | next step | next step |
| 3 | Q-0032: Is the source address known bad in a reputation source? | `ip.reputation` | low | **escalate** | next step | next step |
| 4 | Q-0033: Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | close (mitigated true positive: signature_not_applicable) | next step | next step |
| 5 | Q-0027: Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | close (mitigated true positive: blocked_by_control) | **escalate** | flag to analyst |

## Questions used

| Question | Text | Capability | Influence | Why |
|---|---|---|---|---|
| Q-0000 | Was an alert with the same fingerprint closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason within the validity window, on an entity that is not a crown jewel, with no other alert on the entity in the window? | `case.precedent` | low | Fingerprint includes hashes and key attributes; an attacker must reproduce a previously closed fingerprint exactly. |
| Q-0027 | Did the control that raised the alert block, quarantine, clean or drop the item? | `alert.field` | low | Set by the security control, not by the activity; a product that misreports its action would mislead it. |
| Q-0028 | Is the detection in a low-risk class (potentially unwanted software, adware, grayware)? | `alert.field` | low | Class assigned by the product; an attacker can pick tooling the product classes as unwanted software, which is why a block is required first. |
| Q-0029 | Is the detection in a high-risk class (hacktool, credential theft, ransomware, web shell, exploit, remote access trojan, backdoor)? | `alert.field` | low | Class assigned by the product. |
| Q-0030 | Is the alert's file hash known bad in a reputation source? | `file.reputation` | low | Hash comes from the product's own record of the file. |
| Q-0031 | Is the source address an approved scanner or authorised tester, inside its scheduled window? | `list.lookup` | low | Source address of an established session is hard to spoof; single-packet (UDP or ICMP) signatures can be spoofed, and a compromised scanner would match. |
| Q-0032 | Is the source address known bad in a reputation source? | `ip.reputation` | low | Address comes from the network record. |
| Q-0033 | Does recent vulnerability data show the target is not affected by the vulnerability this signature targets? | `vuln.not_applicable` | low | Vulnerability data is collected independently of the attack; it can be stale or miss unmanaged software. |
| Q-0034 | Is any URL or domain in the alert known bad in a reputation source? | `url.reputation` | low | URL comes from the alert record. |
| Q-0035 | Is the message quarantined or removed from every recipient mailbox? | `email.message_status` | low | Mailbox state comes from the mail platform; the sender cannot change it. |
| Q-0036 | Do click and open records show that no recipient followed a link or opened an attachment from the message? | `email.no_interaction` | low | Click and open records come from the mail platform; clicks outside its rewriting (copied links, other devices) can be missed. |
| Q-0037 | Is the message part of an approved phishing-simulation campaign, matched on sending address and campaign marker? | `list.lookup` | low | Requires both the simulation's sending address and its secret marker header; sender domain alone never matches. |
| Q-0038 | Does an approved, unexpired DLP exception cover this user, policy and destination? | `list.lookup` | none | Approved exception record with an owner and expiry. |
| Q-0039 | Is the destination domain an approved partner for this data class? | `list.lookup` | low | The sender picks the destination, but it must be an approved partner domain. |
| Q-0040 | Has this user sent the same data class to the same destination on at least 3 distinct days in the 30 days before the alert window? | `entity.baseline` | high | The user's own past behaviour; an insider who has been exfiltrating for weeks has built the baseline. |
| Q-0041 | Is the blocked site in a low-risk web category (advertising, streaming, social and similar)? | `alert.field` | low | Category assigned by the filtering service; an attacker can host on a low-risk-categorised site, which is why a block is required first. |
| Q-0042 | Was every connection from the source in the alert window denied, with none allowed or established? | `traffic.denied_only` | low | Session outcomes come from the network control's own records. |
| Q-0043 | Does an approved, unexpired removable-media exception cover this user and device class? | `list.lookup` | none | Approved exception record with an owner and expiry. |
| Q-0044 | Did the alert record no file written to the device? | `alert.field` | low | Recorded by the endpoint control, not by the user. |

## Capabilities used

| Capability | Yes means | Escalate only |
|---|---|---|
| `alert.field` | The alert's normalized field holds one of the listed values (case-insensitive). | no |
| `case.precedent` | An alert with the same fingerprint was closed by an original decision (an analyst or a non-precedent flow step) with a recorded reason inside the validity window, the entity is not a crown jewel, and no other alert hit the entity in the window. | no |
| `email.message_status` | The message is quarantined or removed from every recipient mailbox now. | no |
| `email.no_interaction` | Click and attachment-open records show no recipient followed a link or opened an attachment from the message. | no |
| `entity.baseline` | The entity showed the same behavior on at least min_days distinct days in the lookback, which ends before the alert window. | no |
| `file.reputation` | A reputation source (including bank seed lists such as known-bad driver samples) marks the file's hash as known vulnerable or malicious. | yes |
| `ip.reputation` | A reputation source marks the IP as malicious. | yes |
| `list.lookup` | The entity matches an entry of the named context list under that list's match_rule (file entities match on sha256, or signer plus path), the entry's host scope includes host when given, and the entry is in force at at_time when the list is time-bound. | no |
| `traffic.denied_only` | Every connection from src (to dest, when given) in the alert window was denied; none was allowed or established. | no |
| `url.reputation` | A reputation source marks a URL or domain in the entity as malicious. | yes |
| `vuln.not_applicable` | Vulnerability data no older than max_age shows the host is not affected by the vulnerability the signature targets (product or version absent, or patched). | no |
