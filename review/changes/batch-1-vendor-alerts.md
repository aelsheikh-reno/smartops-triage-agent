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
