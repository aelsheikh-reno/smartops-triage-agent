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

**Round 2 changes (Fable's review numbering)**

| Fable item | What changed |
|---|---|
| #1 DLP (blocker) | Q-0046 (3 or more alerts for the user) is now a flag guard on the benign closes: precedent, known test data, approved exception, approved partner or internal domain. It stays an escalate guard on the block close. It is added as an escalate guard on the unblocked, unapproved-destination flag. Q-0061 (test data) stays a step. |
| #2 IDS and WAF (blocker) | Alert-history guards (Q-0046 for IDS, Q-0047 for WAF) are removed from the tuned-signature and approved-scanner closes. They stay on the blocked and not-applicable closes. |
| #3 Guard semantics | Guards can attach to close and flag outcomes (`applies_to`), and only raise: close becomes flag or escalate, flag becomes escalate. All applicable guards run and the strongest wins, whatever their order. validate rejects a guard on an escalate outcome and a guard result no stronger than its outcome. It counts guard calls in the 6-call path budget, deduplicating identical calls. Design doc §5 and §9 and `guard_semantics` are updated. |
| #4 Email and user-reported phishing | Q0 `on_yes` is now `next`: a high-rated precedent proceeds and never flags by itself. |
| #5 AV Q-0073 | Split by CF-0023 entry type (`if_entry_type`). For analysis hosts, a hash seen outside the list escalates (unchanged). For approved tooling, it flags. |
| #6 AV fingerprint | The fingerprint and precedent entity use `dest_asset_id`. Without it they fall back to `dest`, and Q0 drops to its fallback rating, medium; the redteam reports 1 precedent close that flags under fallback. `dest_asset_id` is now an optional alert field. |
| #7 Q-0048 | Binds `file:file_path` so the Tool Broker can resolve the signer, alongside the alert's hash. A quarantined or unresolvable file answers unknown, which now flags (`on_unknown: flag`). CF-0023 states that AV entries match on hash, or on signer plus path while the file is readable. |
| #8 Removable media | Q-0044 (no files written) carries `needs.coverage: device_control_write_events`. Without write events from the same product in the coverage report, it is no_capability and flags. |
| #9 Scanners vs testers | Pentest and red-team engagements must be logged as approved changes naming the testers' source addresses, or tester alerts flag (Q-0055 note, onboarding form). CF-0018 gains `entry_type` (scanner or tester). A scanner close needs Q-0052 (an active scan job). A tester close needs Q-0055 (a covering change or engagement record). This applies in IDS, firewall and WAF. In WAF, Q-0033 (vulnerability) is dropped and its step holds the tester path: Q-0055 closes as an authorized security test. An unblocked WAF request now flags. |
| #10 Approved senders | CF-0026 is limited to customer-controlled and transactional-notification domains (`sender_kind`); partner domains are out. |
| #11 Step order | In user_reported_phishing, the approved-sender check (step 3) now runs before the no-URL/no-attachment check (step 4). |
| #12 Proxy history | New parameter `proxy_history_min_count` (default 10) for Q-0045 and Q-0046 in proxy_block. |
| #13 Uncovered vendor detections | Issue opened; no code in this PR. |
| #14 org.prevalence | validate rejects `window` combined with `min_weeks`/`of_weeks`. |
| Follow-up to #7 | AV step 2 unknown now continues (regression from #7 fix): a missing or unresolvable hash means the approved-tooling close can't apply, and the flow goes on to the high-risk and pre-execution checks. The replay gate has two regression cases that require high-risk alerts with no hash to escalate. |
| #15 Cloud-share exfiltration | Issue opened for batch 2; no code in this PR. |
| Decision d: per-customer AV cap | The family-wide `max_mode: recommend` is replaced by `auto_requires: [vendor_mapping_verified]`. A detection is capped at Recommend for each customer whose product rows for its family are unverified, recorded by the onboarding check "Check vendor alerts are normalized". validate requires the declaration for any family with unverified rows. |

**Where we did not follow Fable's fix**
- **#1, step placement.** Known test data (Q-0061) stays its own step instead of being moved. A guard can only raise, so a test-data close needs a step. Running it early also means a known test file never reaches the exception and partner checks.
- **#5, analysis hosts.** Only approved-tooling entries drop to flag. For analysis-host entries, a hash seen outside the list still escalates: a sample from a sandbox appearing on a production host means it escaped containment.

**Other effects worth knowing**
- AV replay: the 1116 EICAR event (no hash, detected but not blocked) escalates again after the follow-up fix (it briefly flagged at Q-0048 after #7).
- WAF: an unblocked request now flags (before, it reached the vulnerability step, which flagged generic rules and escalated affected hosts).
