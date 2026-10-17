# Capability specification

Status: (designed, not built). The capabilities, measurements and Triage-side rules below are the design for the Tool Broker and recipes; none runs yet. Parameter bounds and rating changes marked as such are proposals for the next bank change.

One entry per capability in `bank/capabilities.yaml`. The list is the batch-1 set (PR #6), which adds `alert.field`, `url.reputation`, `vuln.not_applicable`, `email.*`, `traffic.denied_only`, `alert.history` and `scan.job_active` to the pilot set.

Each capability is split between the two sides of the broker (design-decisions §6):
- **Measures** is what the Tool Broker returns, with evidence.
- **Triage rule** is how the Triage agent turns that measurement into yes, no or unknown. Its threshold comes from the parameter table (§9).

No threshold lives in a recipe.

Parameter bounds are proposals. The bank does not carry minimums and maximums yet; the bank migration issue adds them to `bank/parameters.yaml`, and validation will reject values outside them. Lowering scrutiny (a lower count, a longer validity, a wider list) needs human approval with an owner and an expiry. Parameters marked *proposed* do not exist in the bank yet.

Template kinds (§7):
- **Sigma**: an event search compiled to SPL by pySigma with the customer's pipeline.
- **lookup**: a typed template against a list, lookup table or index.
- **API**: a typed template against a tool's API.
- **alert field**: read from the alert itself; no broker call.

Every event-search recipe also runs a data-recency test: the data source must show events within the expected ingestion delay, so an empty result is never read as "no".

---

## case.precedent
- **Measures:** closed cases with the same fingerprint inside the validity window. For each case: ID, disposition, reason, who closed it (analyst or a non-precedent flow step), when, and whether it was a mitigated close. Also returns whether the precedent entity is a crown jewel, and the number of other alerts on that entity in the window.
- **Triage rule:** yes if at least one original-decision closure lies within `precedent_validity`, the entity is not a crown jewel, there are no other alerts on the entity, and (for a mitigated precedent) the current alert's action is blocked.
  - `precedent_validity` is per detection: default 24h, min 1h, max 72h (designed, not built; the bank still allows up to 7d).
  - Designed, not built: only closes that passed audit, or at least 2 independent analyst closes of the same fingerprint, may be inherited; and the entity must have no alert of higher severity in the window (instead of no other alert).
  - Closures with reason `precedent_match` are never returned, so precedents never chain.
- **Template kind:** lookup (case memory, Reno's database on premises).
- **Splunk:** none.
- **Known-answer tests:** a seeded test case with a known fingerprint returns one match. A closure made by a precedent is not returned. A crown-jewel test entity returns no match.
- **Unknown when:** case memory is unreachable (unavailable).
- **Attacker influence:** set per detection from the fingerprint fields (Q0 rating, §10). If every field is attacker-chosen, the precedent never closes or flags by itself (the flow proceeds). Where a fingerprint field can fall back (asset ID to hostname), Q0 takes its fallback rating.
- **Owner:** Tool Broker core (no specialist).

## list.lookup
- **Measures:** the IDs of matching entries in the named context list, with each entry's expiry, host scope (asset IDs) and `verified` flag.
- **Triage rule:** yes if at least one entry matches under the list's match rule, is in force at `at_time`, and its host scope covers the host. A match on an entry with `verified: false` taints the close (it becomes a flag).
  - No threshold parameter; the list itself is the customer's fact.
- **Template kind:** lookup (context store). Lists sourced from Splunk lookups are refreshed into the context store by the Splunk specialist.
- **Splunk:** optional; Enterprise Security asset and identity lookups, when a fact is mined from them.
- **Known-answer tests:** a planted test entry matches. An expired test entry does not. A file entity matches on hash, or on signer plus path, never on name alone.
- **Unknown when:**
  - the list was not provided (no_capability, set at onboarding)
  - the entity field is empty
  - a file's hash or signer cannot be resolved
- **Attacker influence:** rated per question. Records the attacker cannot touch are none; hash or signer matches are low.
- **Owner:** Tool Broker core (context store).

## file.hash
- **Measures:** the file's SHA256, and whether it equals the reference value or list.
- **Triage rule:** yes if equal. No parameter.
- **Template kind:** API (EDR file details) or Sigma (process creation or file events that carry hashes).
- **Splunk (CIM):** Endpoint.Processes (`process_hash`), Endpoint.Filesystem (`file_hash`).
- **Known-answer tests:** a known OS binary on a reference host returns its published hash.
- **Unknown when:** the telemetry carries no hash (for example Security 4688 only), or the file is gone.
- **Attacker influence:** low. The hash is computed by the sensor.
- **Owner:** endpoint specialist.

## file.signer
- **Measures:** signature status (valid, invalid, missing), the publisher, and whether the binary is on the trusted list's excluded binaries.
- **Triage rule:** yes if the signature is valid, the publisher is on the trusted list (CF-0008) and the binary is not excluded. Unverified signer entries taint the close.
- **Template kind:** API (EDR) or Sigma (image-load or process events with signature fields).
- **Splunk (CIM):** no CIM field for the signer. It uses the vendor field from the customer's pipeline, which data readiness checks for.
- **Known-answer tests:** a known OS-signed binary returns valid with the expected publisher. A known unsigned test binary returns missing.
- **Unknown when:** no signature data is collected.
- **Attacker influence:** low. Signature validity is checked by the OS or the sensor.
- **Owner:** endpoint specialist.

## file.reputation
- **Measures:** per-source verdicts for the file hash (malicious, vulnerable, no hit), including bank seed lists such as known-bad driver samples.
- **Triage rule:** yes if any source marks the file malicious or vulnerable. This capability is escalate_only: a hit escalates or flags, and a miss is never benign evidence.
- **Template kind:** API (threat intel) plus lookup (seed lists).
- **Splunk:** Enterprise Security threat intelligence lookups, if the customer uses them.
- **Known-answer tests:** the EICAR test file hash returns malicious. A known clean OS hash returns no hit.
- **Unknown when:** every source is unreachable.
- **Attacker influence:** low for a hit. A miss carries no weight.
- **Owner:** threat intel specialist.

## ip.reputation
- **Measures:** per-source verdicts for the IP.
- **Triage rule:** yes if any source marks it malicious. escalate_only.
- **Template kind:** API (threat intel).
- **Splunk:** Enterprise Security threat intelligence lookups, optional.
- **Known-answer tests:** the threat intel platform's own test indicator returns a hit. A reserved documentation address (192.0.2.0/24) returns no hit.
- **Unknown when:** every source is unreachable.
- **Attacker influence:** low for a hit; a miss carries no weight.
- **Owner:** threat intel specialist.

## url.reputation
- **Measures:** per-source verdicts for the URLs and domains in the entity.
- **Triage rule:** yes if any source marks one malicious. escalate_only.
- **Template kind:** API (threat intel or web filtering).
- **Splunk:** Enterprise Security threat intelligence lookups, optional.
- **Known-answer tests:** the platform's own test URL returns a hit. A known benign domain returns no hit.
- **Unknown when:** every source is unreachable.
- **Attacker influence:** low for a hit; a miss carries no weight.
- **Owner:** threat intel specialist.

## identity.groups
- **Measures:** whether the account is a direct or nested member of the named accounts or groups, and which group matched.
- **Triage rule:** yes if it is a member. No parameter.
- **Template kind:** API (directory) or lookup (Enterprise Security identities).
- **Splunk:** the Enterprise Security identity lookup (`identity`, `category`).
- **Known-answer tests:** a known test account is reported in its known group, and is not reported in a group it was never in.
- **Unknown when:** the account is not found in the directory.
- **Attacker influence:** low. Changing group membership needs directory rights, which an attacker with those rights already has. Designed, not built: group membership is never the only low-rated answer on a close path.
- **Owner:** identity specialist.

## identity.risk
- **Measures:** the identity provider's current risk level for the account.
- **Triage rule:** yes if the level is at least `identity_risk_min_level` (*proposed*: default high, min medium, max high). escalate_only.
- **Template kind:** API (identity provider).
- **Splunk:** none.
- **Known-answer tests:** the API returns a level for a known account, and a seeded test-risk account returns its level.
- **Unknown when:** the identity provider has no risk feature.
- **Attacker influence:** low for a hit; a miss carries no weight.
- **Owner:** identity specialist.

## entity.baseline
- **Measures:** the number of distinct days in the lookback, which ends before the alert window, on which the entity showed the behavior.
  - Binaries are compared by hash, or signer plus path.
  - Command lines are normalized first.
- **Triage rule:** yes if the day count is at least `baseline_min_days`, counted over `baseline_lookback`.
  - `baseline_min_days` (*proposed*; today `min_days` in the question): default 3, min 2, max 30.
  - `baseline_lookback`: default 30d, min 14d, max 90d.
- **Template kind:** Sigma, with an aggregation (distinct days). Lookback and window are passed in from parameters.
- **Splunk (CIM):** depends on the behavior. Endpoint.Processes, Network_Traffic, Web or Email; accelerated, with a summary range covering the lookback.
- **Known-answer tests:** a scheduled task known to run daily on a reference host returns about the lookback in days. The data source shows events within the ingestion delay.
- **Unknown when:**
  - the data model is not accelerated, or retention does not cover the lookback
  - the entity or behavior field is empty
- **Attacker influence:** defaults to high, because an attacker can build history (designed, not built: a lower rating needs a written reason and is flagged for review). The validator requires a low-rated yes elsewhere on every close path.
- **Owner:** endpoint, network or email specialist, by behavior.

## org.prevalence
- **Measures:** the distinct hosts with the pattern, and the number of weeks it occurred in.
  - With `window: alert_window`, it counts hosts inside the alert window instead.
  - Hosts in `exclude_list`, matched by asset ID, are not counted.
- **Triage rule:** yes if hosts ≥ `org_prevalence_min_hosts` and weeks ≥ `org_prevalence_min_weeks` of `org_prevalence_of_weeks`. With the alert window, yes if hosts ≥ the question's `min_hosts`.
  - `org_prevalence_min_hosts`: default 5, min 3, max 50.
  - `org_prevalence_min_weeks`: default 3, min 2, max = of_weeks.
  - `org_prevalence_of_weeks`: default 4, min 4, max 12.
- **Template kind:** Sigma, with an aggregation (distinct hosts, distinct weeks).
- **Splunk (CIM):** Endpoint.Processes (`process`, `process_hash`, `dest`), accelerated.
- **Known-answer tests:** a common OS process returns roughly the fleet's host count. A unique test command run on one reference host returns 1.
- **Unknown when:** the data model is not accelerated, the pattern cannot be normalized, or the exclude list is not provided. Setting `window` together with `min_weeks`/`of_weeks` is rejected by validate.
- **Attacker influence:** rated per question. It is high for command lines; as a guard that escalates, low.
- **Owner:** endpoint specialist.

## change.window
- **Measures:** the approved changes covering the entities at `at_time`, each with its implementers (users or groups) and whether it names the entity as a source or target.
- **Triage rule:** answers are:
  - yes if a covering change lists the user (or one of their groups) as implementer. For alerts with no user, the change must name the entity explicitly.
  - no if nothing covers it, or every covering change lists other implementers.
  - unknown if a covering change has no implementer data.
  - No threshold parameter.
- **Template kind:** API (ITSM) or lookup (change records indexed in Splunk).
- **Splunk:** change records, if indexed. These are not the CIM Change data model, which records change events, not tickets.
- **Known-answer tests:** a known past test change returns covered at its time, with its implementer, and not covered an hour after it ends.
- **Unknown when:** the covering change has no implementer data, or the ITSM is unreachable.
- **Attacker influence:** low, and only for approved changes whose approver is not the implementer (designed, not built; the bank rates it none today). A change the implementer approved themselves gives no benign evidence.
- **Owner:** Splunk specialist, when change records are in Splunk. Otherwise ITSM access is an open question, since none of the six specialists covers it.

## alert.field
- **Measures:** the alert's normalized field value. Raw vendor values go through the customer's value table (§7).
- **Triage rule:** `op` (in, not_in, gte, cidr, matches) against `values`, which comes from a parameter. It answers unknown on `unknown_op` against `unknown_values`, or when the field is empty. Each parameter's bounds are listed with it, for example `dlp_record_count_flag` (default 1000, min 1, max 100000) and `usb_files_written_flag` (default 50, min 1, max 10000).
- **Template kind:** alert field (local to the Triage agent; no broker call, outside the call budget).
- **Splunk:** Enterprise Security notable fields after CIM normalization.
- **Known-answer tests:** a replayed sample alert per vendor family returns the expected normalized values. An unapproved raw value is reported as pending translation.
- **Unknown when:** the field is missing or empty, its value is in `unknown_values`, or the value's translation is not yet approved (which taints the close).
- **Attacker influence:** rated per question and per source profile (direct API vs forwarded syslog).
- **Owner:** Triage agent (local). The value tables are approved by the Use Case Manager.

## vuln.not_applicable
- **Measures:** the CVEs the signature maps to, the host's affected status for each, and the age of the scan data.
- **Triage rule:** yes if every mapped CVE is not affected and the data is no older than `vuln_data_max_age`.
  - `vuln_data_max_age`: default 30d, min 1d, max 30d.
- **Template kind:** API (vulnerability scanner) or lookup (vulnerability data in Splunk).
- **Splunk (CIM):** Vulnerabilities (`dest`, `cve`, `signature`, `severity`).
- **Known-answer tests:** a reference host with a known open CVE returns affected. A signature with no CVE returns no mapping.
- **Unknown when:** the signature maps to no CVE (`no_cve_mapping`), the data is older than the maximum age, or the host has never been scanned.
- **Attacker influence:** low. The scan data comes from the customer's scanner.
- **Owner:** endpoint specialist (host posture).

## email.message_status
- **Measures:** the status of each recipient's copy: delivered, quarantined or removed.
- **Triage rule:** yes if every copy is quarantined or removed. No parameter.
- **Template kind:** API (mail platform).
- **Splunk (CIM):** Email for the delivery record. The current status needs the API.
- **Known-answer tests:** a test message removed from a test mailbox returns removed for every recipient.
- **Unknown when:** message trace retention has passed, or the message ID is not found.
- **Attacker influence:** low.
- **Owner:** email specialist.

## email.no_interaction
- **Measures:** the number of link clicks and attachment opens per recipient.
- **Triage rule:** yes if the total is 0. No parameter.
- **Template kind:** API (mail security click and open logs).
- **Splunk:** click logs, if indexed.
- **Known-answer tests:** a test click on a test message is counted.
- **Unknown when:** click or open records are not collected.
- **Attacker influence:** low.
- **Owner:** email specialist.

## traffic.denied_only
- **Measures:** counts of allowed or established versus denied connections from `src` (to `dest` when given) in the alert window.
- **Triage rule:** yes if allowed = 0 and denied ≥ 1. No parameter; the window is the fixed alert window.
- **Template kind:** Sigma, with an aggregation (count by action).
- **Splunk (CIM):** Network_Traffic (`src`, `dest`, `dest_port`, `action`), accelerated.
- **Known-answer tests:** a known health-check source with allowed traffic returns allowed > 0. The data source shows recent events.
- **Unknown when:** there are no connection records for the source in the window.
- **Attacker influence:** low.
- **Owner:** network specialist.

## alert.history
- **Measures:** the number of earlier alerts that already fired inside the triage window and share the key. The key is the fingerprint, or a source, destination, user or campaign key. With `distinct`, it counts the distinct values of that field among those alerts instead.
- **Triage rule:** yes if the count is at least the threshold. A yes is used as a guard, which only raises the outcome. Usually it turns a close into a flag. For DLP user history, a block close becomes an escalation, and the unblocked-to-unapproved flag becomes an escalation.
  - `alert_history_min_count`: default 3, min 2, max 20.
  - `ids_history_min_count`: default 5, min 2, max 50.
  - `waf_distinct_signatures_min`: default 5, min 2, max 50.
  - `proxy_history_min_count`: default 10, min 3, max 50 (proxy alerts repeat more than other families).
  - A lower bound below 2 is rejected, because one earlier alert is not a burst.
- **Template kind:** lookup (alerts already raised). It reads existing alerts only, never raw logs.
- **Splunk:** Enterprise Security notables (the notable index or Incident Review), filtered on the key fields and the triage window. This is not a CIM data model.
- **Known-answer tests:**
  - A planted test notable with a unique test key returns 1; the same key outside the window returns 0.
  - With `distinct`, two planted notables with different signatures return 2.
  - The notable index shows events within the ingestion delay.
- **Unknown when:** the notable index is unreachable, or the key field is empty in the current alert.
- **Attacker influence:** none. It counts alerts already raised, which the activity cannot remove. A count below the threshold is not benign evidence; it only means there is no burst.
- **Owner:** Splunk specialist.

## scan.job_active
- **Measures:** the approved scan jobs from the scanner address that target the address at `at_time`, each with job ID, scanner, targets, start and end.
- **Triage rule:** yes if at least one job covers the target at that time. No parameter.
- **Template kind:** API (vulnerability scanner platform).
- **Splunk:** none. The Vulnerabilities data model holds results, not jobs.
- **Known-answer tests:** a known past scan job is found at its time for one of its targets, and is not found an hour after it ended.
- **Unknown when:** the scanner platform is unreachable or keeps no job records.
- **Attacker influence:** none. Job records come from the scanner platform, not from the traffic.
- **Owner:** network specialist.

## email.auth
- **Measures:** the DMARC result for the From domain, and the SPF and DKIM results with their alignment.
- **Triage rule:** yes if DMARC passes with an aligned SPF or DKIM pass. No parameter.
- **Template kind:** API (mail platform message headers).
- **Splunk (CIM):** no CIM fields for authentication results. It uses the vendor fields from the customer's pipeline.
- **Known-answer tests:** a known internal newsletter returns pass. A test message from an unaligned domain returns fail.
- **Unknown when:** headers are not retained, or the message ID is not found.
- **Attacker influence:** low. A compromised legitimate sender still passes, so this is never the only yes on a close.
- **Owner:** email specialist.

## list.propose_update
- **Measures:** not a measurement. It records a proposal (reduce_scrutiny, enforcement) or applies a change (increase_scrutiny), and returns whether it was recorded or applied.
- **Triage rule:** none. `flow_use: forbidden`; it is called only after a decision. Reduce-scrutiny and enforcement changes need human approval with an owner and an expiry.
- **Template kind:** API (context store write).
- **Splunk:** none.
- **Known-answer tests:** a dry-run proposal appears in the approval queue and is withdrawn. An increase-scrutiny test change notifies the fact owner.
- **Unknown when:** not applicable; a failure is an error, not an answer.
- **Attacker influence:** not applicable. The anti-poisoning evidence rule (§23) guards proposals.
- **Owner:** Use Case Manager, through the Tool Broker core.

---

## Data readiness checklist
Owned by the Splunk specialist (design-decisions §8). It runs at onboarding, before any recipe is built, and produces the customer's data health report.

1. **CIM data models**
   - Enabled and accelerated: Endpoint (Processes, Filesystem, Registry), Network_Traffic, Intrusion_Detection, Web, Email, Malware, Authentication, Vulnerabilities, as the customer's detections need them.
   - Acceleration completeness, and a summary range covering the longest baseline lookback (`baseline_lookback`).
2. **Field coverage per data model**
   - Share of process events with a hash, and with a parent process GUID.
   - Share of network events with `action`, and of web events with category and user agent.
   - Vendor fields the recipes need (signer, email authentication results).
3. **Ingestion delay and time sync**
   - Ingestion delay per source at the median and the 95th percentile.
   - Clock skew between `_time` and index time.
   - Sources with gaps in the last 7 days.
4. **Enterprise Security asset and identity lookups**
   - Populated, with priority, owner and category.
   - The share of alert hosts and users that resolve.
   - Asset IDs available, for matching by asset ID rather than hostname.
5. **Notables:** the notable index reachable, with the fields `alert.history` keys on, and notable volume per rule.
6. **Search head:** concurrency headroom for our searches (feeds the concurrency cap, design-decisions §17), and a search-load test before Shadow.
7. **EDR agent coverage:** the share of hosts with an EDR agent reporting.
8. **Risk-based alerting:** whether the customer uses it (risk notables change what an alert means and how often it repeats).
9. **Asset IDs in the Malware data model:** whether AV alerts carry a device or agent ID. Without it, AV precedents rate medium (the fingerprint falls back to the hostname).

The report lists each capability as buildable, buildable with gaps (named), or blocked, and feeds the coverage report.
