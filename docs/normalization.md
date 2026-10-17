# Vendor alert normalization

The bank's vendor families never read a product's raw values. The normalizer fills the alert's roles
(`docs/intake/normalized-alert-v1.md`), and the Tool Broker answers `alert.class` questions through
**value tables**: one per vendor and product under `bank/recipes/value_tables/`, plus a generic table for
vendor-neutral rows. Each table maps the product's raw values to the fixed values of an alert class
(`alert_classes` in `bank/capabilities.yaml`), and every row is marked `verified: true` or `false`. The
tables are recipe data: they may name products and never enter the runtime bundle.

This page is the onboarding guide for those tables; the tables themselves are the source of truth.

Rule (design-decisions §9, enforced by `tools/validate.py`): the cap is per customer. A detection whose
alert classes have unverified product rows declares `auto_requires: [vendor_mapping_verified]`, and is
capped at Recommend for each customer whose product rows are unverified. The onboarding check "Check
vendor alerts are normalized" records which products each customer runs and verifies their rows. Today
`vendor:av_detection` (Defender, CrowdStrike) and `vendor:ids_alert` (Cisco intrusion classifications)
carry the cap. Generic rows (vendor `any`) do not cap a family; onboarding still confirms each product's
wording against them.

## Whether the file ran (`av_execution_state`: pre_execution, ran, unknown)

Only `pre_execution` may close, and only for low-risk classes. `ran` escalates; `unknown` flags.

| Table | Raw value | Class value | Verified |
|---|---|---|---|
| Microsoft Defender for Endpoint (Graph alert evidence) | `detectionStatus` prevented, `remediationStatus` prevented | pre_execution | false (#20) |
| | `detectionStatus` blocked ("remediated at run time"), `remediationStatus` blocked ("blocked while executing"), `detectionStatus` detected | ran | false (#20) |
| | quarantine alone, or anything else | unknown | default |
| Microsoft Defender Antivirus (event log) | 1116 (detection, no action) | ran | false |
| | 1117 Quarantine, Remove, Clean | unknown | false |
| | 1117 Block | unknown | false. Changed in the bank migration: it was mapped to blocked before execution, but the event does not say whether the file ran |
| CrowdStrike Falcon | Prevention, process blocked from execution | pre_execution | false |
| | Prevention, process killed; Detection, standard detection | ran | false |
| | Quarantine, file quarantined | unknown | false |
| Any product (generic) | blocked_pre_execution, deleted_pre_execution | pre_execution | false |
| | post-execution quarantine or cleaning, pending reboot, partial or failed remediation | unknown | false |

Microsoft's definitions are quoted in `docs/assumptions.md` A4. Which property carries them per evidence
type in the real feed, and whether it reaches the SIEM, is the lab test in #20.

## Risk class (`av_risk_class`: high_risk, low_risk, other)

Read from the detection class and name together, so a remote-admin tool or miner filed under
"potentially unwanted" is still high risk. Generic pattern rows: high-risk families first, then test
files (EICAR and similar) as `other` (they never close as low risk), then low-risk classes.

## IDS signature class (`ids_class`)

Snort-style class types (`attempted-admin`, `trojan-activity`, `policy-violation`, ...), which
`ids_exploit_class_values` uses on the step. The Cisco Secure Firewall table maps classification
descriptions (for example "Attempted Administrator Privilege Gain") to class types.

## Web filtering category (`web_category`)

The names in `web_high_risk_categories`, `web_low_risk_categories` and `web_uncategorized_values`.
Onboarding adds each product's category names to its own table; a category that maps to none is
`other`, neither low nor high risk, and flags.

## Other classes

`control_action` (what the control did), `severity`, `http_status_class`, `user_agent_class`,
`device_event`, `device_class` and `address_zone` (from the customer's `internal_networks`) have generic
rows only. Products whose wording differs get their own table at onboarding.
