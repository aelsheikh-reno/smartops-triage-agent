# Vendor alert normalization

The bank's vendor families never read a product's raw values. The normalizer fills the alert's roles
(`docs/intake/normalized-alert-v1.md`), and the Tool Broker answers `alert.class` questions through
**value tables**: one per vendor and product under `bank/recipes/value_tables/`, plus a generic table for
vendor-neutral rows. Each table maps the product's raw values to the fixed values of an alert class
(`alert_classes` in `bank/capabilities.yaml`), and every row is marked `verified: true` or `false`. The
tables are recipe data: they may name products and never enter the runtime bundle.

This page is the onboarding guide for those tables; the tables themselves are the source of truth.

Rule (design-decisions §9, `docs/broker-questions.md`, enforced by `tools/validate.py`): every row has a
kind, ambiguous or unverified; verified is per customer. A detection is Auto-eligible for a customer only
when every row on its close paths is verified for that customer. The onboarding check "Check
vendor alerts are normalized" records which products each customer runs and verifies their rows. No row is verified for any customer today, so no detection whose close paths read a value table is
Auto-eligible yet; Shadow and Recommend closes on unverified rows are marked. Generic rows (vendor `any`)
are unverified like product rows; onboarding confirms each product's wording against them.

## Whether the file ran (`endpoint.run_status`: pre_execution, ran, unknown)

Only `pre_execution` may close, and only for low-risk classes. `ran` escalates; `unknown` flags.

This is no longer an alert class: the answer comes from the endpoint product's API, the authoritative source (`docs/broker-questions.md`, Source authority). The broker finds the product's alert by the vendor alert ID, else by device, file hash and a bounded window; no match or several answer unknown. The SIEM's copy of the alert is a fallback only (tables with `source: siem_copy`), used when the API is unavailable or not granted; its answers follow the unverified rule (`fallback: true`): they may support a close in Shadow and Recommend, marked, never in Auto. Ambiguous rows (1117 Block, 1117 Quarantine/Remove/Clean, a quarantine alone) answer unknown in every mode.

| Table (source) | Raw value | Class value | Kind |
|---|---|---|---|
| Microsoft Defender for Endpoint (API: Graph alert evidence; `edr_api`) | `detectionStatus` prevented, `remediationStatus` prevented | pre_execution | unverified (#20) |
| | `detectionStatus` blocked ("remediated at run time"), `remediationStatus` blocked ("blocked while executing"), `detectionStatus` detected | ran | unverified (#20) |
| | quarantine alone, or anything else | unknown | default |
| Microsoft Defender Antivirus (event log in the SIEM; `siem_copy`, fallback) | 1116 (detection, no action) | ran | unverified |
| | 1117 Quarantine, Remove, Clean | unknown | ambiguous |
| | 1117 Block | unknown | ambiguous. Changed in the bank migration: it was mapped to blocked before execution, but the event does not say whether the file ran |
| CrowdStrike Falcon (API; `edr_api`; a matching `siem_copy` table is the fallback) | Prevention, process blocked from execution | pre_execution | unverified |
| | Prevention, process killed; Detection, standard detection | ran | unverified |
| | Quarantine, file quarantined | unknown | ambiguous |
| Any product (generic SIEM copy; `siem_copy`, fallback) | blocked_pre_execution, deleted_pre_execution | pre_execution | unverified |
| | post-execution quarantine or cleaning, pending reboot, partial or failed remediation | unknown | ambiguous |

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
`device_event` and `device_class` have generic
rows only. `address_zone` is gone: the customer's address ranges are customer context (list CF-0031, Q-0050), not a vendor's meaning, so they never sit in a value table. Products whose wording differs get their own table at onboarding.
