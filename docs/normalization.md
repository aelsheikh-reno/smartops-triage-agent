# Vendor alert normalization

The bank's vendor families read normalized alert fields. This page maps each product's raw values to
the normalized values the bank's parameters use. It is onboarding material, not bank content, so it
may name products. Onboarding confirms each mapping against the customer's product version and
records how alerts arrive (direct API or forwarded syslog); forwarded alerts cannot close on their own.

Status: draft. Each mapping row records `verified`. Only the Defender rows are verified (against
the replay dataset). The other rows were recalled from public event references and must be checked
against the product's documentation and the customer's version.

Rule (design-decisions §9, enforced by `tools/validate.py`): the cap is per customer. A detection is
capped at Recommend for a customer while that customer's product rows for its family are unverified;
the onboarding check "Check vendor alerts are normalized" records which products each customer runs.
Any family with unverified rows must declare `auto_requires: [vendor_mapping_verified]`. Each table
names the bank detections it feeds on its `Families:` line.

## Antivirus and EDR action (`action`)

The bank distinguishes a block before execution (`av_pre_execution_block_values`, may close for
low-risk classes) from post-execution or unfinished remediation (`av_post_execution_values`, answers
unknown and flags). Any other value answers no and escalates.

Families: `vendor:av_detection`

| Product | Raw value | Normalized | Verified | Note |
|---|---|---|---|---|
| Microsoft Defender (event 1117 Action Name) | Block | blocked | true | |
| Microsoft Defender (event 1117) | Quarantine, Remove, Clean | quarantined, removed, cleaned | true | the event does not say whether the file ran first, so these flag (seen in the replay dataset) |
| Microsoft Defender (event 1116) | any | detected | true | detection only, no action yet |
| CrowdStrike Falcon (PatternDispositionDescription) | Prevention, process blocked from execution | blocked_pre_execution | false | |
| CrowdStrike Falcon | Prevention, process killed | quarantined_post_execution | false | the process started |
| CrowdStrike Falcon | Quarantine, file quarantined | quarantined | false | timing not stated |
| CrowdStrike Falcon | Detection, standard detection | detected | false | |
| Any product | pending reboot, partially remediated, remediation failed | pending_reboot, partially_remediated, remediation_failed | false | generic names; confirm each product's own wording |

Other products are mapped at onboarding using the same rule: if the product cannot show the file was
stopped before it ran, map to a post-execution state.

## Detection class (`category`, `signature`)

`av_class` joins the product's category and detection name, so a remote-admin tool or miner filed
under "potentially unwanted" still matches `av_high_risk_pattern`.

## IDS classification (`category`)

Normalized to Snort class types (`attempted-admin`, `trojan-activity`, `policy-violation`, ...), which
`ids_exploit_class_values` uses. The replay maps Cisco Secure Firewall classification descriptions
(for example "Attempted Administrator Privilege Gain") to class types.

## Web filtering category (`category`)

Normalized to the names in `web_high_risk_categories`, `web_low_risk_categories` and
`web_uncategorized_values`. Onboarding maps each product's category list onto these; a category that
maps to none is neither low nor high risk and flags.
