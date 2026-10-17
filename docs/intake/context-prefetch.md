# Context prefetch

Status: (designed, not built). Design reference: `docs/design-decisions.md` §5.

The context service becomes the Tool Broker's prefetch. When intake (§4) groups a new alert under an entity (§6), the prefetch fetches what nearly every alert on that entity will need, once, and writes it into the broker's measurement cache (§21). It never hands the Triage agent a free-form bundle: the Triage agent still asks each question through the broker as a capability, and the broker answers prefetched capabilities from the cache.

Why: the old context contract built one bundle per alert, including model-facing material (rule intent, threat intel) that the yes/no flow never reads. Prefetching only the shared, structured lookups keeps the call budget and the tool API load per entity, not per alert, and keeps model-written text out of the decision path.

## What is prefetched
Only what nearly every alert needs.

| Item | Capability | Used by | Keyed on |
|---|---|---|---|
| Previous alerts on the entity in the triage window, with their dispositions | `alert.history`, `case.precedent` | entity guard (§6), Q0 (§14), burst guards | host asset ID, user identity ID |
| Open cases and escalations on the entity | `alert.history` (open cases) | entity guard, repeat attach (§15) | host asset ID, user identity ID |
| Asset context: priority (criticality), crown jewel, owner, business unit | `asset.lookup` (designed, not built; today part of `list.lookup`) | priority (§20), crown-jewel guard (§19) | host asset ID |
| Identity context: privileged user, owner, account status, service account | `identity.lookup` (designed, not built; today part of `list.lookup` and `identity.groups`) | priority, identity questions | user identity ID |

Everything else is fetched on demand, through the broker, only when a flow step asks for it:
- threat intel (OpenCTI and others), by the threat-intel specialist
- baselines (`entity.baseline`) and prevalence (`org.prevalence`)
- EDR detail (process tree, file signer, hash), by the endpoint specialist

## Value envelope
Every prefetched value carries:

| Field | Type | Meaning |
|---|---|---|
| `value` | any | The measurement (a list of alerts, a priority, a flag). |
| `source` | string | The source that answered (the customer's authoritative source for the capability, §9). |
| `observed_at` | string (ISO 8601 UTC) | When the source was read. |
| `ttl_seconds` | integer | Time-to-live in the cache (parameter per capability; bounded). |
| `source_status` | `available` or `unavailable` | Whether the source answered. |
| `query_scope` | object | The entity and window the value covers. |

"Source down" must never read as "no hit". An `unavailable` source gives the capability's `unknown_reason: unavailable` (§9): it never closes, and an empty list from an unavailable source is not "no previous alerts". For the entity guard, an unavailable alert history means the guard cannot rule the entity out, so closes on that entity flag.

## Shape
Starts from smartops-soc-app `context_service/templates/context_contract.py` (branch `feature/context-contract-template`, commit `40e399d`):

| Template key | Fate |
|---|---|
| `investigation_id` | Kept as `prefetch_id`, one per entity per grouping window. |
| `iteration` | Dropped: the prefetch runs once per entity per window, not in a loop. |
| `normalized_seed` | Replaced by a reference to the normalized alerts in the group (`docs/intake/normalized-alert-v1.md`). |
| `rule_intent` (`intent`, `semantic_alignment`: deployed SPL compared with the reference SPL) | Moved to the Detection Engineer (§17), once per rule. |
| `escu_context` (`description`, `mitre_techniques`, `data_sources`, `known_false_positives`, `analytic_story`) | Moved to the Detection Engineer, once per rule. Its content is already in the bank. |
| `opencti_threat_intelligence` (`indicators`, `malware`, `threat_actors`, `campaigns`, `relationships`) | Moved to the threat-intel specialist, on demand. |

Prefetch record:

```
prefetch_id
entity: {kind: host | user, key: <asset ID or identity ID>}
window: {start, end}            # the triage window, look-back only (§3)
alerts: [<source_alert.alert_id>, ...]
values:
  alert.history: <envelope>
  alert.open_cases: <envelope>
  asset.lookup: <envelope>      # host entities
  identity.lookup: <envelope>   # user entities
```

## Rules
- Scope: entities named in the alert only, look-back only (§3).
- Read-only. The prefetch writes only to the broker's cache.
- Per-source concurrency caps and batching apply (§9, §21): alert-history lookups for all entities in a grouping window go in one batched query per source where the SIEM allows it.
- Attacker-controlled values are escaped or bound as parameters (§10).
- Ported from smartops-soc-app: the OpenCTI client's probe-first pattern (one probe, then a per-request timeout) for on-demand threat intel (`docs/reuse-map.md`).
