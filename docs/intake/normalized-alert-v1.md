# Normalized alert v1

Status: (designed, not built). This is the contract between the per-SIEM normalizers (the only way in, §4) and the Triage agent (`docs/design-decisions.md` §4). Nothing downstream of the normalizer reads a SIEM's own field names.

Base: smartops-soc-app `context_service/templates/normalized_seed.py`, branch `feature/normalized-seed-template`, commit `062d456`. All of the seed's sections and fields are kept unchanged. Fields marked **added for triage** are new in v1.

## Rules
- `schema_version` is required. A consumer rejects a major version it does not know.
- Unknown entity types are rejected, not mapped to the nearest known type. The permitted types are those of smartops-soc-app `engine/contracts/schemas/task-input.v1.schema.json` (main, commit `a2d0eb0`): `host`, `user`, `ip`, `file_hash`, `domain`, `url`, `process`, `file_name`, `command_line`, `process_id`, `process_guid`.
- Required means the normalizer must fill it or reject the alert. "Per detection" means required when the detection's `required_roles` or its precedent entity needs it. A per-detection field the normalizer cannot fill flags the alert with reason `entity_missing` and opens a fix ticket for the rule (§4). It never guesses.
- Every value is a string unless the Type column says otherwise. Empty is `null` (or `[]` for arrays), never `""` or a placeholder such as `-` or `unknown`.
- Times are ISO 8601 in UTC. `event_time` is the event's own time, never the alert's creation time.
- Attacker-controlled values (command lines, URLs, subjects, file names, user agents) are stored as received. They are escaped or bound as parameters by whoever puts them in a query (§10), and pass the injection classifier before any model reads them (§28).

## Fields added for triage

#### Top level

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `schema_version` | string | yes | added for triage | `"1.0"`. Minor versions add optional fields only. |
| `first_seen` | string (ISO 8601 UTC) | yes | added for triage | Earliest event time among the deduplicated repeats. |
| `last_seen` | string (ISO 8601 UTC) | yes | added for triage | Latest event time among them. |
| `count` | integer | yes | added for triage | Repeats folded into this alert at intake (dedup key: rule ID, primary entity, event time). ESCU notables repeat about 12× per event. |

#### `source_alert` (added for triage)

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `source_alert.siem` | string | yes | added for triage | One of `splunk_es`, `sentinel`, `elastic`, `qradar`, `fortisiem`, `crowdstrike_ngsiem`. |
| `source_alert.alert_id` | string | yes | added for triage | The SIEM's own alert ID (Splunk ES: `event_id` of the notable; Sentinel: incident or alert ID; Elastic: alert `_id`; QRadar: offense ID). The outbound adapter writes back to it. |
| `source_alert.link` | string (URL) | yes | added for triage | Link back to the alert in the SIEM's own screen. |
| `source_alert.created_time` | string (ISO 8601 UTC) | yes | added for triage | When the SIEM raised the alert (Splunk ES: `_time`). Kept for SLA clocks, never used as the event time. |
| `source_alert.event_time_field` | string | yes | added for triage | Which source field `event_time` came from (for example `firstTime`), so a wrong mapping can be found. |

#### `detection` (fields added)

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `detection.rule_id` | string | yes | added for triage | Stable rule ID used for bank matching, exact. Splunk ESCU: the detection's UUID; Sentinel: the analytics rule template ID; Elastic: `rule_id`; Sigma: the rule's `id`; custom: the SIEM's rule ID; vendor: the family. |
| `detection.library` | string | yes | added for triage | One of `escu`, `sentinel`, `elastic`, `sigma`, `custom`, `vendor`. Only the first four match the bank by ID; `custom` goes through the Detection Engineer. |
| `detection.library_version` | string | no | added for triage | Library release the deployed rule came from, when known. |

#### `roles`: canonical entity roles (added for triage)

One object per role. The Triage agent, the entity guard and the cache key on these, never on raw fields.

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `roles.host.name` | string | per detection | added for triage | Filled from `entities.hostname`, `entities.host` or `endpoint.device_name`. |
| `roles.host.asset_id` | string | per detection | added for triage | Resolved through the customer's asset inventory. Phase 0 requires ≥90% of alerts to resolve to an asset with a priority (§11). The entity key for host grouping (§6). |
| `roles.host.asset_priority` | string | no | added for triage | From context question C-05 (§5), through the Tool Broker, not from the SIEM alert. |
| `roles.user.name` | string | per detection | added for triage | Normalized as `domain\name` or UPN, one form per customer. |
| `roles.user.identity_id` | string | per detection | added for triage | Resolved through the identity source. The entity key for user grouping. |
| `roles.src.ip` | string | per detection | added for triage | |
| `roles.src.host` | string | per detection | added for triage | |
| `roles.dest.ip` | string | per detection | added for triage | |
| `roles.dest.host` | string | per detection | added for triage | |
| `roles.dest.port` | integer | per detection | added for triage | |
| `roles.file.sha256` | string | per detection | added for triage | Preferred hash. `file.md5` and `file.sha1` stay in `file`. |
| `roles.file.path` | string | per detection | added for triage | |
| `roles.file.signer` | string | per detection | added for triage | Code-signing signer. With `path`, the only non-hash basis for an allowlist match. |
| `roles.process.guid` | string | per detection | added for triage | Used to fetch hash and signer from the creation event when the alert lacks them (§9). |
| `roles.process.path` | string | per detection | added for triage | |
| `roles.process.command_line` | string | per detection | added for triage | Attacker-controlled. |
| `roles.process.parent_guid` | string | per detection | added for triage | |
| `roles.process.parent_path` | string | per detection | added for triage | |

#### `entity_list` (added for triage)

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `entity_list` | array of object | yes | added for triage | Every entity in the alert as `{type, value, role}`. `type` must be one of the task-input v1 types above; an unknown type is rejected. `role` is one of `host`, `user`, `src`, `dest`, `file`, `process`, or `null`. |

#### `reporting_control` (added for triage)

For vendor alerts (AV/EDR, IDS/IPS, WAF, email gateway, DLP, proxy, firewall, device control). Values are normalized through `docs/normalization.md`.

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `reporting_control.vendor` | string | per detection | added for triage | Offline metadata only: never read by a flow. |
| `reporting_control.product` | string | per detection | added for triage | Offline metadata only. |
| `reporting_control.action` | string | per detection | added for triage | Normalized action (for example `blocked_pre_execution`, `quarantined_post_execution`, `detected`). |
| `reporting_control.action_raw` | string | per detection | added for triage | As the product sent it; the broker's translation reads it (§10). |
| `reporting_control.signature` | string | per detection | added for triage | Detection or signature name. |
| `reporting_control.signature_id` | string | no | added for triage | |
| `reporting_control.vendor_alert_id` | string | yes for vendor alerts | added for triage | The reporting product's own alert ID (for Defender, the alert ID in its security API). The broker uses it to find the product's alert through the product's API, the authoritative source (§9). Missing: the broker falls back to device, file hash and a bounded time window; no match or several matches answer unknown. |
| `reporting_control.endpoint_device` | string | yes for endpoint vendor alerts | added for triage | The reporting product's own device (agent) ID, for the fallback match. |
| `reporting_control.category` | string | per detection | added for triage | Normalized category or class. |
| `reporting_control.delivery` | string | yes for vendor alerts | added for triage | `direct_api` or `forwarded`. Forwarded alerts rate medium for attacker influence and cannot close on their own (§14). |

## Role references in the bank
The bank refers to the normalized alert only through role references, `role:<role>.<attr>`, listed in `tools/roles.py`; `validate` rejects anything else, including every CIM, ECS and Sysmon field name in `tools/field_names.py`. The role attributes beyond the `roles.*` objects above map onto the seed sections: `email.*` to `email`, `web.*` to `http` (category, user agent, status, app, forwarded-for), `registry.*` to `registry`, `device.*` (id, class, event type, files written) and `dlp.*` (object, object hash, record count) to `additional_fields` until v1.1 gives them sections, `process_access.*` (granted access, call trace) and `target_process.path` to `additional_fields`, `actor.name` (the account that acted on `user`) to `authentication.source_user`, and `event.time`/`event.code` to `event_time`/`event.event_code`.

## Mapping from the bank's old field names
Used once, by the bank migration, to rewrite `required_alert_fields` and every field reference to roles. Kept for review:

| Bank name today | v1 path |
|---|---|
| `_time` | `event_time` |
| `dest` | `roles.host.name` (host alerts) or `roles.dest.host` / `roles.dest.ip` (network alerts), per detection |
| `user`, `src_user` | `roles.user.name` |
| `user_id` | `roles.user.identity_id` |
| `src` | `roles.src.ip` or `roles.src.host` |
| `dest_port` | `roles.dest.port` |
| `process` | `roles.process.command_line` |
| `process_path`, `ImagePath`, `SourceImage` | `roles.process.path` |
| `process_name` | `process.process_name` |
| `process_guid`, `SourceProcessGUID` | `roles.process.guid` |
| `process_hash`, `file_hash`, `object_hash` | `roles.file.sha256` (else `file.sha1`, `file.md5`) |
| `parent_process_guid` | `roles.process.parent_guid` |
| `parent_process_path` | `roles.process.parent_path` |
| `parent_process_name` | `process.parent_process_name` |
| `file_path`, `file_name` | `file.file_path`, `file.file_name` |
| `action` | `reporting_control.action` |
| `signature`, `rule` | `reporting_control.signature` |
| `signature_id` | `reporting_control.signature_id` |
| `category` | `reporting_control.category` |
| `severity` | `detection.severity` |
| `status` | `event.event_status` |
| `event_type`, `EventCode` | `event.event_type`, `event.event_code` |
| `url` | `http.url` |
| `http_method`, `http_user_agent` | `http.http_method`, `http.user_agent` |
| `forwarded_for` | `additional_fields.forwarded_for` |
| `transport`, `app` | `network.transport_protocol`, `network.application_protocol` |
| `subject`, `recipient`, `message_id` | `email.subject`, `email.recipient`, `email.message_id` |
| `sender_domain` | `email.domains` (sender's) |
| `registry_path`, `registry_value_name`, `registry_value_data` | `registry.registry_path`, `registry.registry_value_name`, `registry.registry_value_data` |
| `device_id` | `endpoint.device_id` |
| `TargetImage` | `additional_fields.target_process_path` |
| `granted_access`, `CallTrace` | `additional_fields.granted_access`, `additional_fields.call_trace` |
| `device_class`, `files_written`, `object`, `record_count`, `indicator_count` | `additional_fields.<name>` |

## Fields kept from the seed
All fields of `normalized_seed.py` at `062d456`, unchanged. Where a seed field and a role field overlap (for example `entities.src_ip` and `roles.src.ip`), the normalizer fills both from the same source value; flows read the role field.

#### `(top level)`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `event_id` | string | yes | `event_id` |  |
| `event_time` | string (ISO 8601 UTC) | yes | `event_time` | The event's own time, never the alert's creation time (for Splunk ES, `firstTime` with `_time`'s offset). ISO 8601 UTC. |
| `ingest_time` | string (ISO 8601 UTC) | yes | `ingest_time` | When the normalizer received the alert. |

#### `detection`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `detection.detection_id` | string | yes (kept; superseded by `detection.rule_id`) | `detection.detection_id` | The SIEM's own ID as the seed defined it. Matching uses `detection.rule_id`. |
| `detection.name` | string | yes | `detection.name` |  |
| `detection.severity` | string | yes | `detection.severity` | The SIEM's urgency or severity, mapped to informational, low, medium, high or critical. Feeds priority (§20). |
| `detection.security_domain` | string | no | `detection.security_domain` |  |
| `detection.category` | string | no | `detection.category` |  |
| `detection.type` | string | no | `detection.type` |  |
| `detection.source` | string | no | `detection.source` | Seed meaning kept (where the detection came from, free text). Superseded for matching by `detection.library`. |

#### `source_context`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `source_context.siem` | string | yes | `source_context.siem` | One of `splunk_es`, `sentinel`, `elastic`, `qradar`, `fortisiem`, `crowdstrike_ngsiem`. Same value as `source_alert.siem`. |
| `source_context.index` | string | no | `source_context.index` |  |
| `source_context.sourcetype` | string | no | `source_context.sourcetype` |  |
| `source_context.source` | string | no | `source_context.source` |  |
| `source_context.host` | string | no | `source_context.host` |  |

#### `entities`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `entities.host` | string | per detection | `entities.host` |  |
| `entities.hostname` | string | per detection | `entities.hostname` |  |
| `entities.device_id` | string | per detection | `entities.device_id` |  |
| `entities.asset_id` | string | per detection | `entities.asset_id` | Also copied into `roles.host.asset_id`. |
| `entities.user` | string | per detection | `entities.user` |  |
| `entities.user_id` | string | per detection | `entities.user_id` |  |
| `entities.account_name` | string | per detection | `entities.account_name` |  |
| `entities.account_domain` | string | per detection | `entities.account_domain` |  |
| `entities.src_ip` | string | per detection | `entities.src_ip` |  |
| `entities.src_host` | string | per detection | `entities.src_host` |  |
| `entities.src_port` | integer | per detection | `entities.src_port` |  |
| `entities.dest_ip` | string | per detection | `entities.dest_ip` |  |
| `entities.dest_host` | string | per detection | `entities.dest_host` |  |
| `entities.dest_port` | integer | per detection | `entities.dest_port` |  |

#### `authentication`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `authentication.action` | string | per detection | `authentication.action` |  |
| `authentication.status` | string | per detection | `authentication.status` |  |
| `authentication.authentication_method` | string | per detection | `authentication.authentication_method` |  |
| `authentication.logon_type` | string | per detection | `authentication.logon_type` |  |
| `authentication.failure_reason` | string | per detection | `authentication.failure_reason` |  |
| `authentication.session_id` | string | per detection | `authentication.session_id` |  |
| `authentication.source_user` | string | per detection | `authentication.source_user` |  |
| `authentication.target_user` | string | per detection | `authentication.target_user` |  |

#### `process`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `process.process_name` | string | per detection | `process.process_name` |  |
| `process.process_path` | string | per detection | `process.process_path` |  |
| `process.process_id` | integer | per detection | `process.process_id` |  |
| `process.process_guid` | string | per detection | `process.process_guid` |  |
| `process.command_line` | string | per detection | `process.command_line` |  |
| `process.parent_process_name` | string | per detection | `process.parent_process_name` |  |
| `process.parent_process_path` | string | per detection | `process.parent_process_path` |  |
| `process.parent_process_id` | integer | per detection | `process.parent_process_id` |  |
| `process.parent_command_line` | string | per detection | `process.parent_command_line` |  |
| `process.child_process_name` | string | per detection | `process.child_process_name` |  |
| `process.child_process_id` | integer | per detection | `process.child_process_id` |  |

#### `file`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `file.file_name` | string | per detection | `file.file_name` |  |
| `file.file_path` | string | per detection | `file.file_path` |  |
| `file.file_extension` | string | per detection | `file.file_extension` |  |
| `file.file_size` | integer | per detection | `file.file_size` |  |
| `file.md5` | string | per detection | `file.md5` |  |
| `file.sha1` | string | per detection | `file.sha1` |  |
| `file.sha256` | string | per detection | `file.sha256` |  |
| `file.file_action` | string | per detection | `file.file_action` |  |
| `file.file_owner` | string | per detection | `file.file_owner` |  |
| `file.file_signature` | string | per detection | `file.file_signature` | Signer subject. Allowlist matches need hash, or signer plus path, never name or path alone. |

#### `registry`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `registry.registry_path` | string | per detection | `registry.registry_path` |  |
| `registry.registry_key` | string | per detection | `registry.registry_key` |  |
| `registry.registry_value_name` | string | per detection | `registry.registry_value_name` |  |
| `registry.registry_value_data` | string | per detection | `registry.registry_value_data` |  |
| `registry.registry_action` | string | per detection | `registry.registry_action` |  |

#### `network`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `network.src_ip` | string | per detection | `network.src_ip` |  |
| `network.src_port` | integer | per detection | `network.src_port` |  |
| `network.dest_ip` | string | per detection | `network.dest_ip` |  |
| `network.dest_port` | integer | per detection | `network.dest_port` |  |
| `network.protocol` | string | per detection | `network.protocol` |  |
| `network.transport_protocol` | string | per detection | `network.transport_protocol` |  |
| `network.application_protocol` | string | per detection | `network.application_protocol` |  |
| `network.direction` | string | per detection | `network.direction` |  |
| `network.action` | string | per detection | `network.action` |  |
| `network.bytes_in` | integer | per detection | `network.bytes_in` |  |
| `network.bytes_out` | integer | per detection | `network.bytes_out` |  |
| `network.bytes_total` | integer | per detection | `network.bytes_total` |  |
| `network.packets_in` | integer | per detection | `network.packets_in` |  |
| `network.packets_out` | integer | per detection | `network.packets_out` |  |
| `network.connection_count` | integer | per detection | `network.connection_count` |  |

#### `dns`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `dns.query` | string | per detection | `dns.query` |  |
| `dns.query_type` | string | per detection | `dns.query_type` |  |
| `dns.query_length` | integer | per detection | `dns.query_length` |  |
| `dns.response` | string | per detection | `dns.response` |  |
| `dns.response_code` | string | per detection | `dns.response_code` |  |
| `dns.record_type` | string | per detection | `dns.record_type` |  |
| `dns.resolved_ip` | string | per detection | `dns.resolved_ip` |  |

#### `http`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `http.url` | string | per detection | `http.url` |  |
| `http.uri` | string | per detection | `http.uri` |  |
| `http.domain` | string | per detection | `http.domain` |  |
| `http.hostname` | string | per detection | `http.hostname` |  |
| `http.http_method` | string | per detection | `http.http_method` |  |
| `http.status_code` | integer | per detection | `http.status_code` |  |
| `http.user_agent` | string | per detection | `http.user_agent` |  |
| `http.referrer` | string | per detection | `http.referrer` |  |
| `http.request_size` | integer | per detection | `http.request_size` |  |
| `http.response_size` | integer | per detection | `http.response_size` |  |
| `http.content_type` | string | per detection | `http.content_type` |  |

#### `email`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `email.sender` | string | per detection | `email.sender` |  |
| `email.recipient` | string | per detection | `email.recipient` |  |
| `email.cc` | array of string | per detection | `email.cc` |  |
| `email.subject` | string | per detection | `email.subject` |  |
| `email.message_id` | string | per detection | `email.message_id` |  |
| `email.attachment_names` | array of string | per detection | `email.attachment_names` |  |
| `email.attachment_hashes` | array of string | per detection | `email.attachment_hashes` |  |
| `email.urls` | array of string | per detection | `email.urls` |  |
| `email.domains` | array of string | per detection | `email.domains` |  |

#### `threat_observables`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `threat_observables.ip_addresses` | array of string | no | `threat_observables.ip_addresses` |  |
| `threat_observables.domains` | array of string | no | `threat_observables.domains` |  |
| `threat_observables.urls` | array of string | no | `threat_observables.urls` |  |
| `threat_observables.file_hashes` | array of string | no | `threat_observables.file_hashes` |  |
| `threat_observables.email_addresses` | array of string | no | `threat_observables.email_addresses` |  |
| `threat_observables.file_names` | array of string | no | `threat_observables.file_names` |  |

#### `endpoint`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `endpoint.device_name` | string | per detection | `endpoint.device_name` |  |
| `endpoint.device_id` | string | per detection | `endpoint.device_id` |  |
| `endpoint.os` | string | per detection | `endpoint.os` |  |
| `endpoint.os_version` | string | per detection | `endpoint.os_version` |  |
| `endpoint.agent_id` | string | per detection | `endpoint.agent_id` |  |
| `endpoint.agent_version` | string | per detection | `endpoint.agent_version` |  |
| `endpoint.action` | string | per detection | `endpoint.action` |  |
| `endpoint.status` | string | per detection | `endpoint.status` |  |

#### `cloud`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `cloud.cloud_provider` | string | per detection | `cloud.cloud_provider` |  |
| `cloud.account_id` | string | per detection | `cloud.account_id` |  |
| `cloud.subscription_id` | string | per detection | `cloud.subscription_id` |  |
| `cloud.tenant_id` | string | per detection | `cloud.tenant_id` |  |
| `cloud.region` | string | per detection | `cloud.region` |  |
| `cloud.resource_id` | string | per detection | `cloud.resource_id` |  |
| `cloud.resource_type` | string | per detection | `cloud.resource_type` |  |
| `cloud.resource_name` | string | per detection | `cloud.resource_name` |  |
| `cloud.service` | string | per detection | `cloud.service` |  |
| `cloud.operation` | string | per detection | `cloud.operation` |  |

#### `identity`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `identity.user` | string | per detection | `identity.user` |  |
| `identity.user_id` | string | per detection | `identity.user_id` |  |
| `identity.user_type` | string | per detection | `identity.user_type` |  |
| `identity.role` | string | per detection | `identity.role` |  |
| `identity.privilege` | string | per detection | `identity.privilege` |  |
| `identity.source_identity` | string | per detection | `identity.source_identity` |  |
| `identity.target_identity` | string | per detection | `identity.target_identity` |  |

#### `geo`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `geo.src_country` | string | no | `geo.src_country` |  |
| `geo.src_city` | string | no | `geo.src_city` |  |
| `geo.dest_country` | string | no | `geo.dest_country` |  |
| `geo.dest_city` | string | no | `geo.dest_city` |  |
| `geo.latitude` | number | no | `geo.latitude` |  |
| `geo.longitude` | number | no | `geo.longitude` |  |

#### `event`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `event.event_code` | string | no | `event.event_code` |  |
| `event.event_type` | string | no | `event.event_type` |  |
| `event.event_category` | string | no | `event.event_category` |  |
| `event.event_action` | string | no | `event.event_action` |  |
| `event.event_status` | string | no | `event.event_status` |  |
| `event.message` | string | no | `event.message` |  |

#### `(top level)`

| Field | Type | Required | Source in seed | Note |
|---|---|---|---|---|
| `tags` | array of string | no | `tags` | Free tags from the SIEM. Never used in a flow. |
| `additional_fields` | object | no | `additional_fields` | Fields with no v1 slot, by their source name. A detection may require one only through the mapping table below. |
| `raw_event` | string | yes | `raw_event` | Original alert, kept for evidence and the Falsifier. Never read by a model without the injection classifier (§28). |
