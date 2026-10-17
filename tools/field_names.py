"""Known schema field names that must never appear in bank logic (bank/detections, bank/questions).

Seeded from Splunk CIM (Endpoint, Network_Traffic, Intrusion_Detection, Web, Email, Malware, Alerts,
Authentication, Change, Data_Loss_Prevention), Elastic Common Schema and Sysmon / Windows event data.
The bank refers to canonical roles instead (tools/roles.py). Matching is exact and case-sensitive on
whole structured values (and on the name after an old value:/process:/file:/module: prefix); prose
fields (text, notes, reasons) are not scanned. This is a test list, not bank content: it names schemas.
"""

CIM = {
    # common and Endpoint
    "_time", "dest", "dest_asset_id", "dest_ip", "dest_name", "dest_nt_domain", "dest_port", "dest_priority", "dest_category",
    "src", "src_ip", "src_name", "src_port", "src_user", "src_user_id", "src_category", "src_priority",
    "user", "user_id", "user_name", "user_category", "user_priority", "user_bunit", "user_agent",
    "process", "process_name", "process_path", "process_id", "process_guid", "process_hash", "process_exec",
    "process_current_directory", "process_integrity_level", "original_file_name",
    "parent_process", "parent_process_name", "parent_process_path", "parent_process_id", "parent_process_guid",
    "parent_process_exec", "vendor_product", "action", "status", "signature", "signature_id", "category", "severity",
    "registry_path", "registry_key_name", "registry_value_name", "registry_value_data", "registry_value_type", "registry_hive",
    "file_hash", "file_name", "file_path", "file_size", "file_create_time", "file_modify_time", "file_acl",
    "service", "service_name", "service_path", "service_exec", "start_mode",
    # Network_Traffic and Intrusion_Detection
    "transport", "protocol", "app", "rule", "bytes", "bytes_in", "bytes_out", "packets", "direction", "ids_type",
    # Web
    "url", "url_domain", "uri_path", "uri_query", "http_method", "http_user_agent", "http_referrer", "http_content_type",
    "site", "cookie",
    # Email
    "message_id", "recipient", "recipient_domain", "recipient_count", "sender", "src_user_domain", "subject", "file_hash",
    "internal_message_id", "message_info", "orig_recipient", "return_addr", "size",
    # Data loss prevention and Alerts
    "object", "object_category", "object_path", "dlp_type", "record_count", "id", "type", "description", "mitre_technique_id",
    # Malware and device control
    "date", "device_id", "device_class", "event_type", "files_written", "indicator_count", "forwarded_for",
    # Authentication and Change
    "authentication_method", "authentication_service", "change_type", "command", "object_attrs", "result",
    # access to LSASS (CIM Endpoint processes extension)
    "granted_access", "source_image_hash", "writer_hash", "driver_hash",
}

ECS = {
    "@timestamp", "host.name", "host.hostname", "host.id", "host.ip", "user.name", "user.id", "user.domain",
    "source.ip", "source.port", "source.address", "destination.ip", "destination.port", "destination.address", "destination.domain",
    "process.name", "process.executable", "process.command_line", "process.args", "process.pid", "process.entity_id",
    "process.hash.sha256", "process.hash.md5", "process.parent.name", "process.parent.executable", "process.parent.entity_id",
    "process.code_signature.subject_name", "file.path", "file.name", "file.hash.sha256", "file.hash.sha1", "file.hash.md5",
    "file.code_signature.subject_name", "registry.path", "registry.value", "registry.data.strings", "event.action", "event.code",
    "event.category", "event.type", "event.outcome", "event.module", "event.dataset", "rule.name", "rule.id", "url.full",
    "url.domain", "url.original", "user_agent.original", "http.request.method", "http.response.status_code",
    "network.transport", "network.protocol", "email.message_id", "email.subject", "email.from.address", "email.to.address",
    "threat.indicator.type", "observer.vendor", "observer.product",
}

SYSMON = {
    "Image", "ParentImage", "CommandLine", "ParentCommandLine", "ProcessGuid", "ParentProcessGuid", "ProcessId", "Hashes",
    "OriginalFileName", "User", "IntegrityLevel", "TargetImage", "SourceImage", "SourceProcessGUID", "TargetProcessGUID",
    "SourceProcessGuid", "TargetProcessGuid", "GrantedAccess", "CallTrace", "SourceUser", "TargetUser", "TargetObject",
    "Details", "EventType", "ImageLoaded", "Signature", "SignatureStatus", "Signed", "TargetFilename", "DestinationIp",
    "DestinationPort", "DestinationHostname", "SourceIp", "QueryName", "ImagePath", "ServiceName", "ServiceType", "StartType",
    "EventCode", "EventID", "Computer", "SubjectUserName", "TargetUserName", "NewProcessName", "ParentProcessName",
}

KNOWN = CIM | ECS | SYSMON
