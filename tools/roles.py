"""Canonical roles of the normalized alert (docs/intake/normalized-alert-v1.md) that bank logic may refer to.

The bank never names a SIEM, product or schema field. Detections declare `required_roles`, and question
inputs, binds and fingerprints refer to role attributes with the reference forms below. The normalizer
fills the roles; a required role it cannot fill flags the alert with reason entity_missing.

Reference forms in bank inputs:
  role:<role>.<attr>    a value of the normalized alert (for example role:host.asset_id)
  entity:<kind>         an entity the Tool Broker resolves (hash, signer) from the alert's roles
  derived:<name>        a value the detection derives from roles (declared under derived_fields)
  alert:<name>          a property of the alert as a whole (its fingerprint)
  bind:<name>           a placeholder a flow step must bind
"""
import re

ROLES = {
    "host": ["name", "asset_id"],
    "user": ["name", "identity_id"],
    "actor": ["name"],                      # the account that acted on `user` (for example created it)
    "src": ["ip", "host"],
    "dest": ["ip", "host", "port", "domain", "address"],
    "file": ["sha256", "path", "name", "signer"],
    "process": ["guid", "path", "name", "command_line", "sha256", "parent_guid", "parent_path", "parent_name"],
    "target_process": ["path"],
    "process_access": ["rights", "call_stack"],   # access rights requested on the target process, and the calling code's stack
    "registry": ["path", "value_name", "value_data"],
    # vendor_alert_id / endpoint_device: the reporting product's own alert ID and device (agent) ID, which the Tool Broker
    # uses to find the alert in the vendor's API (the authoritative source); missing -> a bounded fallback match
    "reporting_control": ["action", "action_raw", "signature", "signature_id", "category", "severity", "delivery", "vendor_alert_id", "endpoint_device"],
    "email": ["message_id", "sender", "sender_domain", "recipient", "subject", "url", "indicator_count", "delivery_stage"],
    "web": ["url", "user_agent", "method", "status", "category", "app", "forwarded_for"],
    "network": ["transport", "rule"],
    "device": ["id", "class", "event_type", "files_written"],
    "dlp": ["object", "object_hash", "record_count", "egress_stage"],   # egress_stage: before_egress or after_egress (whether the data had left when the control acted)
    "event": ["time", "type_id"],   # type_id: the OS or product's identifier for the event type
}
ATTRS = {f"{r}.{a}" for r, attrs in ROLES.items() for a in attrs}

# Entities the Tool Broker resolves from roles (for example to a hash and signer).
ENTITIES = {
    "process": "the alert's process (role process)",
    "parent_process": "the parent of the alert's process",
    "module": "the module (DLL or registered file) the alert's process loaded",
    "file": "the alert's file (role file)",
    "recipient_hosts": "the hosts of the message's recipients (role email), as the Tool Broker resolves them",
    "subject": "placeholder: the step must bind it to one of the entities above",
}
ALERT_PROPS = {"fingerprint", "entity", "severity"}  # entity: the grouping entity (host by asset ID, or user); severity: normalized (bank/contract/severity.yaml)
PLACEHOLDERS = {"entity:subject", "bind:history_key"}

REF = re.compile(r"\b(role|entity|derived|alert|bind):([A-Za-z_][A-Za-z0-9_.]*)")
OLD_REF = re.compile(r"\b(value|process|module|file):([A-Za-z_][A-Za-z0-9_]*)\b")


def check_ref(kind, name, derived=()):
    """None if the reference is valid, else an error message."""
    if kind == "role":
        return None if name in ATTRS else f"role:{name} is not a role attribute of normalized alert v1"
    if kind == "entity":
        return None if name in ENTITIES else f"entity:{name} is not a known entity kind"
    if kind == "derived":
        return None if name in derived else f"derived:{name} is not declared in the detection's derived_fields"
    if kind == "alert":
        return None if name in ALERT_PROPS else f"alert:{name} is not an alert property"
    if kind == "bind":
        return None
    return f"unknown reference kind {kind}"


def role_of(ref):
    """The top-level role a reference needs (for required_roles), or None."""
    kind, _, name = ref.partition(":")
    if kind == "role":
        return name.split(".")[0]
    if kind == "entity":
        return {"process": "process", "parent_process": "process", "module": "process", "file": "file", "recipient_hosts": "email"}.get(name)
    return None
