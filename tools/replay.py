#!/usr/bin/env python3
"""Replay gate: run flows on true-positive events against a clean-room customer.

For each rule-level detection whose source rule has test datasets (splunk/attack_data), and for
the vendor families mapped below, this fetches the datasets, normalises events to the bank's
alert fields, keeps the events the source rule would fire on, and runs the flow with a clean-room
customer: empty lists, no baselines, no change windows, no precedents, no reputation hits.
Telemetry in the dataset itself (alert fields, connection outcomes) is used as-is.

A close with disposition false_positive, benign_true_positive or inherit on a true-positive event
FAILS. A close as mitigated_true_positive (the control stopped it) is reported separately; with
--strict it fails too. Guards run as the bank defines them; alert.history counts the earlier
true-positive events of the same detection in the replay (the alerts that would already have fired).
Vulnerability lookups report why they answered unknown: no_cve_mapping when the signature names no
CVE, otherwise no_data (the clean room holds no vulnerability data).

This is a test harness, not bank content: it names source formats and products.
Flows run on normalized alert v1 roles (the harness plays the normalizer) and typed broker answers turned into
yes/no by each step's rule; alert classes go through the bank's value tables.
Usage: tools/replay.py [--strict] [family ...]   families as in tools/gates.sh; none means all; fails if it replays 0 detections or 0 events
"""
import csv
import ipaddress
import glob
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

CACHE = os.path.join(B.ROOT, "sources", "attack_data")
ESCU = os.path.join(B.ROOT, "sources", "security_content")
OFFICE = {"eqnedt32.exe", "excel.exe", "graph.exe", "msaccess.exe", "mspub.exe", "onenote.exe", "onenoteim.exe", "onenotem.exe",
          "outlook.exe", "powerpnt.exe", "visio.exe", "winproj.exe", "winword.exe"}
OFFICE_CHILD = {"bitsadmin.exe", "certutil.exe", "cmd.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "regsvr32.exe",
                "rundll32.exe", "wmic.exe", "wscript.exe"}


def fetch(url):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, url.split("/datasets/", 1)[-1].replace("/", "__"))
    if not os.path.exists(path):
        r = subprocess.run(["curl", "-sSLf", "--retry", "3", "-o", path, url], capture_output=True, text=True)
        if r.returncode:
            return None, r.stderr.strip()[:120]
    return path, None


# ---------- parsers ----------
def xml_events(text):
    for chunk in re.findall(r"<Event[ >].*?</Event>", text, re.S):
        d = dict(re.findall(r"<Data Name=['\"]([^'\"]+)['\"]>([^<]*)</Data>", chunk))
        d["_eid"] = (re.search(r"<EventID[^>]*>(\d+)</EventID>", chunk) or [None, ""])[1]
        d["_channel"] = (re.search(r"<Channel>([^<]*)</Channel>", chunk) or [None, ""])[1]
        d["_computer"] = (re.search(r"<Computer>([^<]*)</Computer>", chunk) or [None, ""])[1]
        d["_time"] = (re.search(r"SystemTime=['\"]([^'\"]+)", chunk) or [None, ""])[1]
        yield d


def classic_events(text):
    for rec in re.split(r"\n(?=\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})", text):
        code = re.search(r"EventCode=(\d+)", rec)
        if not code:
            continue
        d = {"_eid": code.group(1), "_channel": (re.search(r"LogName=(\S+)", rec) or [None, ""])[1],
             "_computer": (re.search(r"ComputerName=(\S+)", rec) or [None, ""])[1]}
        names = re.findall(r"Account Name:\s*(\S+)", rec)
        d["SubjectUserName"] = names[0] if names else ""
        d["TargetUserName"] = names[1] if len(names) > 1 else ""
        d["Group_Name"] = (re.search(r"Group Name:\s*(\S+)", rec) or [None, ""])[1]
        yield d


def json_events(text):
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(re.sub(r'":\s*-\s*([,}])', r'":null\1', line))
            except json.JSONDecodeError:
                continue


def events(path, sourcetype):
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if sourcetype == "XmlWinEventLog":
        return list(xml_events(text))
    if sourcetype == "WinEventLog":
        return list(classic_events(text))
    return list(json_events(text))


# ---------- normalisation to bank alert fields ----------
base = lambda p: (p or "").replace("/", "\\").split("\\")[-1].lower()


def norm_windows(e):
    eid, ch = e.get("_eid"), e.get("_channel", "").lower()
    n = {"dest": e.get("_computer"), "_time": e.get("_time"), "_eid": eid, "_channel": ch}
    if "sysmon" in ch and eid == "1" or eid == "4688":
        img = e.get("Image") or e.get("NewProcessName")
        par = e.get("ParentImage") or e.get("ParentProcessName")
        n.update(process_path=img, process_name=base(img), process=e.get("CommandLine", ""), original_file_name=(e.get("OriginalFileName") or "").lower(),
                 parent_process_path=par, parent_process_name=base(par), parent_process_guid=e.get("ParentProcessGuid"),
                 process_guid=e.get("ProcessGuid"), process_hash=e.get("Hashes"), user=e.get("User") or e.get("SubjectUserName"))
        n["_kind"] = "process"
    elif "sysmon" in ch and eid == "10":
        n.update(SourceImage=e.get("SourceImage"), SourceProcessGUID=e.get("SourceProcessGUID"), TargetImage=e.get("TargetImage"),
                 granted_access=e.get("GrantedAccess"), CallTrace=e.get("CallTrace"), user_id=e.get("SourceUser"), _kind="access")
    elif "sysmon" in ch and eid in ("12", "13", "14"):
        path = e.get("TargetObject", "")
        n.update(registry_path=path, registry_value_name=path.split("\\")[-1], registry_value_data=e.get("Details"),
                 process_guid=e.get("ProcessGuid"), user=e.get("User"), _kind="registry")
    elif eid in ("4720", "4732"):
        n.update(user=e.get("TargetUserName") or e.get("MemberName"), src_user=e.get("SubjectUserName"), group=e.get("TargetUserName") if eid == "4732" else "",
                 _kind="account", Group_Name=e.get("Group_Name", ""))
    elif eid in ("1102", "104"):
        n.update(user=e.get("SubjectUserName") or e.get("SubjectUser") or "", EventCode=eid, _kind="logclear")
    elif eid == "7045":
        n.update(ImagePath=e.get("ImagePath"), ServiceName=e.get("ServiceName"), ServiceType=e.get("ServiceType"), _kind="service")
    elif eid in ("1116", "1117"):
        act = (e.get("Action Name") or "").lower()
        n.update(signature=e.get("Threat Name"), category=(e.get("Category Name") or "").lower(), file_path=e.get("Path"),
                 file_name=base((e.get("Path") or "").split("->")[-1]), file_hash=None, user=e.get("Detection User"),
                 action=DEFENDER_ACTION.get(act, act) if eid == "1117" else "detected", _kind="av",
                 _raw={"EventID": eid, "Action Name": e.get("Action Name") or ""}, _tables=["microsoft-defender-antivirus-event-log"])
    return n


# The harness's normalized action for reporting_control.action. Whether the file ran is decided by the bank's
# value table (bank/broker/translations/), from the raw event ID and Action Name kept in _raw.
DEFENDER_ACTION = {"block": "blocked", "quarantine": "quarantined", "remove": "removed", "clean": "cleaned", "allow": "allowed", "no action": "detected"}
def norm_crowdstrike(e):
    if e.get("event_simpleName") != "ProcessRollup2":
        return {}
    img = e.get("ImageFileName")
    return {"dest": e.get("ComputerName"), "process_path": img, "process_name": base(img), "process": e.get("CommandLine", ""),
            "parent_process_name": (e.get("ParentBaseFileName") or "").lower(), "parent_process_path": e.get("ParentBaseFileName"),
            "process_hash": e.get("SHA256HashData"), "user": e.get("UserName"), "process_guid": e.get("TargetProcessId"),
            "parent_process_guid": e.get("ParentProcessId"), "_kind": "process", "_time": e.get("timestamp")}


def norm_estreamer(e):
    if e.get("EventType") == "IntrusionEvent":
        blocked = (e.get("InlineResult") or "").lower() in ("blocked", "dropped")
        return {"src": e.get("InitiatorIP"), "dest": e.get("ResponderIP"), "dest_port": e.get("ResponderPort"), "signature": e.get("IntrusionRuleMessage"),
                "signature_id": e.get("SignatureID"), "severity": e.get("PriorityID"), "action": "blocked" if blocked else "allowed", "_kind": "ids",
                "category": e.get("Classification"), "_raw": {"Classification": e.get("Classification") or ""}, "_tables": ["cisco-secure-firewall"],
                "_time": e.get("EventSecond")}
    if e.get("EventType") == "ConnectionEvent":
        return {"src": e.get("InitiatorIP"), "dest": e.get("ResponderIP"), "dest_port": e.get("ResponderPort"), "transport": e.get("Protocol"),
                "action": "blocked" if (e.get("AC_RuleAction") or "").lower() in ("block", "block with reset") else "allowed",
                "rule": e.get("FirewallRule"), "_kind": "conn", "_time": e.get("FirstPacketSecond")}
    return {}


def normalise(raw, sourcetype):
    if sourcetype in ("XmlWinEventLog", "WinEventLog"):
        return norm_windows(raw)
    if sourcetype.startswith("crowdstrike"):
        return norm_crowdstrike(raw)
    if sourcetype == "cisco:sfw:estreamer":
        return norm_estreamer(raw)
    return {}


# ---------- what each source rule fires on ----------
def _lookup(name, col, flt=None):
    with open(os.path.join(ESCU, "lookups", "csv", name), newline="") as fh:
        return {r[col].lower() for r in csv.DictReader(fh) if r.get(col) and (flt is None or flt(r))}


RMM = _lookup("remote_access_software.csv", "remote_utility", lambda r: r.get("isutility", "").upper() == "TRUE")
LOLDRV = {x.split("\\")[-1] for x in _lookup("loldrivers.csv", "driver_name")}
c = lambda n: (n.get("process") or "").lower()
pn = lambda n: n.get("process_name") or ""
P = {
 "escu:detect_psexec_with_accepteula_flag": lambda n: (pn(n) in ("psexec.exe", "psexec64.exe") or n.get("original_file_name") == "psexec.c") and "accepteula" in c(n),
 "escu:windows_service_creation_on_remote_endpoint": lambda n: pn(n) == "sc.exe" and "\\\\" in c(n) and "create" in c(n) and "binpath" in c(n),
 "escu:process_execution_via_wmi": lambda n: n.get("parent_process_name") == "wmiprvse.exe" and "dismhost.exe" not in c(n),
 "escu:remote_process_instantiation_via_winrm_and_powershell": lambda n: pn(n) in ("powershell.exe", "pwsh.exe") and "invoke-command" in c(n) and "-computername" in c(n),
 "escu:windows_remote_services_rdp_enable": lambda n: (n.get("registry_path") or "").lower().endswith("fdenytsconnections") and "0x00000000" in (n.get("registry_value_data") or "").lower(),
 "escu:windows_file_download_via_certutil": lambda n: pn(n) == "certutil.exe" and (re.search(r"[-/]url ", c(n)) or (re.search(r"urlcache|verifyctl", c(n)) and re.search(r"[-/]f ", c(n)))),
 "escu:windows_office_product_spawned_uncommon_process": lambda n: n.get("parent_process_name") in OFFICE and pn(n) in OFFICE_CHILD,
 "escu:bitsadmin_download_file": lambda n: pn(n) == "bitsadmin.exe" and re.search(r"transfer|addfile", c(n)),
 "escu:windows_file_download_via_powershell": lambda n: pn(n) in ("powershell.exe", "pwsh.exe") and re.search(r"iwr |invoke-webrequest|wget |curl|\.download(data|file|string)", c(n)),
 "escu:malicious_powershell_process___execution_policy_bypass": lambda n: pn(n) in ("powershell.exe", "pwsh.exe") and " -ex" in c(n) and " bypass " in c(n) + " ",
 "escu:windows_schtasks_create_run_as_system": lambda n: pn(n) == "schtasks.exe" and "/create " in c(n) and "/ru " in c(n) and "system" in c(n),
 "escu:suspicious_scheduled_task_from_public_directory": lambda n: pn(n) == "schtasks.exe" and "/create" in c(n) and re.search(r"\\users\\public\\|\\programdata\\|windows\\temp", c(n)),
 "escu:registry_keys_used_for_persistence": lambda n: n.get("_kind") == "registry" and re.search(r"\\currentversion\\run|startupapproved\\run|user shell folders|winlogon\\(shell|userinit)|\\policies\\explorer\\run", (n.get("registry_path") or "").lower()),
 "escu:detect_new_local_admin_account": lambda n: n.get("_eid") == "4720" or (n.get("_eid") == "4732" and "administrators" in (n.get("Group_Name", "") + (n.get("group") or "")).lower()),
 "escu:windows_possible_credential_dumping": lambda n: n.get("_kind") == "access" and (n.get("TargetImage") or "").lower().endswith("lsass.exe")
     and (n.get("user_id") or "").upper() not in ("NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\NETWORK SERVICE")
     and re.search(r"dbgcore|dbghelp|kernel32|kernelbase|ntdll", (n.get("CallTrace") or "").lower())
     and (int(n.get("granted_access") or "0", 16) & 0x1000 or int(n.get("granted_access") or "0", 16) & 0x40),
 "escu:creation_of_shadow_copy": lambda n: (pn(n) == "vssadmin.exe" and "create" in c(n) and "shadow" in c(n)) or (pn(n) == "wmic.exe" and "shadowcopy" in c(n) and "create" in c(n)),
 "escu:deleting_shadow_copies": lambda n: pn(n) in ("vssadmin.exe", "wmic.exe") and "delete" in c(n) and "shadow" in c(n),
 "escu:add_or_set_windows_defender_exclusion": lambda n: re.search(r"(add|set)-mppreference ", c(n)) and re.search(r"-exclusion|-controlledfolderaccessallowedapplications|-attacksurfacereductiononlyexclusions", c(n)),
 "escu:windows_event_log_cleared": lambda n: n.get("_kind") == "logclear",
 "escu:detect_remote_access_software_usage_process": lambda n: pn(n) in RMM,
 "escu:suspicious_rundll32_no_command_line_arguments": lambda n: pn(n) == "rundll32.exe" and re.search(r'rundll32(\.exe)?"?\s*$', c(n)),
 "escu:suspicious_regsvr32_register_suspicious_path": lambda n: pn(n) == "regsvr32.exe" and re.search(r"\\appdata\\|\\programdata\\|\\windows\\temp\\", c(n)) and not re.search(r"\.dll|\.ax|\.ocx", c(n)),
 "escu:detect_mshta_url_in_command_line": lambda n: pn(n) == "mshta.exe" and re.search(r"https?://", c(n)),
 "escu:windows_vulnerable_driver_installed": lambda n: n.get("_kind") == "service" and "kernel" in (n.get("ServiceType") or "").lower() and base(n.get("ImagePath")) in LOLDRV,
 "escu:detect_sharphound_usage": lambda n: pn(n) == "sharphound.exe" or n.get("original_file_name") == "sharphound.exe",
 "product_alert:ids_signature": lambda n: n.get("_kind") == "ids",
 "product_alert:av_edr_malware": lambda n: n.get("_kind") == "av",
 "product_alert:firewall_deny": lambda n: n.get("_kind") == "conn" and n.get("action") == "blocked",
}
# Vendor families replayed on vendor telemetry that ESCU tests ship with.
VENDOR = {
 "product_alert:ids_signature": ["detections/network/cisco_secure_firewall___intrusion_events_by_threat_activity.yml", "detections/network/cisco_secure_firewall___high_priority_intrusion_classification.yml"],
 "product_alert:av_edr_malware": ["detections/endpoint/windows_defender_threat_detected_on_kernel_object_path.yml"],
 "product_alert:firewall_deny": ["detections/network/cisco_secure_firewall___blocked_connection.yml"],
}
NOT_REPLAYABLE = {
 "product_alert:waf_block": "no WAF event dataset ships with any ESCU test",
 "product_alert:email_gateway_threat": "no email-gateway event dataset ships with any ESCU test",
 "product_alert:user_reported_email": "no user-report dataset exists in splunk/attack_data",
 "product_alert:dlp_policy_match": "no DLP event dataset ships with any ESCU test",
 "product_alert:proxy_url_block": "ESCU proxy datasets hold allowed requests only, no URL-filter blocks",
 "product_alert:device_control_connect": "no device-control event dataset ships with any ESCU test",
 "product_alert:device_control_write": "no device-control event dataset ships with any ESCU test",
}


# ---------- harness mapping to normalized alert v1 roles ----------
# The bank refers to roles, never to fields. The harness plays the normalizer: it maps the CIM-like keys the
# parsers above produce to role attributes, per event kind, and keeps the raw vendor values the value tables read.
ROLE = {
    "_time": "event.time", "dest": "host.name", "dest_asset_id": "host.asset_id", "user": "user.name", "user_id": "user.name",
    "src_user": "actor.name", "src": "src.ip", "dest_port": "dest.port", "transport": "network.transport", "rule": "network.rule",
    "process": "process.command_line", "process_name": "process.name", "process_path": "process.path", "process_guid": "process.guid",
    "process_hash": "process.sha256", "parent_process_guid": "process.parent_guid", "parent_process_path": "process.parent_path",
    "parent_process_name": "process.parent_name", "registry_path": "registry.path", "registry_value_name": "registry.value_name",
    "registry_value_data": "registry.value_data", "EventCode": "event.code", "ImagePath": "file.path",
    "SourceImage": "process.path", "SourceProcessGUID": "process.guid", "TargetImage": "target_process.path",
    "granted_access": "process_access.granted_access", "CallTrace": "process_access.call_trace",
    "signature": "reporting_control.signature", "signature_id": "reporting_control.signature_id", "category": "reporting_control.category",
    "severity": "reporting_control.severity", "action": "reporting_control.action", "file_hash": "file.sha256", "file_name": "file.name",
    "file_path": "file.path",
}
NETWORK_KINDS = {"ids", "conn"}


def to_roles(n):
    out = {}
    for k, v in n.items():
        if k.startswith("_") or v in (None, ""):
            continue
        r = ROLE.get(k)
        if k == "dest" and n.get("_kind") in NETWORK_KINDS:
            r = "dest.ip"
        if r:
            out[r] = v
    if n.get("action") is not None:
        out["reporting_control.action_raw"] = n.get("_action_raw") or n.get("action")
    for k in ("_time", "_kind", "_idx", "_raw", "_tables", "_api"):
        if k in n:
            out[k] = n[k]
    if n.get("_time"):
        out["event.time"] = n["_time"]
    return out


def ref_value(ref, n):
    """Value of a role:/derived:/alert: reference, or of the role an entity: reference needs (None if missing)."""
    kind, _, name = ref.partition(":")
    if kind in ("role", "derived"):
        return n.get(name)
    if kind == "alert":
        return n.get(name)
    if kind == "entity":
        return n.get({"process": "process.guid", "parent_process": "process.parent_guid", "module": "process.guid", "file": "file.path"}[name])
    return None


def derive(d, n):
    for name, spec in (d.get("derived_fields") or {}).items():
        src = spec["from"] if isinstance(spec["from"], list) else [spec["from"]]
        vals = [str(ref_value(f, n)) for f in src if ref_value(f, n) not in (None, "")]
        if "pattern" in spec:
            hits = re.findall(spec["pattern"], vals[0], re.I) if vals else []
            n[name] = (",".join(hits) if spec.get("all") else hits[0]) if hits else None
        elif spec.get("first"):
            n[name] = vals[0] if vals else None
        else:
            n[name] = spec.get("join", " ").join(vals) if vals else None
    n["fingerprint"] = "|".join(str(ref_value(f, n)) for f in d["fingerprint"])
    return n


# ---------- clean-room customer: the Tool Broker's typed answers ----------
def measure(b, q, inputs, n, ctx):
    """The broker's typed answer for one question on one alert, or None for status unknown."""
    cap = q["capability"]["name"]
    if q["id"] in (ctx.get("overrides") or {}):
        return ctx["overrides"][q["id"]]   # a regression case supplies a broker answer the clean room cannot give
    optional = set(q["capability"].get("optional_inputs") or [])
    for kind, name in B.walk_refs({k: v for k, v in inputs.items() if k not in optional}):
        if kind != "bind" and ref_value(f"{kind}:{name}", n) in (None, ""):
            return None
    if cap == "alert.class":
        cls = inputs["class"]
        tables = [t for t in n.get("_tables", []) if cls in (b["value_tables"].get(t, {}).get("classes") or {})]
        if tables:
            values = n.get("_raw") or {}
        else:
            reads = [inputs["of"].split(":", 1)[1]] if inputs.get("of") else b["capabilities"]["alert_classes"][cls]["reads"]
            values = {r: n.get(r) for r in reads}
            if all(v in (None, "") for v in values.values()):
                return None
            # further role inputs (for example the email delivery stage) are read by the translation too
            values.update({str(v).split(":", 1)[1]: n.get(str(v).split(":", 1)[1]) for k, v in inputs.items()
                           if k not in ("class", "of") and str(v).startswith("role:")})
        v, ctx["_trust"], ctx["_prov"] = B.classify_effective(b, cls, values, tables, ctx=ctx, question=q["id"])
        return v
    if cap == "endpoint.run_status":
        # The endpoint API is authoritative (_api: the vendor alerts it matched); without it the SIEM's copy of the alert
        # is the fallback (_raw read through the product's siem_copy table, else the generic one).
        copy = {"raw": n.get("_raw") or {"value": n.get("reporting_control.action_raw")}, "tables": n.get("_tables") or []}
        v, ctx["_trust"], ctx["_prov"] = B.run_status(b, n.get("_api"), copy, ctx=ctx)
        return v
    if cap == "list.lookup" and (b["facts"].get(inputs.get("list")) or {}).get("default_entries"):
        # A context list that starts from default entries (CF-0031 internal networks: the private ranges) holds them in the clean room.
        import ipaddress
        try:
            ip = ipaddress.ip_address(str(ref_value(inputs["entity"], n)))
        except ValueError:
            return None
        return any(ip in ipaddress.ip_network(c) for c in b["facts"][inputs["list"]]["default_entries"])
    if cap == "context.rule":
        return B.context_rule(b, q["context_rule"], ctx.get("context") or {})
    if cap == "alert.measure":
        return float(ref_value(inputs["of"], n))
    if cap == "traffic.denied_only":
        conns = [x for x in ctx["conns"] if x.get("src.ip") == n.get("src.ip")]
        return None if not conns else all(x.get("reporting_control.action") == "blocked" for x in conns)
    if cap == "alert.history":
        key = inputs["key"]
        earlier = [x for x in ctx["alerts"][:n["_idx"]] if ref_value(key, x) == ref_value(key, n)]
        if inputs.get("distinct"):
            return len({ref_value(inputs["distinct"], x) for x in earlier})
        return len(earlier)
    if cap == "vuln.not_applicable":
        ctx["vuln_unknown"][("no_cve_mapping" if not re.search(r"CVE-\d{4}-\d+", str(n.get("reporting_control.signature")), re.I) else "no_data")] += 1
        return None
    if cap in ("entity.baseline", "org.prevalence", "email.message_status", "email.no_interaction", "email.auth", "file.signer"):
        return None
    return False   # precedent.check, list.lookup (CF-0031 internal networks included), identity.groups, change.window, scan.job_active, *.reputation: empty in a clean room


def answer(b, q, item, n, ctx, d):
    """The Triage side of one question: the broker's answer, status and trust, turned into yes / no / unknown by the step's rule.
    Records (question, yes/no/unknown, trust, provenance) in ctx["answers"]; the triage side reads only the trust."""
    if set((q.get("needs") or {}).get("coverage") or []) - set(ctx.get("coverage") or []):
        return "unknown"   # clean room: no coverage report, so the question is no_capability
    ctx["_trust"], ctx["_prov"] = "checked", None
    value = measure(b, q, B.step_inputs(q, item), n, ctx)
    a = B.apply_rule(b, item.get("rule"), value, B.answer_type(b, q["id"]), d)
    ctx.setdefault("answers", []).append((q["id"], a, ctx["_trust"], ctx["_prov"]))
    return a


def run_flow(b, d, n, ctx):
    """One alert through one flow in ctx["mode"] (shadow, recommend or auto; default recommend).
    The Auto rule, in triage terms: a not_checked answer may support a close in Shadow and Recommend (the close is marked
    "not_checked: <question>" in the explanation and decision log), never in Auto (the close becomes a flag). An answer of
    unknown supports nothing. The provenance in brackets is the broker's, shown here for the gate report only."""
    ctx["answers"] = []
    out, trail = _run_flow(b, d, n, ctx)
    nc = sorted({f"{qid} [{prov}]" for qid, a, trust, prov in ctx["answers"] if trust == "not_checked" and a != "unknown"})
    if out.startswith("close") and nc:
        if ctx.get("mode") == "auto":
            return "flag", trail + [f"not_checked answer in Auto: {', '.join(nc)} -> flag"]
        trail = trail + [f"not_checked: {x}" for x in nc]
    return out, trail


def _run_flow(b, d, n, ctx):
    trail = []
    for st in d["flow"]:
        q = b["questions"][st["question"]]
        a = answer(b, q, st, n, ctx, d)
        out = st["on_" + a]
        trail.append(f"{st['question']}={a}")
        if out != "next":
            results = []
            for gd in st.get("guards") or []:
                if not B.guard_applies(gd, out) or (gd.get("if_entry_type") and n.get("_matched_entry_type") not in gd["if_entry_type"]):
                    continue
                results.append((gd, answer(b, b["questions"][gd["question"]], gd, n, ctx, d)))
            raised = B.raise_outcome(out, results)
            if raised != out:
                trail.append("guards " + ",".join(f"{g['question']}={a}" for g, a in results) + f" -> {raised}")
                out = raised
        if out != "next":
            return context_unknown(out, trail, ctx)
    return "flag", trail


def context_unknown(out, trail, ctx):
    """Every close depends on C-06 (Q0 needs a known non-crown-jewel; no auto-close on crown jewels): if C-06 is unknown or
    its source unavailable (None), the close becomes a flag with reason context_unknown. Missing context never escalates."""
    if out.startswith("close") and (ctx.get("context") or {}).get("C-06") is None:
        return "flag", trail + ["context_unknown C-06 -> flag"]
    return out, trail


# Regression cases: hand-built normalized alerts (roles, plus the raw values the value tables read) with a required outcome.
GRAPH = ["microsoft-defender-for-endpoint"]
EVENT_LOG = ["microsoft-defender-antivirus-event-log"]
AV = {"host.name": "ws-01", "user.name": "u1", "event.time": "2026-10-17T00:00:00Z", "file.path": "C:\\Users\\Public\\m.exe", "file.name": "m.exe"}
PUA = {"reporting_control.signature": "PUA:Win32/Presenoker", "reporting_control.category": "pua"}


def api(*evidence):
    """The endpoint API's answer: the vendor alerts the broker matched (by vendor alert ID, else device + hash + window)."""
    return {"tables": GRAPH, "matches": list(evidence)}


VERIFIED = ["microsoft-defender-for-endpoint", "generic"]   # tables a synthetic customer has verified (as after #20 and onboarding)
USB = {"_coverage": ["device_control_write_events"], "host.name": "srv-01", "user.name": "u1", "event.time": "2026-10-17T00:00:00Z", "device.event_type": "connect", "device.class": "storage",
       "reporting_control.action": "allowed", "device.files_written": 0}
MAIL = {"_overrides": {"Q-0035": True}, "email.sender": "a@example.org", "email.subject": "invoice", "email.recipient": "u1@corp.example",
        "email.url": "http://example.org/x", "file.sha256": "1" * 64, "event.time": "2026-10-17T00:00:00Z", "reporting_control.action": "quarantined"}
API_PREVENTED = dict(AV, **PUA, **{"file.sha256": "d" * 64, "reporting_control.vendor_alert_id": "da-4", "_api": api({"detectionStatus": "prevented"})})
BLOCK_1117 = dict(AV, **PUA, **{"file.sha256": "e" * 64, "reporting_control.action_raw": "Block", "_raw": {"EventID": "1117", "Action Name": "Block"}, "_tables": EVENT_LOG})

# (detection, name, alert, required outcome). A required outcome ending in "+not_checked" also requires the close to be marked
# "not_checked: <question>"; any other close must not be marked. Alert keys starting with _ are harness inputs: _mode (shadow, recommend, auto; default
# recommend), _api (the endpoint API's matches), _raw/_tables (the SIEM copy), _coverage (coverage reports present),
# _context (context answers; None = unknown or source unavailable), _verified (tables a synthetic customer has verified),
# _overrides (broker answers per question the clean room cannot give, for example the mailbox status).
REGRESSION = [
 ("D-0026", "no hash, high-risk class, detected (not blocked) must escalate",
  dict(AV, **{"reporting_control.signature": "HackTool:Win32/Mimikatz", "reporting_control.category": "hacktool", "reporting_control.action_raw": "detected"}), "escalate"),
 ("D-0026", "no hash, high-risk class, blocked must escalate",
  dict(AV, **{"reporting_control.signature": "HackTool:Win32/Mimikatz", "reporting_control.category": "hacktool", "reporting_control.action_raw": "blocked_pre_execution"}), "escalate"),
 ("D-0026", "Defender API detectionStatus blocked (remediated at run time), low-risk class: no close",
  dict(AV, **PUA, **{"file.sha256": "a" * 64, "reporting_control.vendor_alert_id": "da-1", "_api": api({"detectionStatus": "blocked"})}), "escalate"),
 ("D-0026", "Defender API quarantine only (no detection status), low-risk class: flag",
  dict(AV, **PUA, **{"file.sha256": "b" * 64, "reporting_control.vendor_alert_id": "da-2", "_api": api({"remediationStatus": "quarantined"})}), "flag"),
 ("D-0026", "any product, no API, SIEM copy quarantined only (ambiguous row), low-risk class: flag",
  dict(AV, **{"file.sha256": "c" * 64, "reporting_control.signature": "Adware:Win32/X", "reporting_control.category": "adware",
              "reporting_control.action_raw": "quarantined"}), "flag"),
 ("D-0026", "Defender API prevented, low-risk, unverified rows, Recommend: recommended close, marked not_checked",
  dict(API_PREVENTED, _mode="recommend"), "close:mitigated_true_positive+not_checked"),
 ("D-0026", "Defender API prevented, low-risk, unverified rows, Shadow: close shown, marked not_checked",
  dict(API_PREVENTED, _mode="shadow"), "close:mitigated_true_positive+not_checked"),
 ("D-0026", "Defender API prevented, low-risk, unverified rows, Auto: not closed (flag)",
  dict(API_PREVENTED, _mode="auto"), "flag"),
 ("D-0026", "Defender API prevented, low-risk, rows verified for the customer, Auto: mitigated close",
  dict(API_PREVENTED, _mode="auto", _verified=VERIFIED), "close:mitigated_true_positive"),
 ("D-0026", "C-06 source unavailable: the same verified Auto close flags (context_unknown)",
  dict(API_PREVENTED, _mode="auto", _verified=VERIFIED, _context={"C-06": None}), "flag"),
 ("D-0026", "event 1117 Block (ambiguous), Shadow: flag", dict(BLOCK_1117, _mode="shadow"), "flag"),
 ("D-0026", "event 1117 Block (ambiguous), Recommend: flag", dict(BLOCK_1117, _mode="recommend"), "flag"),
 ("D-0026", "event 1117 Block (ambiguous), Auto, other rows verified: flag", dict(BLOCK_1117, _mode="auto", _verified=VERIFIED), "flag"),
 ("D-0026", "Defender API unavailable, SIEM event-log copy 1116 (detected): ran stands from the fallback, escalate",
  dict(AV, **PUA, **{"file.sha256": "e" * 64, "reporting_control.action_raw": "detected", "_raw": {"EventID": "1116", "Action Name": "Not Applicable"},
                     "_tables": EVENT_LOG}), "escalate"),
 ("D-0026", "no vendor alert ID, fallback match finds two Defender alerts, low-risk class: flag",
  dict(AV, **PUA, **{"file.sha256": "f" * 64, "reporting_control.endpoint_device": "dev-1",
                     "_api": api({"detectionStatus": "prevented"}, {"detectionStatus": "prevented"})}), "flag"),
 ("D-0026", "no vendor alert ID, fallback match finds no Defender alert, low-risk class: flag",
  dict(AV, **PUA, **{"file.sha256": "0" * 64, "reporting_control.endpoint_device": "dev-1", "_api": api()}), "flag"),
 ("D-0031", "email quarantined before delivery, Recommend: close (blocked by the control), marked not_checked",
  dict(MAIL, **{"email.delivery_stage": "pre_delivery"}), "close:mitigated_true_positive+not_checked"),
 ("D-0031", "email quarantined after delivery (a purge of a delivered message): ambiguous, flag",
  dict(MAIL, **{"email.delivery_stage": "post_delivery"}), "flag"),
 ("D-0031", "email quarantined with no delivery stage: ambiguous, flag", dict(MAIL), "flag"),
 ("D-0034", "removable media, C-08 unknown: flag (context_unknown), never escalate",
  dict(USB, _context={"C-06": False}), "flag"),
 ("D-0034", "removable media, C-08 server: Q-0067 escalates",
  dict(USB, _context={"C-06": False, "C-08": "server"}), "escalate"),
 ("D-0034", "removable media, C-08 workstation, Recommend: close (no data transferred), marked not_checked",
  dict(USB, _context={"C-06": False, "C-08": "workstation"}), "close:benign_true_positive+not_checked"),
 ("D-0034", "removable media, C-08 workstation, unverified rows, Auto: flag",
  dict(USB, _mode="auto", _context={"C-06": False, "C-08": "workstation"}), "flag"),
 ("D-0034", "removable media, C-08 workstation, rows verified, Auto: close",
  dict(USB, _mode="auto", _verified=VERIFIED, _context={"C-06": False, "C-08": "workstation"}), "close:benign_true_positive"),
 ("D-0034", "removable media, C-06 unavailable and C-08 workstation: flag (context_unknown)",
  dict(USB, _context={"C-06": None, "C-08": "workstation"}), "flag"),
]


TODAY = "2026-10-17"


def synthetic_customer(b, tables):
    """A customer that verified every non-ambiguous row of these tables (cited doc, 20-alert spot check, version, expiry)."""
    recs = [{"table": t, "row": r["id"], "vendor_doc": (b["value_tables"][t].get("references") or ["doc"])[0], "spot_check_alerts": 20,
             "checked_by": "product operator", "checked_on": TODAY, "product_version": "1.0", "expires": "2027-10-17"}
            for t in tables for spec in b["value_tables"][t]["classes"].values() for r in spec.get("rows") or [] if r.get("kind") != "ambiguous"]
    return {"customer": "regression", "products": {t: "1.0" for t in tables}, "verifications": recs, "modes": {}}


def run_regression(b, ctx, batches):
    failures = []
    import copy
    for did, name, alert, want in REGRESSION:
        if b["detections"][did]["family"] not in batches:
            continue
        bb, customer = b, None
        if alert.get("_verified"):
            bb, customer = copy.deepcopy(b), "regression"
            bb["customers"][customer] = synthetic_customer(bb, alert["_verified"])
        n = derive(bb["detections"][did], dict(alert, _idx=0))
        c = dict(ctx, alerts=[n], conns=[], context=dict(ctx.get("context") or {}, **(alert.get("_context") or {})), coverage=alert.get("_coverage") or [],
                 overrides=alert.get("_overrides") or {},
                 mode=alert.get("_mode", "recommend"), customer=customer, today=TODAY)
        out, trail = run_flow(bb, bb["detections"][did], n, c)
        need_mark = want.endswith("+not_checked")
        want = want.replace("+not_checked", "")
        got = out if want.startswith("close:") and out.startswith(want) else out.split(":")[0]
        ok = (got == want or (want.startswith("close:") and out.startswith(want))) and \
            (not need_mark or any(t.startswith("not_checked:") for t in trail)) and \
            (need_mark or not any(t.startswith("not_checked:") for t in trail))
        print(f"  {'ok  ' if ok else 'FAIL'} {did}: {name} -> {out}  [{' > '.join(trail)}]")
        if not ok:
            failures.append(name)
    return failures


def main():
    strict = "--strict" in sys.argv
    batches = B.select_batches([a for a in sys.argv[1:] if not a.startswith("--")])
    b = B.load()
    # Clean-room customer: no crown-jewel list entries (C-06 answered no) and no asset inventory (C-08 unknown: Q-0067 flags).
    ctx = {"vuln_unknown": Counter(), "context": {"C-06": False}, "mode": "recommend", "customer": None, "today": TODAY}
    rows, cannot, fails, mitigated = [], [], [], []
    # The harness picks true-positive events by the source rule's logic, so it keys on the source rule ID from the intake
    # rule map (escu:<rule file> or product_alert:<kind>); results are reported by D-ID.
    rule_of = {d_id: sid for sid, d_id in B.source_ids(b, ("escu", "product_alert")).items()}
    for did, d in sorted(b["detections"].items()):
        if B.batch_of("rule", d) not in batches:
            continue
        sid = rule_of.get(did)
        if sid in NOT_REPLAYABLE:
            cannot.append((did, NOT_REPLAYABLE[sid]))
            continue
        src = d.get("source") if isinstance(d.get("source"), dict) else {}
        rules = VENDOR.get(sid) or ([src["path"]] if src.get("repo") not in (None, "internal") else [])
        tests = []
        for r in rules:
            y = B._load(os.path.join(ESCU, r))
            for t in y.get("tests") or []:
                tests += t.get("attack_data", [])
        if not tests:
            cannot.append((did, "source rule has no test dataset"))
            continue
        evs, notes = [], []
        for t in tests:
            path, error = fetch(t["data"])
            if not path:
                notes.append(f"fetch failed: {error}")
                continue
            norm = [normalise(e, t.get("sourcetype", "")) for e in events(path, t.get("sourcetype", ""))]
            if not any(norm):
                notes.append(f"{t.get('sourcetype')} not used by this flow's fields")
            evs += [x for x in norm if x]
        ctx["conns"] = [to_roles(x) for x in evs if x.get("_kind") == "conn"]
        tp = [derive(d, to_roles(x)) for x in evs if P[sid](x)]
        for i, x in enumerate(tp):
            x["_idx"] = i
        ctx["alerts"] = tp
        if not tp:
            cannot.append((did, "no event in the datasets matches the source rule" + (f" ({'; '.join(sorted(set(notes)))})" if notes else "")))
            continue
        outcomes = Counter()
        for n in tp:
            out, trail = run_flow(b, d, n, ctx)
            key = out.split(":")[0] if not out.startswith("close") else out
            outcomes[key] += 1
            if out.startswith("close:mitigated_true_positive"):
                mitigated.append((did, out, trail))
            elif out.startswith("close"):
                fails.append((did, out, trail))
        rows.append((did, len(tests), len(tp), outcomes))
    print(f"{'detection':<62} {'datasets':>8} {'TP events':>9}  outcomes")
    for did, nt, ntp, oc in rows:
        print(f"{did:<62} {nt:>8} {ntp:>9}  " + ", ".join(f"{k} {v}" for k, v in sorted(oc.items())))
    print("\nCould not replay:")
    for did, why in cannot:
        print(f"  {did}: {why}")
    if mitigated:
        print(f"\nClosed as mitigated_true_positive (the control stopped it): {len(mitigated)} events")
        for did, out, trail in mitigated[:10]:
            print(f"  {did}: {out}  [{' > '.join(trail)}]")
    if fails:
        print(f"\nFAIL: {len(fails)} true-positive events closed")
        for did, out, trail in fails[:20]:
            print(f"  {did}: {out}  [{' > '.join(trail)}]")
    if ctx["vuln_unknown"]:
        print("\nVulnerability step answered unknown (never closes): " + ", ".join(f"{k} {v}" for k, v in sorted(ctx["vuln_unknown"].items())))
    print("\nRegression cases:")
    reg_fail = run_regression(b, ctx, batches)
    n_reg = sum(1 for did, *_ in REGRESSION if b["detections"][did]["family"] in batches)
    B.require_loaded(f"replay ({', '.join(sorted(batches))})", detections=len(rows), events=sum(r[2] for r in rows))
    bad = fails or reg_fail or (strict and mitigated)
    print(f"\nreplay: {sum(r[2] for r in rows)} TP events in {len(rows)} detections, {n_reg - len(reg_fail)}/{n_reg} regression cases; "
          f"{len(fails)} benign/FP closes, {len(mitigated)} mitigated closes"
          f" -> {'FAIL' if bad else 'PASS'}{' (strict)' if strict else ''}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
