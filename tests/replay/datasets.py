"""Replay datasets: fetch the pinned attack_data files, parse them, normalise events to the harness's fields and map those
to normalized alert v1 roles (the harness plays the normalizer). Test harness, not bank content: it names source formats
and products. Sources are pinned in tests/replay/sources.lock; a failed download raises, it never passes as "not replayable".
"""
import json
import os
import re
import subprocess

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LOCK = yaml.safe_load(open(os.path.join(HERE, "sources.lock")))
ESCU = os.path.join(ROOT, "sources", "security_content")
CACHE = os.path.join(ROOT, "sources", "attack_data", LOCK["splunk/attack_data"]["commit"])


class FetchError(RuntimeError):
    pass


def check_pins():
    """The local security_content clone must be at its pinned commit; returns the problem, or None."""
    want = LOCK["splunk/security_content"]["commit"]
    r = subprocess.run(["git", "-C", ESCU, "rev-parse", "HEAD"], capture_output=True, text=True)
    got = r.stdout.strip()
    if r.returncode or got != want:
        return f"sources/security_content is at {got or 'nothing'}, sources.lock pins {want}"
    return None


def fetch(url):
    """A test's dataset, fetched by the pinned attack_data commit (never by branch). Raises FetchError on failure."""
    if "/datasets/" not in url or "splunk/attack_data/" not in url:
        raise FetchError(f"not an attack_data dataset URL: {url}")
    rel = "datasets/" + url.split("/datasets/", 1)[1]
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, url.split("/datasets/", 1)[1].replace("/", "__"))
    if not os.path.exists(path):
        lock = LOCK["splunk/attack_data"]
        pinned = lock["fetch"].format(commit=lock["commit"], path=rel)
        r = subprocess.run(["curl", "-sSLf", "--retry", "3", "-o", path + ".part", pinned], capture_output=True, text=True)
        if r.returncode:
            raise FetchError(f"{pinned}: {r.stderr.strip()[:160]}")
        os.replace(path + ".part", path)
    return path


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


# ---------- harness mapping to normalized alert v1 roles ----------
# The bank refers to roles, never to fields. The harness plays the normalizer: it maps the CIM-like keys the
# parsers above produce to role attributes, per event kind, and keeps the raw vendor values the value tables read.
ROLE = {
    "_time": "event.time", "dest": "host.name", "dest_asset_id": "host.asset_id", "user": "user.name", "user_id": "user.name",
    "src_user": "actor.name", "src": "src.ip", "dest_port": "dest.port", "transport": "network.transport", "rule": "network.rule",
    "process": "process.command_line", "process_name": "process.name", "process_path": "process.path", "process_guid": "process.guid",
    "process_hash": "process.sha256", "parent_process_guid": "process.parent_guid", "parent_process_path": "process.parent_path",
    "parent_process_name": "process.parent_name", "registry_path": "registry.path", "registry_value_name": "registry.value_name",
    "registry_value_data": "registry.value_data", "EventCode": "event.type_id", "ImagePath": "file.path",
    "SourceImage": "process.path", "SourceProcessGUID": "process.guid", "TargetImage": "target_process.path",
    "granted_access": "process_access.rights", "CallTrace": "process_access.call_stack",
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


