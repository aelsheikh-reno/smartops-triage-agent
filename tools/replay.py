#!/usr/bin/env python3
"""Replay gate: run flows on true-positive events against a clean-room customer.

For each rule-level detection whose source rule has test datasets (splunk/attack_data), and for
the vendor families mapped below, this fetches the datasets, normalises events to the bank's
alert fields, keeps the events the source rule would fire on, and runs the flow with a clean-room
customer: empty lists, no baselines, no change windows, no precedents, no reputation hits.
Telemetry in the dataset itself (alert fields, connection outcomes) is used as-is.

A close with disposition false_positive, benign_true_positive or inherit on a true-positive event
FAILS. A close as mitigated_true_positive (the control stopped it) is reported separately; with
--strict it fails too.

This is a test harness, not bank content: it names source formats and products.
Usage: tools/replay.py [--strict] [ids...]
"""
import csv
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
        n.update(signature=e.get("Threat Name"), category=(e.get("Category Name") or "").lower(), file_path=e.get("Path"),
                 file_name=base((e.get("Path") or "").split("->")[-1]), file_hash=None, user=e.get("Detection User"),
                 action="blocked" if eid == "1117" and (e.get("Action Name") or "").lower() in ("quarantine", "remove", "clean", "block") else (e.get("Action Name") or "").lower(),
                 _kind="av")
    return n


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
 "escu:add_or_set_antivirus_exclusion": lambda n: re.search(r"(add|set)-mppreference ", c(n)) and re.search(r"-exclusion|-controlledfolderaccessallowedapplications|-attacksurfacereductiononlyexclusions", c(n)),
 "escu:windows_event_log_cleared": lambda n: n.get("_kind") == "logclear",
 "escu:detect_remote_access_software_usage_process": lambda n: pn(n) in RMM,
 "escu:suspicious_rundll32_no_command_line_arguments": lambda n: pn(n) == "rundll32.exe" and re.search(r'rundll32(\.exe)?"?\s*$', c(n)),
 "escu:suspicious_regsvr32_register_suspicious_path": lambda n: pn(n) == "regsvr32.exe" and re.search(r"\\appdata\\|\\programdata\\|\\windows\\temp\\", c(n)) and not re.search(r"\.dll|\.ax|\.ocx", c(n)),
 "escu:detect_mshta_url_in_command_line": lambda n: pn(n) == "mshta.exe" and re.search(r"https?://", c(n)),
 "escu:windows_vulnerable_driver_installed": lambda n: n.get("_kind") == "service" and "kernel" in (n.get("ServiceType") or "").lower() and base(n.get("ImagePath")) in LOLDRV,
 "escu:detect_sharphound_usage": lambda n: pn(n) == "sharphound.exe" or n.get("original_file_name") == "sharphound.exe",
 "vendor:ids_alert": lambda n: n.get("_kind") == "ids",
 "vendor:av_detection": lambda n: n.get("_kind") == "av",
 "vendor:firewall_deny": lambda n: n.get("_kind") == "conn" and n.get("action") == "blocked",
}
# Vendor families replayed on vendor telemetry that ESCU tests ship with.
VENDOR = {
 "vendor:ids_alert": ["detections/network/cisco_secure_firewall___intrusion_events_by_threat_activity.yml", "detections/network/cisco_secure_firewall___high_priority_intrusion_classification.yml"],
 "vendor:av_detection": ["detections/endpoint/windows_defender_threat_detected_on_kernel_object_path.yml"],
 "vendor:firewall_deny": ["detections/network/cisco_secure_firewall___blocked_connection.yml"],
}
NOT_REPLAYABLE = {
 "vendor:waf_alert": "no WAF event dataset ships with any ESCU test",
 "vendor:email_gateway": "no email-gateway event dataset ships with any ESCU test",
 "vendor:user_reported_phishing": "no user-report dataset exists in splunk/attack_data",
 "vendor:dlp_match": "no DLP event dataset ships with any ESCU test",
 "vendor:proxy_block": "ESCU proxy datasets hold allowed requests only, no URL-filter blocks",
 "vendor:removable_media": "no device-control event dataset ships with any ESCU test",
}


# ---------- clean-room customer ----------
def answer(cap, inputs, n, ctx):
    fields = [f for _, f in B.walk_refs(inputs)]
    if any(f not in ("fingerprint",) and n.get(f) in (None, "") for f in fields):
        return "unknown"
    if cap == "alert.field":
        field = inputs["field"].split(":", 1)[1]
        allowed = inputs["in"]
        if isinstance(allowed, dict):
            allowed = ctx["params"][allowed["param"]]["default"]
        return "yes" if str(n.get(field)).lower() in {str(v).lower() for v in allowed} else "no"
    if cap == "traffic.denied_only":
        conns = [x for x in ctx["conns"] if x.get("src") == n.get("src")]
        return "unknown" if not conns else "yes" if all(x.get("action") == "blocked" for x in conns) else "no"
    if cap in ("entity.baseline", "org.prevalence", "vuln.not_applicable", "email.message_status", "email.no_interaction", "file.signer"):
        return "unknown"
    return "no"   # case.precedent, list.lookup, identity.groups, change.window, *.reputation: empty in a clean room


def run_flow(b, d, n, ctx):
    trail = []
    for st in d["flow"]:
        q = b["questions"][st["question"]]
        a = answer(q["capability"]["name"], B.step_inputs(q, st), n, ctx)
        out = st["on_" + a]
        trail.append(f"{st['question']}={a}")
        if out != "next":
            return out, trail
    return "flag", trail


def main():
    strict = "--strict" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    b = B.load()
    ctx = {"params": b["parameters"]}
    rows, cannot, fails, mitigated = [], [], [], []
    for did, d in sorted(b["detections"].items()):
        if only and not any(did.startswith(o) for o in only):
            continue
        if did in NOT_REPLAYABLE:
            cannot.append((did, NOT_REPLAYABLE[did]))
            continue
        src = d.get("source") if isinstance(d.get("source"), dict) else {}
        rules = VENDOR.get(did) or ([src["path"]] if src.get("repo") not in (None, "internal") else [])
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
        ctx["conns"] = [x for x in evs if x.get("_kind") == "conn"]
        tp = [x for x in evs if P[did](x)]
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
    bad = fails or (strict and mitigated)
    print(f"\nreplay: {sum(r[2] for r in rows)} TP events in {len(rows)} detections; {len(fails)} benign/FP closes, {len(mitigated)} mitigated closes"
          f" -> {'FAIL' if bad else 'PASS'}{' (strict)' if strict else ''}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
