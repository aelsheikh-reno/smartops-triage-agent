#!/usr/bin/env python3
"""Self-test for the gates: plant each forbidden pattern in a scratch copy of the bank and check that the
validator (or the close-path gate) rejects it, and that allowed changes pass. Exit 1 if any gate misses one.

Usage: tools/selftest.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dump = lambda d: yaml.safe_dump(d, sort_keys=False, width=200, allow_unicode=True)


def edit_yaml(path, fn):
    d = yaml.safe_load(open(path))
    fn(d)
    open(path, "w").write(dump(d))


def edit_text(path, old, new):
    s = open(path).read()
    assert old in s, (path, old)
    open(path, "w").write(s.replace(old, new, 1))


def q(n):
    return f"bank/questions/{n}.yaml"


PSEXEC = "bank/detections/escu/detect_psexec_with_accepteula_flag.yaml"
OVERLAY = "bank/overlays/customer/selftest/parameters.yaml"


def overlay(*overrides):
    def write(root):
        os.makedirs(os.path.join(root, os.path.dirname(OVERLAY)), exist_ok=True)
        open(os.path.join(root, OVERLAY), "w").write(dump({"customer": "selftest", "overrides": list(overrides)}))
    return write


def y(path, fn):
    return lambda root: edit_yaml(os.path.join(root, path), fn)


def t(path, old, new):
    return lambda root: edit_text(os.path.join(root, path), old, new)


def cap(d, name):
    return next(c for c in d["capabilities"] if c["name"] == name)


def first_guard(d, qid):
    for st in d["flow"]:
        for g in st.get("guards") or []:
            if g["question"] == qid:
                return g


# (name, gate, change, expected substring or None for "must pass")
CASES = [
    ("question reads a field directly", "validate", y(q("Q-0016"), lambda d: d["capability"]["inputs"].update(entity="value:dest")), "reads a field directly"),
    ("schema field name as an input value", "validate", y(q("Q-0016"), lambda d: d["capability"]["inputs"].update(entity="dest_ip")), "schema field name"),
    ("Sysmon field name in a detection", "validate", y(PSEXEC, lambda d: d["flow"][1].update(bind={"entity": "TargetImage"})), "schema field name"),
    ("unknown role attribute", "validate", y(q("Q-0016"), lambda d: d["capability"]["inputs"].update(entity="role:host.nam")), "not a role attribute"),
    ("role used but not required", "validate", y(PSEXEC, lambda d: d.update(required_roles=[r for r in d["required_roles"] if r != "user"])), "to required_roles"),
    ("old required_alert_fields key", "validate", y(PSEXEC, lambda d: d.update(required_alert_fields=["dest"])), "old key"),
    ("threshold inside a question", "validate", y(q("Q-0045"), lambda d: d["capability"]["inputs"].update(min_count=3)), "threshold or comparison"),
    ("count answer without a step rule", "validate", y(PSEXEC, lambda d: first_guard(d, "Q-0045").pop("rule")), "needs a rule"),
    ("literal threshold on a step", "validate", y(PSEXEC, lambda d: first_guard(d, "Q-0045").update(rule={"gte": 3})), "not the literal"),
    ("enum rule value outside the class", "validate", y("bank/detections/vendor/av_detection.yaml", lambda d: d["flow"][3].update(rule={"yes": ["blocked"]})), "rule yes values"),
    ("question without a context/triage tag", "validate", y(q("Q-0016"), lambda d: d.pop("kind")), "kind"),
    ("rated below its capability's floor", "validate", y(q("Q-0003"), lambda d: d["attacker_influence"].update(rating="low")), "below its capability's rating"),
    ("below the floor with a written reason passes", "validate",
     y(q("Q-0003"), lambda d: d["attacker_influence"].update(rating="low", below_floor_reason="selftest")), None),
    ("change.window without an independent approver", "validate", t("bank/capabilities.yaml", "requires_independent_approver: true", "requires_independent_approver: false"), "approver who is not an implementer"),
    ("±24h scope", "validate", t("bank/capabilities.yaml", "24h look-back ending at the alert time", "fixed ±24h alert window"), "never ±24h"),
    ("parameter without bounds", "validate", y("bank/parameters.yaml", lambda d: d["parameters"]["alert_history_min_count"].pop("bounds")), "needs default, bounds"),
    ("default outside its bounds", "validate", y("bank/parameters.yaml", lambda d: d["parameters"]["alert_history_min_count"].update(default=99)), "outside bounds"),
    ("precedent validity over 72h", "validate", y(PSEXEC, lambda d: d.setdefault("parameters", {}).update(precedent_validity_hours=168)), "outside bounds"),
    ("reduce-scrutiny override without approval", "validate", overlay({"param": "alert_history_min_count", "value": 6}), "reduces scrutiny"),
    ("reduce-scrutiny list override without approval", "validate", overlay({"param": "web_low_risk_categories", "value": ["advertising", "malware"]}), "reduces scrutiny"),
    ("reduce-scrutiny override with approval passes", "validate",
     overlay({"param": "alert_history_min_count", "value": 6, "approved_by": "soc lead", "owner": "it ops", "expiry": "2027-01-31"}), None),
    ("raise-scrutiny override needs no approval", "validate", overlay({"param": "alert_history_min_count", "value": 2}), None),
    ("override outside bounds", "validate", overlay({"param": "precedent_validity_hours", "value": 100, "approved_by": "x", "owner": "y", "expiry": "z"}), "outside bounds"),
    ("context question missing", "validate", lambda root: os.remove(os.path.join(root, "bank/context/C-03.yaml")), "context questions must be exactly"),
    ("entity_missing reason code missing", "validate", t("bank/reason_codes.yaml", "- code: entity_missing", "- code: entity_gone"), "entity_missing"),
    ("unverified product rows without the cap", "validate", y("bank/detections/vendor/ids_alert.yaml", lambda d: d.pop("auto_requires")), "declare auto_requires"),
    ("value-table row without verified", "validate",
     y("bank/recipes/value_tables/microsoft-defender-for-endpoint.yaml", lambda d: d["classes"]["run_status"]["rows"][0].pop("verified")), "verified must be"),
    # Round 2: thresholds stay Triage-side, classification principle, source authority, per-class parameters.
    ("threshold at the broker in org.prevalence", "validate", y(q("Q-0015"), lambda d: d["capability"]["inputs"].update(min_hosts=3)), "threshold or comparison"),
    ("org.prevalence statistic setting as a literal", "validate", y(q("Q-0015"), lambda d: d["capability"]["inputs"].update(min_weeks=2)), "bound to a recipe_statistic parameter"),
    ("org.prevalence statistic bound to a policy parameter", "validate",
     y(q("Q-0015"), lambda d: d["capability"]["inputs"].update(min_weeks={"param": "org_prevalence_min_hosts"})), "bound to a recipe_statistic parameter"),
    ("min_weeks above of_weeks", "validate", y("bank/parameters.yaml", lambda d: d["parameters"]["org_prevalence_min_weeks"].update(default=5)), "must not exceed"),
    ("customer policy list inside a value table", "validate",
     y("bank/recipes/value_tables/microsoft-defender-for-endpoint.yaml", lambda d: d["classes"]["run_status"].update(param="usb_non_storage_classes")), "never a customer's policy"),
    ("customer address ranges matched inside a value table", "validate",
     y("bank/recipes/value_tables/generic.yaml", lambda d: next(iter(d["classes"].values()))["rows"][0]["match"].update(cidr_param="internal_networks")), "never a customer's policy"),
    ("vendor-meaning mapping inside a parameter", "validate",
     y("bank/parameters.yaml", lambda d: d["parameters"].update(av_action_map={"default": {"Block": "pre_execution"}, "bounds": {"min_items": 1}, "reduces_scrutiny_when": "grows"})), "never a mapping"),
    ("EDR capability answered from the SIEM although an endpoint API exists", "validate",
     y("bank/capabilities.yaml", lambda d: cap(d, "endpoint.run_status").update(source_authority={"authoritative": "siem_copy", "fallback": ["edr_api"]})), "an endpoint API source exists"),
    ("per-class value for a class C-08 does not have", "validate",
     y("bank/parameters.yaml", lambda d: d["parameters"]["entity_guard_min_alerts"]["by_entity_class"].update(laptop=3)), "not an asset class of C-08"),
    ("per-class value outside bounds", "validate",
     y("bank/parameters.yaml", lambda d: d["parameters"]["entity_guard_min_alerts"]["by_entity_class"].update(server=999)), "outside bounds"),
    ("context rule reads a context question it does not declare", "validate", y(q("Q-0067"), lambda d: d["capability"]["inputs"].update(reads=["C-06"])), "context_rule over"),
    # Vendor-leak gate: query language, SIEM product terms, schema field names in bank logic.
    ("query-language token (SPL) in question text", "validate", y(q("Q-0016"), lambda d: d.update(text=d["text"] + " (index=main | tstats count)")), "query-language token"),
    ("query-language token (KQL) in a flow", "validate",
     y(PSEXEC, lambda d: d["flow"][0]["attacker_influence"].update(reason="DeviceEvents | summarize count() by DeviceId")), "query-language token"),
    ("SIEM product term in a context question", "validate", y("bank/context/C-03.yaml", lambda d: d.update(text=d["text"] + " Read from Incident Review.")), "SIEM product term"),
    ("SIEM product term in a capability", "validate", y("bank/capabilities.yaml", lambda d: cap(d, "alert.history").update(measures="Count of notables for the key.")), "SIEM product term"),
    ("schema field name in question prose", "validate", y(q("Q-0016"), lambda d: d.update(text=d["text"] + " Compare dest_ip.")), "schema field name"),
    ("schema field name in a parameter", "validate",
     y("bank/parameters.yaml", lambda d: d["parameters"]["alert_history_min_count"].update(description="Counted by process_guid.")), "schema field name"),
    ("vendor terms in offline metadata and value tables pass", "validate",
     lambda root: (edit_yaml(os.path.join(root, PSEXEC), lambda d: d.update(data_source=d["data_source"] + ["Splunk ES notable via | tstats from datamodel=Endpoint"])),
                   edit_yaml(os.path.join(root, "bank/recipes/value_tables/generic.yaml"), lambda d: d.update(feed=d["feed"] + " (sourcetype=XmlWinEventLog, dest_ip)"))), None),
    ("identity groups as the only low-rated yes on a close path", "redteam",
     y(PSEXEC, lambda d: d["flow"][3].update(on_yes="close:benign_true_positive:admin_activity_baselined")), "FAIL escu:detect_psexec"),
]


def run(root, gate):
    cmd = {"validate": ["tools/validate.py"], "redteam": ["tools/redteam_paths.py", "--quiet"]}[gate]
    r = subprocess.run([sys.executable] + cmd, cwd=root, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    misses = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "base")
        for d in ("bank", "tools", "docs"):
            shutil.copytree(os.path.join(ROOT, d), os.path.join(base, d), ignore=shutil.ignore_patterns("__pycache__"))
        if os.path.isdir(os.path.join(ROOT, "sources")):
            os.symlink(os.path.join(ROOT, "sources"), os.path.join(base, "sources"))
        rc, out = run(base, "validate")
        if rc:
            print("FAIL the unmodified bank does not validate:\n" + out[-2000:])
            return 1
        for i, (name, gate, change, expect) in enumerate(CASES):
            root = os.path.join(tmp, f"case{i}")
            shutil.copytree(base, root, symlinks=True)
            change(root)
            rc, out = run(root, gate)
            ok = (rc == 0) if expect is None else (rc != 0 and expect in out)
            misses += not ok
            print(f"  {'ok  ' if ok else 'MISS'} {gate:<8} {name}" + ("" if ok else f"\n       expected {'pass' if expect is None else repr(expect)}, got rc={rc}: {out.strip().splitlines()[-1] if out.strip() else ''}"))
    print(f"\nselftest: {len(CASES) - misses} of {len(CASES)} planted cases handled -> {'PASS' if not misses else 'FAIL'}")
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
