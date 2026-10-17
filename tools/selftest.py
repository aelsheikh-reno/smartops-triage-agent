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
    return f"bank/triage/questions/{n}.yaml"


PSEXEC = "bank/triage/detections/endpoint/D-0006.yaml"
AV = "bank/triage/detections/endpoint_malware/D-0026.yaml"
IDS = "bank/triage/detections/network/D-0028.yaml"
USB = "bank/triage/detections/data_protection/D-0034.yaml"
RULE_MAP = "bank/intake/rule-map.yaml"
EVIDENCE = "bank/contract/evidence.yaml"
PROPOSALS = "bank/triage/proposals.yaml"
OVERLAY = "bank/triage/customers/selftest/parameters.yaml"


def overlay(*overrides):
    def write(root):
        os.makedirs(os.path.join(root, os.path.dirname(OVERLAY)), exist_ok=True)
        open(os.path.join(root, OVERLAY), "w").write(dump({"customer": "selftest", "overrides": list(overrides)}))
    return write


CUSTOMER = "bank/broker/customers/selftest/verifications.yaml"
MODES = "bank/triage/customers/selftest/modes.yaml"


def customer(modes, verify=(), products=None, **rec_changes):
    """Write a customer layer: product versions, verification records for every non-ambiguous row of the verify tables, modes."""
    def write(root):
        recs = []
        for t in verify:
            doc = yaml.safe_load(open(os.path.join(root, "bank/broker/translations", t + ".yaml")))
            for spec in doc["classes"].values():
                for r in spec.get("rows") or []:
                    if r.get("kind") != "ambiguous":
                        recs.append(dict({"table": t, "row": r["id"], "vendor_doc": (doc.get("references") or ["doc"])[0], "spot_check_alerts": 20,
                                          "checked_by": "product operator", "checked_on": "2026-10-17", "product_version": "1.0",
                                          "expires": "2099-01-01"}, **rec_changes))
        os.makedirs(os.path.join(root, os.path.dirname(CUSTOMER)), exist_ok=True)
        open(os.path.join(root, CUSTOMER), "w").write(dump({"customer": "selftest", "products": products or {t: "1.0" for t in verify},
                                                             "verifications": recs}))
        os.makedirs(os.path.join(root, os.path.dirname(MODES)), exist_ok=True)
        open(os.path.join(root, MODES), "w").write(dump({"customer": "selftest", "modes": modes}))
    return write


AV_TABLES = ["microsoft-defender-for-endpoint", "generic"]


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


def prove_all(root, did, events=5, status="reviewed", aimed="pass", **rec):
    """Plant a reviewed proof record for every close path of one detection, its aimed case file, and a replay coverage
    report that meets the floor (aimed = the aimed case's replay result)."""
    script = (
        "import sys, json, os, yaml; sys.path.insert(0, 'tools'); import bank as B; from engine import executor as E\n"
        f"b = B.load(); d = b['detections']['{did}']\n"
        "ids = [E.path_id(d, p) for p, o, g in E.enumerate_paths(d['flow']) if o.startswith('close')]\n"
        "os.makedirs('bank/triage/proofs', exist_ok=True); os.makedirs('build', exist_ok=True)\n"
        f"rec = dict(id='PR-9001', paths=ids, attacker_position='selftest', why_unrealistic_or_guard='selftest', residual_risk='selftest', aimed_cases=['selftest-aimed'], status='{status}', reviewer='soc lead', reviewed_on='2026-10-17')\n"
        f"rec.update({rec!r})\n"
        "yaml.safe_dump({'proofs': [rec]}, open('bank/triage/proofs/selftest.yaml', 'w'))\n"
        f"os.makedirs('tests/cases/{did}/aimed', exist_ok=True)\n"
        f"yaml.safe_dump(dict(detection='{did}', name='selftest-aimed', reason='selftest', proof='PR-9001', alert={{'host.name': 'h-1'}}), open('tests/cases/{did}/aimed/selftest-aimed.yaml', 'w'))\n"
        f"json.dump({{'detections': {{'{did}': {{'tp_events': {events}, 'paths': {{}}, 'aimed': {{'selftest-aimed': '{aimed}'}}}}}}}}, open('build/replay_coverage.json', 'w'))\n")
    subprocess.run([sys.executable, "-c", script], cwd=root, check=True)


def aimed_d6(overrides):
    """Plant one aimed case for D-0006's step-2 close and the draft proof record it links to."""
    def write(root):
        proof_file([{"id": "PR-1", "paths": [D6_CLOSE], "attacker_position": "x", "why_unrealistic_or_guard": "x", "residual_risk": "x",
                     "aimed_cases": ["selftest-aimed"], "status": "draft"}])(root)
        os.makedirs(os.path.join(root, "tests/cases/D-0006/aimed"), exist_ok=True)
        open(os.path.join(root, "tests/cases/D-0006/aimed/selftest-aimed.yaml"), "w").write(dump({
            "detection": "D-0006", "name": "selftest-aimed", "reason": "selftest", "proof": "PR-1", "overrides": overrides,
            "alert": {"host.name": "ws-07", "user.name": "admin1", "process.parent_name": "cmd.exe", "process.name": "psexec.exe",
                      "process.sha256": "7" * 64, "process.command_line": "psexec.exe -accepteula \\\\srv-02 cmd",
                      "event.time": "2026-10-17T08:00:00Z", "severity": "medium"}}))
    return write


def proof_file(recs):
    def write(root):
        os.makedirs(os.path.join(root, "bank/triage/proofs"), exist_ok=True)
        open(os.path.join(root, "bank/triage/proofs/selftest.yaml"), "w").write(dump({"proofs": recs}))
    return write


SHARED = "tests/fixtures/shared_verification/microsoft-defender-for-endpoint-10.8.yaml"


def shared_at(version_dir):
    def write(root):
        dest = os.path.join(root, "bank/broker/verifications/shared/microsoft-defender-for-endpoint")
        os.makedirs(dest, exist_ok=True)
        shutil.copy(os.path.join(root, SHARED), os.path.join(dest, f"{version_dir}.yaml"))
    return write


D6_CLOSE = "D-0006@v9:1:Q-0000=no > 2:Q-0001=yes"


# (name, gate, change, expected substring or None for "must pass")
CASES = [
    ("question reads a field directly", "validate", y(q("Q-0016"), lambda d: d.setdefault("inputs", {}).update(entity="value:dest")), "reads a field directly"),
    ("schema field name as an input value", "validate", y(q("Q-0016"), lambda d: d.setdefault("inputs", {}).update(entity="dest_ip")), "schema field name"),
    ("Sysmon field name in a detection", "validate", y(PSEXEC, lambda d: d["flow"][1].update(bind={"entity": "TargetImage"})), "schema field name"),
    ("unknown role attribute", "validate", y(q("Q-0016"), lambda d: d.setdefault("inputs", {}).update(entity="role:host.nam")), "not a role attribute"),
    ("role used but not required", "validate", y(PSEXEC, lambda d: d.update(required_roles=[r for r in d["required_roles"] if r != "user"])), "to required_roles"),
    ("old required_alert_fields key", "validate", y(PSEXEC, lambda d: d.update(required_alert_fields=["dest"])), "old key"),
    ("threshold inside a question", "validate", y(q("Q-0045"), lambda d: d.setdefault("inputs", {}).update(min_count=3)), "threshold or comparison"),
    ("count answer without a step rule", "validate", y(PSEXEC, lambda d: first_guard(d, "Q-0045").pop("rule")), "needs a rule"),
    ("literal threshold on a step", "validate", y(PSEXEC, lambda d: first_guard(d, "Q-0045").update(rule={"gte": 3})), "not the literal"),
    ("enum rule value outside the class", "validate", y(AV, lambda d: d["flow"][3].update(rule={"yes": ["blocked"]})), "rule yes values"),
    ("question without a context/triage tag", "validate", y(q("Q-0016"), lambda d: d.pop("kind")), "kind"),
    ("rated below its capability's floor", "validate", y(q("Q-0003"), lambda d: d["attacker_influence"].update(rating="low")), "below its capability's rating"),
    ("below the floor with a written reason passes", "validate",
     y(q("Q-0003"), lambda d: d["attacker_influence"].update(rating="low", below_floor_reason="selftest")), None),
    ("change.window without an independent approver", "validate", t("bank/broker/capabilities.yaml", "requires_independent_approver: true", "requires_independent_approver: false"), "approver who is not an implementer"),
    ("±24h scope", "validate", t("bank/broker/capabilities.yaml", "24h look-back ending at the alert time", "fixed ±24h alert window"), "never ±24h"),
    ("parameter without bounds", "validate", y("bank/triage/parameters.yaml", lambda d: d["parameters"]["alert_history_min_count"].pop("bounds")), "needs default, bounds"),
    ("default outside its bounds", "validate", y("bank/triage/parameters.yaml", lambda d: d["parameters"]["alert_history_min_count"].update(default=99)), "outside bounds"),
    ("precedent validity over 72h", "validate", y(PSEXEC, lambda d: d.setdefault("parameters", {}).update(precedent_validity_hours=168)), "outside bounds"),
    ("reduce-scrutiny override without approval", "validate", overlay({"param": "alert_history_min_count", "value": 6}), "reduces scrutiny"),
    ("reduce-scrutiny list override without approval", "validate", overlay({"param": "web_low_risk_categories", "value": ["advertising", "malware"]}), "reduces scrutiny"),
    ("reduce-scrutiny override with approval passes", "validate",
     overlay({"param": "alert_history_min_count", "value": 6, "approved_by": "soc lead", "owner": "it ops", "expiry": "2027-01-31"}), None),
    ("raise-scrutiny override needs no approval", "validate", overlay({"param": "alert_history_min_count", "value": 2}), None),
    ("override outside bounds", "validate", overlay({"param": "precedent_validity_hours", "value": 100, "approved_by": "x", "owner": "y", "expiry": "z"}), "outside bounds"),
    ("context question missing", "validate", lambda root: os.remove(os.path.join(root, "bank/triage/context/C-03.yaml")), "context questions must be exactly"),
    ("entity_missing reason code missing", "validate", t("bank/triage/reason_codes.yaml", "- code: entity_missing", "- code: entity_gone"), "entity_missing"),
    ("old auto_requires key", "validate", y(IDS, lambda d: d.update(auto_requires=["vendor_mapping_verified"])), "replaced by per-customer"),
    ("value-table row with no kind", "validate",
     y("bank/broker/translations/microsoft-defender-for-endpoint.yaml", lambda d: d["classes"]["run_status"]["rows"][0].pop("kind")), "kind must be"),
    ("verified written into the shared bank row", "validate",
     y("bank/broker/translations/microsoft-defender-for-endpoint.yaml", lambda d: d["classes"]["run_status"]["rows"][0].update(verified=True)), "verified is per customer"),
    # Round 2: thresholds stay Triage-side, classification principle, source authority, per-class parameters.
    ("threshold at the broker in org.prevalence", "validate", y(q("Q-0015"), lambda d: d.setdefault("inputs", {}).update(min_hosts=3)), "threshold or comparison"),
    ("org.prevalence statistic setting as a literal", "validate", y(q("Q-0015"), lambda d: d.setdefault("inputs", {}).update(min_weeks=2)), "bound to a statistic_setting parameter"),
    ("org.prevalence statistic bound to a policy parameter", "validate",
     y(q("Q-0015"), lambda d: d.setdefault("inputs", {}).update(min_weeks={"param": "org_prevalence_min_hosts"})), "bound to a statistic_setting parameter"),
    ("min_weeks above of_weeks", "validate", y("bank/triage/parameters.yaml", lambda d: d["parameters"]["org_prevalence_min_weeks"].update(default=5)), "must not exceed"),
    ("customer policy list inside a value table", "validate",
     y("bank/broker/translations/microsoft-defender-for-endpoint.yaml", lambda d: d["classes"]["run_status"].update(param="usb_non_storage_classes")), "never a customer's policy"),
    ("customer address ranges matched inside a value table", "validate",
     y("bank/broker/translations/generic.yaml", lambda d: next(iter(d["classes"].values()))["rows"][0]["match"].update(cidr_param="internal_networks")), "never a customer's policy"),
    ("vendor-meaning mapping inside a parameter", "validate",
     y("bank/triage/parameters.yaml", lambda d: d["parameters"].update(av_action_map={"default": {"Block": "pre_execution"}, "bounds": {"min_items": 1}, "reduces_scrutiny_when": "grows"})), "never a mapping"),
    ("EDR capability answered from the SIEM although an endpoint API exists", "validate",
     y("bank/broker/capabilities.yaml", lambda d: cap(d, "endpoint.run_status").update(source_authority={"authoritative": "siem_copy", "fallback": ["edr_api"]})), "an endpoint API source exists"),
    ("per-class value for a class C-08 does not have", "validate",
     y("bank/triage/parameters.yaml", lambda d: d["parameters"]["entity_guard_min_alerts"]["by_entity_class"].update(laptop=3)), "not an asset class of C-08"),
    ("per-class value outside bounds", "validate",
     y("bank/triage/parameters.yaml", lambda d: d["parameters"]["entity_guard_min_alerts"]["by_entity_class"].update(server=999)), "outside bounds"),
    ("context rule reads a context question it does not declare", "validate", y(q("Q-0067"), lambda d: d.setdefault("inputs", {}).update(reads=["C-06"])), "context_rule over"),
    # Vendor-leak gate: query language, SIEM product terms, schema field names in bank logic.
    ("query-language token (SPL) in question text", "validate", y(q("Q-0016"), lambda d: d.update(text=d["text"] + " (index=main | tstats count)")), "query-language token"),
    ("query-language token (KQL) in a flow", "validate",
     y(PSEXEC, lambda d: d["flow"][0]["attacker_influence"].update(reason="DeviceEvents | summarize count() by DeviceId")), "query-language token"),
    ("SIEM product term in a context question", "validate", y("bank/triage/context/C-03.yaml", lambda d: d.update(text=d["text"] + " Read from Incident Review.")), "SIEM product term"),
    ("SIEM product term in a capability", "validate", y("bank/broker/capabilities.yaml", lambda d: cap(d, "alert.history").update(measures="Count of notables for the key.")), "SIEM product term"),
    ("schema field name in question prose", "validate", y(q("Q-0016"), lambda d: d.update(text=d["text"] + " Compare dest_ip.")), "schema field name"),
    ("schema field name in a parameter", "validate",
     y("bank/triage/parameters.yaml", lambda d: d["parameters"]["alert_history_min_count"].update(description="Counted by process_guid.")), "schema field name"),
    ("vendor terms in offline metadata and value tables pass", "validate",
     lambda root: (edit_yaml(os.path.join(root, RULE_MAP), lambda d: d["rules"][5].update(data_source=d["rules"][5]["data_source"] + ["Splunk ES notable via | tstats from datamodel=Endpoint"])),
                   edit_yaml(os.path.join(root, "bank/broker/translations/generic.yaml"), lambda d: d.update(feed=d["feed"] + " (sourcetype=XmlWinEventLog, dest_ip)"))), None),
    # Round 3: gates never pass on nothing; raise-only answers; missing context never escalates.
    ("empty family: every endpoint-malware detection removed", "redteam endpoint_malware",
     lambda root: [os.remove(f) for f in __import__("glob").glob(os.path.join(root, "bank/triage/detections/endpoint_malware/*.yaml"))], "loaded 0 flows"),
    ("empty bank: no detection at all", "validate",
     lambda root: [os.remove(f) for f in __import__("glob").glob(os.path.join(root, "bank/triage/detections/*/*.yaml"))], "loaded 0 detections"),
    ("wrong family name (attacker influence)", "redteam vendr", lambda root: None, "unknown family vendr"),
    ("old batch name (replay)", "replay escu", lambda root: None, "unknown family escu"),
    ("fallback-source table not marked fallback", "validate",
     y("bank/broker/translations/microsoft-defender-antivirus-event-log.yaml", lambda d: d.pop("fallback")), "declares fallback: true"),
    ("worst-case default for unknown context", "validate", y("bank/triage/context/C-08.yaml", lambda d: d.update(unanswered_value="server")), "no worst-case default"),
    ("unknown context escalates", "validate", y("bank/triage/context/C-06.yaml", lambda d: d.update(on_unknown="escalate")), "never escalates"),
    ("guard escalates on unknown context", "validate",
     y(USB, lambda d: first_guard(d, "Q-0067").update(when=["yes", "unknown"])), "never escalates"),
    # Round 4: row kinds, per-customer verification, Auto eligibility, technique fallbacks capped at Recommend.
    ("ambiguous row mapped to a close-supporting value", "validate",
     y("bank/broker/translations/microsoft-defender-antivirus-event-log.yaml",
       lambda d: next(r for r in d["classes"]["run_status"]["rows"] if r["id"] == "run_status.1117_block").update(value="pre_execution")), "an ambiguous row maps to"),
    ("Auto with unverified rows on a close path", "validate", customer({"D-0026": "auto"}), "set to Auto while unverified value-table rows"),
    ("Auto with only some of the rows verified", "validate",
     customer({"D-0026": "auto"}, verify=["microsoft-defender-for-endpoint"], products={"microsoft-defender-for-endpoint": "1.0"}),
     "set to Auto while unverified value-table rows"),
    ("Auto with every row on its close paths verified but no proof", "validate", customer({"D-0026": "auto"}, verify=AV_TABLES), "unproven close paths"),
    ("Auto with every row verified and every close path proven passes", "validate",
     lambda root: (customer({"D-0026": "auto"}, verify=AV_TABLES)(root), prove_all(root, "D-0026")), None),
    ("verification with a spot check below 20 alerts", "validate", customer({}, verify=AV_TABLES, spot_check_alerts=19), "below verification_min_spot_check_alerts"),
    ("vendor product version change re-opens verification", "validate",
     customer({}, verify=AV_TABLES, products={"microsoft-defender-for-endpoint": "2.0", "generic": "1.0"}), "re-opens verification"),
    ("expired verification", "validate", customer({}, verify=AV_TABLES, expires="2020-01-01"), "expired"),
    ("verification without a cited vendor doc", "validate", customer({}, verify=AV_TABLES, vendor_doc=""), "missing vendor_doc"),
    ("technique fallback set to Auto in the bank", "validate", y("bank/triage/techniques/T1003.001.yaml", lambda d: d.update(max_mode="auto")), "capped at recommend"),
    ("technique fallback set to Auto for a customer", "validate", customer({"T1003.001": "auto"}), "technique fallbacks are capped at Recommend"),
    # Round 5: the triage layer stays neutral; the contract and its envelope; trust and translation kinds; email quarantine.
    ("vendor name in a triage question", "validate", y(q("Q-0016"), lambda d: d.update(notes="Ask the CrowdStrike console.")), "triage-neutral layer: vendor or product name"),
    ("vendor name in the contract", "validate", t("bank/contract/answer.yaml", "the Tool Broker decides trust", "the Splunk search decides trust"), "triage-neutral layer: vendor or product name"),
    ("rule library name in a detection", "validate", y(PSEXEC, lambda d: d.update(notes="Same logic as the ESCU rule.")), "triage-neutral layer: rule library name"),
    ("rule library name in a triage comment", "validate", lambda root: open(os.path.join(root, "bank/triage/parameters.yaml"), "a").write("# tuned from SigmaHQ\n"),
     "triage-neutral layer: rule library name"),
    ("reference to the broker's translations in a detection", "validate", y(AV, lambda d: d.update(notes="Read through the translation table row for the product.")),
     "triage-neutral layer: reference to the broker"),
    ("context-list ID in a triage question", "validate", y(q("Q-0016"), lambda d: d.setdefault("inputs", {}).update(list="CF-0009")), "triage-neutral layer: reference to the broker"),
    ("broker path in a triage file", "validate", y(q("Q-0049"), lambda d: d.update(notes="See bank/broker/translations.")), "triage-neutral layer: reference to the broker"),
    ("field name in a triage detection's prose", "validate", y(PSEXEC, lambda d: d.update(notes="Filter on parent_process_name.")), "triage-neutral layer"),
    ("query-language token in a triage file", "validate", y(PSEXEC, lambda d: d.update(intent=d["intent"] + " | tstats count by dest")), "triage-neutral layer"),
    ("vendor names inside derived_from pass", "validate", y(PSEXEC, lambda d: d["derived_from"].update(title="Splunk ESCU rule, Sigma and CrowdStrike notes")), None),
    ("answer without request_id", "validate",
     y("bank/contract/envelope_examples.yaml", lambda d: d["answers"][0]["message"].pop("request_id")), "missing request_id"),
    ("answer with a mismatched run_id", "validate",
     y("bank/contract/envelope_examples.yaml", lambda d: d["answers"][0]["message"].update(run_id="other-run")), "the acceptance rule says run_id does not match"),
    ("envelope schema without trust", "validate",
     y("bank/contract/envelope.yaml", lambda d: d["answer"]["required"].remove("trust")), "answer schema must require trust"),
    ("question missing from the contract", "validate",
     y("bank/contract/questions.yaml", lambda d: d.update(questions=[x for x in d["questions"] if x["id"] != "Q-0016"])), "must list every question"),
    ("contract answer type differs from the broker's", "validate",
     y("bank/contract/questions.yaml", lambda d: next(x for x in d["questions"] if x["id"] == "Q-0045")["answer"].update(type="bool")), "differs from what the broker implements"),
    ("standards-defined translation without its standard", "validate",
     y("bank/broker/translations/generic.yaml", lambda d: d["classes"]["http_status_class"]["rows"][0].pop("standard")), "cites its standard"),
    ("model-proposed translation without proposed_by", "validate",
     y("bank/broker/translations/generic.yaml", lambda d: d["classes"]["severity"]["rows"][0].update(kind="proposed")), "records proposed_by: model"),
    ("email quarantine translation not limited to email and DLP questions", "validate",
     y("bank/broker/translations/generic.yaml", lambda d: next(r for r in d["classes"]["control_action"]["rows"] if r["id"] == "control_action.quarantined_pre_delivery").pop("questions")),
     "lists the email and DLP questions it serves"),
    ("email quarantine translation read by an endpoint or network question", "validate",
     y("bank/broker/translations/generic.yaml", lambda d: next(r for r in d["classes"]["control_action"]["rows"] if r["id"] == "control_action.quarantined_pre_delivery").update(questions=["Q-0027"])),
     "limited to email and DLP questions"),
    ("identity groups as the only low-rated yes on a close path", "redteam",
     y(PSEXEC, lambda d: d["flow"][3].update(on_yes="close:benign_true_positive:admin_activity_baselined")), "FAIL D-0006"),
    # Round 6: actor identity, Auto exclusions, human evidence, deadlines and defer, normalized severity, replay data caps.
    ("actor-identity answer (a provisioning account on a list) as the only hard-to-fake yes", "redteam",
     y("bank/triage/detections/identity/D-0025.yaml", lambda d: d["flow"][1].update(on_yes="close:benign_true_positive:provisioning_service_account")), "FAIL D-0025"),
    ("actor-identity tag removed from an actor-account question", "validate", y(q("Q-0020"), lambda d: d.pop("actor_identity")), "tag it actor_identity"),
    ("actor-identity tag removed from the change-implementer question", "validate", y(q("Q-0004"), lambda d: d.pop("actor_identity")), "tag it actor_identity"),
    ("family without replay data that isn't capped", "replay email", y("bank/triage/detections/email/D-0031.yaml", lambda d: [d.pop(k) for k in ("max_mode", "max_mode_reason", "auto_excluded_reason")]),
     "not capped at Recommend"),
    ("destructive detection not capped at Recommend", "validate", y("bank/triage/detections/endpoint/D-0004.yaml", lambda d: [d.pop(k) for k in ("max_mode", "max_mode_reason", "auto_excluded_reason")]),
     "destructive or anti-forensic technique"),
    ("unknown auto_excluded_reason code", "validate", y("bank/triage/detections/endpoint/D-0004.yaml", lambda d: d.update(auto_excluded_reason="looks_risky")), "not a detection-level code"),
    ("Q0 closes on a detection with Q0 off", "validate", y("bank/triage/detections/endpoint/D-0016.yaml", lambda d: d["flow"][0].update(on_yes="close:inherit:precedent_match")), "q0_off_reason is set"),
    ("customer sets a capped detection to Auto", "validate", customer({"D-0031": "auto"}), "capped at Recommend"),
    # B3: an accepted recommendation counted as human evidence, in each place that counts closes
    ("accepted recommendation added to the human-evidence definition", "validate",
     y(EVIDENCE, lambda d: d["human_evidence"]["counts"].update(accepted_recommendation="an analyst accepted the recommendation")), "counts exactly"),
    ("Auto close dropped from what never counts", "validate", y(EVIDENCE, lambda d: d["human_evidence"]["never"].pop("auto_close")), "never count as human evidence"),
    ("C-04 counts closes without the definition", "validate", y("bank/triage/context/C-04.yaml", lambda d: d.update(evidence="all_closes")), "evidence count C-04"),
    ("Q0 counts closes without the definition", "validate", y("bank/triage/context_rules.yaml", lambda d: d["q0"].update(evidence="accepted_recommendations")), "evidence count q0"),
    ("routine-pair proposals count accepted recommendations", "validate", y(PROPOSALS, lambda d: d["proposals"]["routine_pairs"].update(evidence="recommendations_and_overrides")), "evidence count routine_pairs"),
    ("routine rule counts closes without the definition", "validate", y("bank/triage/context_rules.yaml", lambda d: d["entity_guard"]["routine"].pop("evidence")), "evidence count routine (context_rules)"),
    ("list-entry proposals count accepted recommendations", "validate", y(PROPOSALS, lambda d: d["proposals"]["list_entries"].update(evidence="any_close")), "evidence count list_entries"),
    ("closure mining counts accepted recommendations", "validate", y(PROPOSALS, lambda d: d["proposals"]["closure_mining"].pop("evidence")), "evidence count closure_mining"),
    ("threshold proposals scored on accepted recommendations", "validate", y(PROPOSALS, lambda d: d["proposals"]["thresholds"].update(evidence="agreement")), "evidence count thresholds"),
    ("case memory counts closes without the definition", "validate", y("bank/broker/capabilities.yaml", lambda d: cap(d, "case.precedent").pop("evidence")), "evidence count case.precedent"),
    ("list proposals written without the definition", "validate", y("bank/broker/capabilities.yaml", lambda d: cap(d, "list.propose_update").update(evidence="accepted")), "evidence count list.propose_update"),
    ("Q0 in Auto on independent closes alone (no audited close)", "validate",
     y("bank/triage/context_rules.yaml", lambda d: d["q0"]["yes_when"]["all"][0]["any"][1]["C-04.independent_human"].pop("modes")), "in Auto a precedent needs an audited close"),
    # S1, S2: the entity guard
    ("Q0 while another detection fires on the entity", "validate", y("bank/triage/context_rules.yaml", lambda d: d["q0"]["yes_when"]["all"].pop(1)), "distinct_detections lte 1"),
    ("no 24h distinct-detection rule", "validate", y("bank/triage/context_rules.yaml", lambda d: d["entity_guard"]["hot_when"]["any"].pop(2)), "24h distinct-detection rule"),
    # B4: deadlines, defer and the cache
    ("a missed deadline answers unknown", "validate", y("bank/contract/envelope.yaml", lambda d: d["deadline"].update(on_miss="unknown")), "deadline.on_miss must be source_unavailable"),
    ("a cached source_unavailable", "validate", y("bank/contract/envelope.yaml", lambda d: d["cache"]["cached_statuses"].append("source_unavailable")), "source_unavailable is never cached"),
    ("a cached source_unavailable accepted as a valid retry", "validate",
     y("bank/contract/envelope_examples.yaml", lambda d: next(r for r in d["retries"] if r["name"] == "a cached source_unavailable").update(expect="valid")), "was cached"),
    ("a defer past max wait not turned into source_unavailable", "validate", y("bank/contract/envelope.yaml", lambda d: d["defer_rule"].update(past_max_wait="unknown")), "past_max_wait must be source_unavailable"),
    ("a defer past max wait expected to be answered", "validate",
     y("bank/contract/envelope_examples.yaml", lambda d: next(s for s in d["sequences"] if s["name"].startswith("deferred for overload")).update(expect="answered")), "the resolution rule says source_unavailable"),
    ("transport retries bump the attempt number", "validate",
     y("bank/contract/envelope.yaml", lambda d: d["ids"].update(request_id="<run_id>:<step>:<question id>:<attempt>; the attempt grows on every send")), "attempt grows only on a deliberate re-ask"),
    # §3: normalized severity only
    ("a severity comparison on a raw SIEM severity", "validate",
     y("bank/triage/context_rules.yaml", lambda d: d["q0"]["yes_when"]["all"][2]["C-03"].update(not_above="role:reporting_control.severity")), "compare normalized severities only"),
    ("a raw SIEM severity in a counted-severity parameter", "validate",
     y("bank/triage/parameters.yaml", lambda d: d["parameters"]["entity_day_counted_severities"].update(default=["medium", "high", "urgent"])), "outside the normalized scale"),
    ("a SIEM severity mapped off the scale", "validate", y("bank/intake/severity-map.yaml", lambda d: d["siems"]["splunk_es"]["map"].update(critical="sev1")), "not a normalized severity"),
    # S7: the evidence item for the alerted file, never the first
    ("Defender evidence read from the first item", "validate",
     y("bank/broker/translations/microsoft-defender-for-endpoint.yaml", lambda d: d.pop("evidence")), "known answer 'benign sibling prevented, alerted file detected'"),
    # B1, B2, S3: flow guards
    ("user report from the customer's own domain closes", "replay email",
     y("bank/triage/detections/email/D-0032.yaml", lambda d: d["flow"][2].update(guards=[g for g in d["flow"][2]["guards"] if g["question"] != "Q-0075"])), "FAIL D-0032"),
    ("no-interaction close without the recipient-host check", "replay email",
     y("bank/triage/detections/email/D-0031.yaml", lambda d: d["flow"][4].pop("guards")), "FAIL D-0031"),
    ("approved infrastructure source closes a deny alert on its own", "redteam",
     y("bank/triage/detections/network/D-0027.yaml", lambda d: d["flow"][2].pop("guards")), "FAIL D-0027"),
    # §4: one stage per concept, windows look back only
    ("email delivery-stage row serving the DLP question", "validate",
     y("bank/broker/translations/generic.yaml", lambda d: next(r for r in d["classes"]["control_action"]["rows"] if r["id"] == "control_action.quarantined_pre_delivery").update(questions=["Q-0074", "Q-0062"])),
     "serves email questions only"),
    ("a question that looks into the alert window", "validate", y(q("Q-0073"), lambda d: d.update(text="Was the file's hash seen in the alert window on any other host?")), "windows look back only"),
    # Round 7: one executor; test data out of code; replay never loses coverage silently.
    ("vendor name in the executor", "validate", lambda root: open(os.path.join(root, "engine/executor.py"), "a").write("\n# as the CrowdStrike API returns it\n"), "neutral executor: vendor or product name"),
    ("detection ID in the executor", "validate", lambda root: open(os.path.join(root, "engine/executor.py"), "a").write("\nSPECIAL = {'D-0026'}\n"), "neutral executor: detection, technique, question or context-question ID"),
    ("the executor reads a file", "validate", lambda root: open(os.path.join(root, "engine/executor.py"), "a").write("\nimport yaml\n"), "neutral executor: file format"),
    # Round 8: proof status, suggested dispositions, human evidence for flags, guard-only questions, shared verification.
    ("Auto on an unproven path", "validate", customer({"D-0006": "auto"}), "set to Auto with unproven close paths"),
    ("a reviewed proof with no reviewer", "validate",
     proof_file([{"id": "PR-1", "paths": [D6_CLOSE], "attacker_position": "x", "why_unrealistic_or_guard": "x", "residual_risk": "x", "status": "reviewed", "reviewed_on": "2026-10-17"}]),
     "a reviewed proof record needs a reviewer"),
    ("a proof pointing to a missing path", "validate",
     proof_file([{"id": "PR-1", "paths": ["D-0006@v9:1:Q-0000=no > 2:Q-9999=yes"], "attacker_position": "x", "why_unrealistic_or_guard": "x", "residual_risk": "x", "status": "draft"}]),
     "does not exist in the current flows"),
    ("a stale proof (an earlier detection version)", "validate",
     proof_file([{"id": "PR-1", "paths": [D6_CLOSE.replace("@v9", "@v8")], "attacker_position": "x", "why_unrealistic_or_guard": "x", "residual_risk": "x", "status": "draft"}]),
     "does not exist in the current flows"),
    ("a draft proof does not make Auto eligible", "validate", lambda root: (customer({"D-0026": "auto"}, verify=AV_TABLES)(root), prove_all(root, "D-0026", status="draft")),
     "set to Auto with unproven close paths"),
    ("a proof without enough replay does not make Auto eligible", "validate", lambda root: (customer({"D-0026": "auto"}, verify=AV_TABLES)(root), prove_all(root, "D-0026", events=4)),
     "set to Auto with unproven close paths"),
    # Round 9: the proof floor and aimed cases.
    ("a proof with no aimed case", "validate",
     proof_file([{"id": "PR-1", "paths": [D6_CLOSE], "attacker_position": "x", "why_unrealistic_or_guard": "x", "residual_risk": "x", "aimed_cases": [], "status": "draft"}]),
     "a proof record needs at least one aimed case"),
    ("an aimed case that closes", "replay endpoint", aimed_d6({"Q-0001": True, "Q-0014": 5}), "FAIL D-0006 aimed selftest-aimed"),
    # Round 10: gate fixes for the bank proofs (#32).
    ("a contract triage question with no bank file", "validate",
     y("bank/contract/questions.yaml", lambda d: d["questions"].append({"id": "Q-9999", "answer": {"type": "bool"}})), "must list every question exactly once"),
    ("a contract context question that is not guard-only, with no bank file", "validate",
     y("bank/contract/questions.yaml", lambda d: d["questions"].append({"id": "C-99", "kind": "context", "answer": {"type": "bool"}})), "must list every question exactly once"),
    ("a stale proof in a per-detection proof folder", "validate",
     lambda root: (os.makedirs(os.path.join(root, "bank/triage/proofs/D-0006"), exist_ok=True),
                   open(os.path.join(root, "bank/triage/proofs/D-0006/selftest.yaml"), "w").write(dump({"proofs": [
                       {"id": "PR-1", "paths": [D6_CLOSE.replace("@v9", "@v8")], "attacker_position": "x", "why_unrealistic_or_guard": "x", "residual_risk": "x",
                        "aimed_cases": ["x"], "status": "draft"}]}))),
     "does not exist in the current flows"),
    ("a link with no link-click telemetry still closing", "replay email",
     y("tests/cases/D-0031/the-same-with-attachment-and-link-click-telemetry-close.yaml", lambda c: c.update(coverage=["attachment_open_telemetry"])), "FAIL D-0031"),
    ("a proof bar below the floor of 5", "validate", y("bank/contract/proof.yaml", lambda c: c["parameters"]["proof_min_tp_events"]["bounds"].update(min=4)),
     "below the floor of 5"),
    ("a suggests value that isn't a real disposition", "validate",
     y(PSEXEC, lambda d: d["flow"][4].update(flag_suggests={"on_yes": {"suggests": "close:benign_true_positive:no_such_reason", "reason": "selftest"}})), "not a real close disposition"),
    ("a suggestion on an edge that is not a flag", "validate",
     y(PSEXEC, lambda d: d["flow"][4].update(flag_suggests={"on_no": {"suggests": "close:benign_true_positive:approved_change", "reason": "selftest"}})), "attaches to a flag edge"),
    ("human evidence: an analyst's own close of a flag no longer counted", "validate",
     y(EVIDENCE, lambda d: d["human_evidence"]["counts"].pop("flag_own_close")), "counts exactly"),
    ("human evidence: an accepted flag suggestion counted", "validate",
     y(EVIDENCE, lambda d: (d["human_evidence"]["never"].pop("flag_accepted_suggestion"), d["human_evidence"]["counts"].update(flag_accepted_suggestion="x"))), "counts exactly"),
    ("human evidence: an override of a flag's suggestion not counted per analyst", "validate",
     y(EVIDENCE, lambda d: d["human_evidence"]["independent_kinds"].remove("flag_override")), "independent_kinds are the human closes"),
    ("a guard-only question read by Q0", "validate",
     y("bank/contract/questions.yaml", lambda d: next(x for x in d["questions"] if x["id"] == "C-06").update(guard_only=True)), "reads guard-only context question C-06"),
    ("a guard-only question used in a step", "validate",
     lambda root: (edit_yaml(os.path.join(root, "bank/contract/questions.yaml"), lambda d: next(x for x in d["questions"] if x["id"] == "C-08").update(guard_only=True)),
                   edit_yaml(os.path.join(root, PSEXEC), lambda d: d["flow"][1].update(question="Q-0067"))),
     "it may only be a guard"),
    ("a shared verification filed under the wrong version", "validate", shared_at("10.9"), "lives at bank/broker/verifications/shared/microsoft-defender-for-endpoint/10.8.yaml"),
    ("a shared verification filed correctly passes", "validate", shared_at("10.8"), None),
    ("context-question ID in the executor", "validate", lambda root: open(os.path.join(root, "engine/executor.py"), "a").write("\nCROWN_JEWEL = 'C-06'\n"),
     "neutral executor: detection, technique, question or context-question ID"),
    ("no context answer listed as needed for a close", "validate", y("bank/triage/context_rules.yaml", lambda d: d.update(closes_need_known=[])), "closes_need_known must list"),
    ("entity class taken from a context question that is not one", "validate",
     y("bank/triage/context_rules.yaml", lambda d: d["entity_guard"]["entity_class"].update(question="C-99")), "entity_class.question must name a context question"),
    ("unknown counted as an entity class", "validate",
     y("bank/triage/context_rules.yaml", lambda d: d["entity_guard"]["entity_class"]["classes"].append("unknown")), "never unknown"),
    ("field name in the executor", "validate", lambda root: open(os.path.join(root, "engine/executor.py"), "a").write("\nKEY = 'process_guid'\n"), "neutral executor: schema field name"),
    ("not replayable without a reason", "validate", y("tests/replay/coverage.yaml", lambda d: d["detections"]["D-0031"].pop("reason")), "not replayable needs a reason"),
    ("not replayable but not capped", "validate",
     lambda root: (edit_yaml(os.path.join(root, "tests/replay/coverage.yaml"), lambda d: d["detections"].update({"D-0006": {"replayable": False, "reason": "selftest"}}))),
     "must be capped at Recommend"),
    ("replayable without a fires_on rule", "validate", lambda root: os.remove(os.path.join(root, "tests/replay/fires_on/D-0006.yaml")), "needs a fires_on rule"),
    ("replayable detection that replays zero events", "replay endpoint",
     y("tests/replay/fires_on/D-0006.yaml", lambda d: d.update(fires_when={"field": "process_name", "op": "in", "value": ["no-such.exe"]})), "0 true-positive events"),
    ("failed dataset download", "replay endpoint",
     lambda root: (edit_text(os.path.join(root, "tests/replay/sources.lock"), 'commit: "aafa53ea228fbab8d9ac3e33c9275fab2136909d"', 'commit: "0000000000000000000000000000000000000000"')),
     "download failed"),
    ("regression case expectation lowered", "replay endpoint_malware",
     y("tests/cases/D-0026/no-hash-high-risk-class-detected-not-blocked-must-escalate.yaml", lambda d: d.update(expect={"outcome": "close:mitigated_true_positive"})), "FAIL D-0026"),
]


def run(root, gate):
    """gate: validate, redteam or replay, optionally followed by batch arguments ("redteam vendr")."""
    name, *args = gate.split()
    cmd = {"validate": ["tools/validate.py"], "redteam": ["tools/redteam_paths.py", "--quiet"], "replay": ["tools/replay.py", "--strict"]}[name] + args
    r = subprocess.run([sys.executable] + cmd, cwd=root, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def main():
    misses = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "base")
        for d in ("bank", "tools", "docs", "engine", "tests"):
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
