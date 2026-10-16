#!/usr/bin/env python3
"""Validate the question bank. Exit 1 on any error."""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

REQUIRED = {
    "question": ["id", "text", "tests", "capability", "source", "license", "text_origin", "legal_review", "status", "version"],
    "explanation": ["id", "name", "description", "source", "license", "version"],
    "fact": ["id", "name", "description", "fields", "collected_by", "version"],
    "rule": ["id", "name", "techniques", "data_source", "telemetry_class", "required_alert_fields", "intent", "fp_quality", "fingerprint", "precedent_validity", "flow", "source", "license", "status", "version"],
    "technique": ["id", "name", "attack_version", "max_mode", "assumed_alert_fields", "fingerprint", "precedent_validity", "flow", "source", "license", "status", "version"],
}
# Integration names and query syntax that must not appear outside source/data_source/license fields.
FORBIDDEN = re.compile(r"\b(splunk|servicenow|jira|crowdstrike|sentinelone|qradar|carbon black|tstats|sourcetype|index\s*=|inputlookup|\|\s*stats)\b", re.I)
EXEMPT_KEYS = {"source", "data_source", "license", "_file", "seed_from"}
TELEMETRY = {"process_creation", "process_access", "registry", "image_load", "driver_load", "file", "network", "dns",
             "authentication", "account_management", "log_management", "service_install"}
ATTACK = os.path.join(B.ROOT, "sources/attack-stix-data/enterprise-attack/enterprise-attack-20.0.json")


def scan_text(obj, path=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k not in EXEMPT_KEYS:
                yield from scan_text(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from scan_text(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        m = FORBIDDEN.search(obj)
        if m:
            yield path, m.group(0)


def main():
    b = B.load()
    errors, warnings, info = [], [], []
    err = lambda where, msg: errors.append(f"{where}: {msg}")
    caps, params = b["capability_by_name"], b["parameters"]
    budget = b["capabilities"]["scope"]["max_calls_per_alert"]

    for kind, coll in (("question", b["questions"]), ("explanation", b["explanations"]), ("fact", b["facts"])):
        for i, doc in coll.items():
            for k in REQUIRED[kind]:
                if k not in doc:
                    err(doc["_file"], f"missing {k}")
    for fid, f in b["facts"].items():
        if f.get("collected_by") == "bank_seed" and not f.get("license"):
            err(f["_file"], "bank_seed fact needs license")

    for qid, q in b["questions"].items():
        w = q["_file"]
        if q["tests"] not in b["explanations"]:
            err(w, f"tests unknown explanation {q['tests']}")
        cap = q.get("capability") or {}
        if not isinstance(cap, dict) or cap.get("name") not in caps:
            err(w, f"unknown capability {cap.get('name') if isinstance(cap, dict) else cap}")
            continue
        if caps[cap["name"]].get("flow_use") == "forbidden":
            err(w, f"capability {cap['name']} cannot back a question")
        for lid in B.list_refs(q):
            if lid not in b["facts"]:
                err(w, f"unknown context fact {lid}")
        for pv in (cap.get("params") or {}).values():
            if isinstance(pv, dict) and pv.get("param") not in params:
                err(w, f"unknown parameter {pv}")
        if q["status"] not in ("draft", "approved"):
            err(w, f"bad status {q['status']}")
        if q["status"] == "approved" and not q.get("approved_by"):
            err(w, "approved without approved_by")
        lic = q["license"] if isinstance(q["license"], list) else [q["license"]]
        if q["text_origin"] != "original" and any(l != "Apache-2.0" for l in lic) and not q["legal_review"]:
            err(w, "text copied from non-Apache source needs legal_review: true")
        if "answer_source" in q or "enrichment" in (q.get("needs") or {}):
            err(w, "old answer_source/enrichment keys; declare one capability")
        if any(B.has_unverified_seed(b["facts"][l]) for l in B.list_refs(q) if l in b["facts"]):
            info.append(f"{qid}: reads unverified seed data; its closes flag until onboarding verifies the entries")

    for what, coll in (("capabilities", [b["capabilities"]]), ("questions", b["questions"].values()), ("facts", b["facts"].values()),
                       ("detections", b["detections"].values()), ("techniques", b["techniques"].values())):
        for doc in coll:
            for path, hit in scan_text(doc):
                err(doc.get("_file", "bank/capabilities.yaml"), f"tool name or query syntax '{hit}' at {path}")

    attack_ids = None
    if os.path.exists(ATTACK):
        with open(ATTACK) as fh:
            data = json.load(fh)
        attack_ids = {r["external_id"] for o in data["objects"] if o["type"] == "attack-pattern"
                      and not o.get("revoked") and not o.get("x_mitre_deprecated")
                      for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"}
    else:
        warnings.append("ATT&CK v20.0 data not found under sources/; technique ids not checked")

    for kind, d in B.flows(b):
        w = d["_file"]
        for k in REQUIRED[kind]:
            if k not in d:
                err(w, f"missing {k}")
        if kind == "technique" and d.get("max_mode") != "recommend":
            err(w, "technique fallback must be capped at recommend")
        techs = d.get("techniques", [d["id"]] if kind == "technique" else [])
        for t in techs:
            if attack_ids is not None and t not in attack_ids:
                err(w, f"technique {t} not active in ATT&CK v20.0")
            if kind == "rule" and t not in b["techniques"]:
                warnings.append(f"{d['id']}: no technique fallback for {t}")
        for tc in d.get("telemetry_class", []):
            if tc not in TELEMETRY:
                err(w, f"unknown telemetry_class {tc}")
        for step, edge, bad in B.tainted_closes(b, d.get("flow", [])):
            info.append(f"{d['id']}: close at step {step} ({edge}) flags until onboarding verifies seed data used at step(s) {bad}")
        for e in d.get("explanations", []):
            if e not in b["explanations"]:
                err(w, f"unknown explanation {e}")
        fields = set(d.get("required_alert_fields") or d.get("assumed_alert_fields") or [])
        avail = fields | set(d.get("derived_fields") or {}) | {"fingerprint"}
        for fp in d.get("fingerprint", []):
            if fp not in avail and fp not in ("writer_hash", "driver_hash", "source_image_hash"):
                err(w, f"fingerprint field {fp} not available")
        flow = d.get("flow", [])
        if not 1 <= len(flow) <= 5:
            err(w, f"flow has {len(flow)} steps (1-5 allowed)")
        if len(flow) > budget:
            err(w, f"flow exceeds call budget {budget}")
        for n, st in enumerate(flow, 1):
            where = f"{w} step {n}"
            if st.get("step") != n:
                err(where, "steps must be numbered 1..n")
            q = b["questions"].get(st.get("question"))
            if not q:
                err(where, f"unknown question {st.get('question')}")
                continue
            if n == 1 and (q["id"] != "Q-0000" or st["on_yes"] != "close:inherit:precedent_match"):
                err(where, "flow must start with Q-0000 closing as precedent_match")
            cap = caps.get(q["capability"]["name"], {})
            for edge in ("on_yes", "on_no", "on_unknown"):
                v = st.get(edge)
                m = B.OUTCOME.match(v or "")
                if not m:
                    err(where, f"{edge} invalid outcome {v!r}")
                    continue
                if m.group(2):
                    rc = b["reason_codes"].get(m.group(3))
                    if not rc:
                        err(where, f"unknown reason code {m.group(3)}")
                    elif rc["disposition"] != m.group(2):
                        err(where, f"{m.group(3)} is {rc['disposition']}, not {m.group(2)}")
                    if edge == "on_unknown":
                        err(where, "unknown must never close")
                    if cap.get("escalate_only"):
                        err(where, f"escalate_only capability {cap['name']} cannot close")
            if cap.get("escalate_only") and st["on_yes"] != "escalate":
                err(where, f"escalate_only capability {cap['name']}: a hit must escalate")
            if n == len(flow) and "next" in (st["on_yes"], st["on_no"], st["on_unknown"]):
                err(where, "last step cannot fall through with next")
            for ref_kind, fld in B.walk_refs(B.step_inputs(q, st)):
                if fld == "subject_guid":
                    err(where, f"{q['id']} needs a bind for its entity")
                elif fld not in avail:
                    err(where, f"{q['id']} input {ref_kind}:{fld} not in alert fields")
        used = [st.get("question") for st in flow]
        if not any(B.OUTCOME.match(st.get(e, "")) and st.get(e, "").startswith("close") for st in flow[1:] for e in ("on_yes", "on_no")):
            info.append(f"{d['id']}: no close outside Q0 (escalate/flag only)")

    for x in b["pilot"]["detections"]:
        if x["id"] not in b["detections"]:
            err("bank/pilot.yaml", f"{x['id']} has no detection file")
    used_q = {st["question"] for _, d in B.flows(b) for st in d["flow"]}
    for qid in sorted(set(b["questions"]) - used_q):
        warnings.append(f"{qid}: not used by any flow")
    used_rc = {B.OUTCOME.match(st[e]).group(3) for _, d in B.flows(b) for st in d["flow"] for e in ("on_yes", "on_no") if st[e].startswith("close")}
    for rc in sorted(set(b["reason_codes"]) - used_rc):
        warnings.append(f"reason code {rc}: not used")

    for title, items in (("ERROR", errors), ("WARN", warnings), ("INFO", info)):
        for i in items:
            print(f"{title} {i}")
    print(f"\n{len(b['detections'])} detections, {len(b['techniques'])} technique fallbacks, {len(b['questions'])} questions, "
          f"{len(b['facts'])} context facts, {len(caps)} capabilities: {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
