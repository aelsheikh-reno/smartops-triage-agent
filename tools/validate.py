#!/usr/bin/env python3
"""Validate the question bank. Exit 1 on any error."""
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

REQUIRED = {
    "question": ["id", "text", "tests", "capability", "attacker_influence", "source", "license", "text_origin", "legal_review", "status", "version"],
    "explanation": ["id", "name", "description", "source", "license", "version"],
    "fact": ["id", "name", "description", "fields", "collected_by", "version"],
    "rule": ["id", "name", "techniques", "data_source", "sigma_logsource", "sigma_refs", "required_alert_fields", "intent", "fp_quality", "fingerprint", "precedent_validity", "flow", "source", "license", "status", "version"],
    "technique": ["id", "name", "attack_version", "max_mode", "assumed_alert_fields", "fingerprint", "precedent_validity", "flow", "source", "license", "status", "version"],
}
import export_bundle  # noqa: E402
import vendors  # noqa: E402

# Query syntax that must never appear in the bank.
QUERY_SYNTAX = re.compile(r"\b(tstats|sourcetype|inputlookup|index\s*=)|\|\s*stats\b", re.I)
# The only fields that may name vendors or products: offline provenance and matching metadata.
EXEMPT_KEYS = {"data_source", "sigma_logsource", "sigma_refs", "source", "license"}
SIGMA = os.path.join(B.ROOT, "sources/sigma")
ATTACK = os.path.join(B.ROOT, "sources/attack-stix-data/enterprise-attack/enterprise-attack-20.0.json")


def scan_text(obj, path="", exempt=EXEMPT_KEYS):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k not in exempt and not k.startswith("_"):
                yield from scan_text(v, f"{path}.{k}", exempt)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from scan_text(v, f"{path}[{i}]", exempt)
    elif isinstance(obj, str):
        hit = vendors.find(obj)
        if not hit:
            m = QUERY_SYNTAX.search(obj)
            hit = m.group(0) if m else None
        if hit:
            yield path, hit


def main():
    b = B.load()
    errors, warnings, info = [], [], []
    err = lambda where, msg: errors.append(f"{where}: {msg}")
    caps, params = b["capability_by_name"], b["parameters"]
    budget = b["capabilities"]["scope"]["max_calls_per_alert"]
    profiles = {k for k in b["capabilities"]["source_profiles"] if k != "note"}

    for kind, coll in (("question", b["questions"]), ("explanation", b["explanations"]), ("fact", b["facts"])):
        for i, doc in coll.items():
            for k in REQUIRED[kind]:
                if k not in doc:
                    err(doc["_file"], f"missing {k}")
    for fid, f in b["facts"].items():
        if f.get("supply_effort") not in ("low", "medium", "high") or not str(f.get("supply_effort_reason", "")).strip():
            err(f["_file"], "supply_effort must be low|medium|high, with a supply_effort_reason")
        if f.get("collected_by") == "bank_seed" and not f.get("seed_file"):
            err(f["_file"], "bank_seed fact needs a seed_file (with source and license)")

    for qid, q in b["questions"].items():
        w = q["_file"]
        if q["tests"] not in b["explanations"]:
            err(w, f"tests unknown explanation {q['tests']}")
        cap = q.get("capability") or {}
        if not isinstance(cap, dict) or cap.get("name") not in caps:
            err(w, f"unknown capability {cap.get('name') if isinstance(cap, dict) else cap}")
            continue
        ai = q.get("attacker_influence") or {}
        if ai.get("rating") not in B.RATING_ORDER or not str(ai.get("reason", "")).strip():
            err(w, "attacker_influence needs rating none|low|medium|high and a one-line reason")
        for prof, r in (ai.get("by_source") or {}).items():
            if prof not in profiles or r not in B.RATING_ORDER:
                err(w, f"attacker_influence.by_source {prof}: {r} needs a known source profile and rating")
        if cap["name"] == "org.prevalence":
            allp = dict(cap.get("inputs") or {}); allp.update(cap.get("params") or {})
            if "window" in allp and ({"min_weeks", "of_weeks"} & set(allp)):
                err(w, "org.prevalence: window cannot be combined with min_weeks/of_weeks")
        for item in (q.get("needs") or {}).get("coverage") or []:
            if item not in (b["capabilities"].get("coverage_items") or {}):
                err(w, f"needs.coverage {item} is not declared in capabilities.yaml coverage_items")
        if cap["name"] == "alert.field":
            inp, ops = cap.get("inputs") or {}, caps["alert.field"]["ops"]
            if "in" in inp or inp.get("op") not in ops or "values" not in inp or "field" not in inp:
                err(w, f"alert.field needs field, op (one of {', '.join(ops)}) and values")
            if ("unknown_op" in inp) != ("unknown_values" in inp) or inp.get("unknown_op", "in") not in ops:
                err(w, "alert.field unknown_op and unknown_values go together")
            for k in ("values", "unknown_values"):
                v = inp.get(k)
                if isinstance(v, dict) and v.get("param") not in params:
                    err(w, f"alert.field {k}: unknown parameter {v}")
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

    # Vendor-name guard: every bank file except seed data (onboarding-only, never in the bundle).
    named = [("bank/capabilities.yaml", b["capabilities"]), ("bank/parameters.yaml", b["parameters"]),
             ("bank/reason_codes.yaml", list(b["reason_codes"].values())), ("bank/pilot.yaml", b["pilot"])]
    for coll in ("questions", "explanations", "facts", "detections", "techniques"):
        named += [(d["_file"], {k: v for k, v in d.items() if k != "seed"}) for d in b[coll].values()]
    for where, doc in named:
        for path, hit in scan_text(doc):
            err(where, f"vendor/product name or query syntax '{hit}' at {path}")
    for u in b["use_cases"]:   # catalog: 'linked' holds source references, like sigma_refs
        for path, hit in scan_text(u, exempt=EXEMPT_KEYS | {"linked", "covered_by"}):
            err(f"bank/use_cases.yaml {u['id']}", f"vendor/product name '{hit}' at {path}")
    for qid, q in b["questions"].items():
        hit = vendors.where_phrase(q["text"])
        if hit:
            err(q["_file"], f"question text says where or with which tool ('{hit}'); describe only what to check")
    for fid, s in b["seeds"].items():
        if fid not in b["facts"]:
            err(s["_file"], f"seed for unknown fact {fid}")
        elif b["facts"][fid].get("seed_file") != os.path.relpath(s["_file"], "bank"):
            err(s["_file"], f"{fid} does not point at this seed file")
        if not s.get("source") or not s.get("license"):
            err(s["_file"], "seed needs source and license")
    for fid, f in b["facts"].items():
        if f.get("seed_file") and fid not in b["seeds"]:
            err(f["_file"], f"seed_file {f['seed_file']} missing")
    # Runtime bundle: no offline metadata keys, no vendor names anywhere.
    bundle = export_bundle.build(b)
    def walk(o, path="bundle"):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in export_bundle.OFFLINE_KEYS:
                    err("runtime bundle", f"offline key {k} at {path}")
                yield from walk(v, f"{path}.{k}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                yield from walk(v, f"{path}[{i}]")
        elif isinstance(o, str):
            hit = vendors.find(o)
            if hit:
                yield path, hit
    for path, hit in walk(bundle):
        err("runtime bundle", f"vendor/product name '{hit}' at {path}")

    sigma_tax, sigma_ids = None, None
    if os.path.isdir(SIGMA):
        with open(os.path.join(SIGMA, "tests/logsource.json")) as fh:
            sigma_tax = json.load(fh)["legit"]
        sigma_ids = {}
        for path in glob.glob(os.path.join(SIGMA, "rules*/**/*.yml"), recursive=True):
            with open(path) as fh:
                for line in fh:
                    if line.startswith("id: "):
                        sigma_ids[line[4:].split("#")[0].strip()] = path
                        break
    else:
        warnings.append("SigmaHQ repo not found under sources/; sigma_logsource and sigma_refs not checked")

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
            if kind == "rule" and d.get("family") != "vendor" and t not in b["techniques"]:
                warnings.append(f"{d['id']}: no technique fallback for {t}")
        if kind == "rule":
            vendor = d.get("family") == "vendor"
            if d.get("fp_quality") not in ("good", "vague", "none", "generic"):
                err(w, f"fp_quality {d.get('fp_quality')} must be good|vague|none|generic")
            if vendor:
                if not d["id"].startswith("vendor:"):
                    err(w, "vendor-family detections use the vendor: id prefix")
                if b["use_cases"] and d.get("use_case") not in {u["id"] for u in b["use_cases"]}:
                    err(w, f"use_case {d.get('use_case')} not in the catalog")
            ls = d.get("sigma_logsource") or []
            if not ls and not (vendor and d.get("sigma_logsource_none")):
                err(w, "sigma_logsource must list at least one entry (vendor families may leave it empty with sigma_logsource_none)")
            for entry in ls:
                keys = set(entry) - {"product"}
                if len(keys) != 1 or not keys <= {"category", "service"}:
                    err(w, f"sigma_logsource entry {entry} must be [product plus] one of category or service")
                elif sigma_tax is not None:
                    kind_key = keys.pop()
                    product = entry.get("product", "empty")
                    if entry[kind_key] not in sigma_tax.get(product, {}).get(kind_key, {}):
                        err(w, f"sigma_logsource {entry} not in Sigma taxonomy (tests/logsource.json)")
            for ref in d.get("sigma_refs") or []:
                if ref.get("relation") not in ("equivalent", "closest"):
                    err(w, f"sigma_refs {ref.get('id')}: relation must be equivalent or closest")
                if sigma_ids is not None:
                    path = sigma_ids.get(ref.get("id"))
                    if not path:
                        err(w, f"sigma_refs {ref.get('id')} not found in SigmaHQ rules")
                    else:
                        with open(path) as fh:
                            text = fh.read()
                        if f"title: {ref.get('title')}" not in text:
                            err(w, f"sigma_refs {ref['id']}: title does not match {os.path.relpath(path, SIGMA)}")
                        if "status: deprecated" in text:
                            err(w, f"sigma_refs {ref['id']} is deprecated")
        for step, edge, bad in B.tainted_closes(b, d.get("flow", [])):
            info.append(f"{d['id']}: close at step {step} ({edge}) flags until onboarding verifies seed data used at step(s) {bad}")
        for e in d.get("explanations", []):
            if e not in b["explanations"]:
                err(w, f"unknown explanation {e}")
        fields = set(d.get("required_alert_fields") or d.get("assumed_alert_fields") or []) | set(d.get("optional_alert_fields") or [])
        avail = fields | set(d.get("derived_fields") or {}) | {"fingerprint"}
        for fp in d.get("fingerprint", []):
            if fp not in avail and fp not in ("writer_hash", "driver_hash", "source_image_hash"):
                err(w, f"fingerprint field {fp} not available")
        flow = d.get("flow", [])
        if not 1 <= len(flow) <= 5:
            err(w, f"flow has {len(flow)} steps (1-5 allowed)")
        fi = d.get("fingerprint_influence") or {}
        for fp in d.get("fingerprint", []):
            if (fi.get(fp) or {}).get("rating") not in B.RATING_ORDER or not str((fi.get(fp) or {}).get("reason", "")).strip():
                err(w, f"fingerprint_influence must rate {fp} (none|low|medium|high, with a reason)")
        if d.get("precedent_entity") not in avail:
            err(w, f"precedent_entity {d.get('precedent_entity')} must be an alert or derived field")
        for fp, e in fi.items():
            fb = (e or {}).get("fallback")
            if fb and (fb.get("field") not in avail or fb.get("rating") not in B.RATING_ORDER):
                err(w, f"fingerprint_influence {fp}: fallback needs an available field and a rating")
        if d.get("precedent_entity_fallback") and d["precedent_entity_fallback"] not in avail:
            err(w, f"precedent_entity_fallback {d['precedent_entity_fallback']} must be an alert or derived field")
        for req in d.get("auto_requires") or []:
            if req not in (b["capabilities"].get("auto_requirements") or {}):
                err(w, f"auto_requires {req} is not declared in capabilities.yaml auto_requirements")
        refs_ok = all(st.get("question") in b["questions"] for st in flow) and all(
            gd.get("question") in b["questions"] for st in flow for gd in st.get("guards") or [])
        if refs_ok:
            calls = max((B.path_calls(b, p, o, gs) for p, o, gs in B.enumerate_paths(flow)), default=0)
            if calls > budget:
                err(w, f"worst path makes {calls} capability calls (steps plus guards), over the budget of {budget}")
        for n, st in enumerate(flow, 1):
            where = f"{w} step {n}"
            if st.get("step") != n:
                err(where, "steps must be numbered 1..n")
            q = b["questions"].get(st.get("question"))
            if not q:
                err(where, f"unknown question {st.get('question')}")
                continue
            if n == 1:
                want, got = B.q0_rating(d), (st.get("attacker_influence") or {}).get("rating")
                if q["id"] != "Q-0000":
                    err(where, "flow must start with Q-0000")
                elif got != want or not str((st.get("attacker_influence") or {}).get("reason", "")).strip():
                    err(where, f"Q0 attacker_influence is {got}; the fingerprint fields give {want} (with a reason)")
                elif st["on_yes"] != ("next" if want == "high" else "close:inherit:precedent_match"):
                    err(where, f"Q0 rated {want}: on_yes must be {'next' if want == 'high' else 'close:inherit:precedent_match'}")
                fb = B.q0_fallback_rating(d)
                if fb and fb != want and (st.get("attacker_influence") or {}).get("fallback_rating") != fb:
                    err(where, f"Q0 needs attacker_influence.fallback_rating {fb} (fingerprint fallback)")
                if (st.get("bind") or {}).get("entity") != f"value:{d.get('precedent_entity')}":
                    err(where, "Q0 must bind entity to value:<precedent_entity>")
            elif st.get("attacker_influence"):
                err(where, "step-level attacker_influence is only for Q0")
            kinds = {B.outcome_kind(st.get(e, "")) for e in ("on_yes", "on_no", "on_unknown")} - {"next"}
            for gd in st.get("guards") or []:
                gw = f"{where} guard {gd.get('question')}"
                gq = b["questions"].get(gd.get("question"))
                if not gq:
                    err(gw, "unknown question")
                    continue
                if gd.get("then") not in ("flag", "escalate"):
                    err(gw, "then must be flag or escalate")
                applies = gd.get("applies_to", ["close"])
                if not applies or set(applies) - {"close", "flag"}:
                    err(gw, "applies_to lists close and/or flag; a guard never attaches to an escalate outcome")
                for k in applies:
                    if k not in kinds:
                        err(gw, f"applies to {k}, but the step has no {k} outcome")
                    elif B.SEVERITY.get(gd.get("then"), -1) <= B.SEVERITY[k]:
                        err(gw, f"then {gd.get('then')} is not stronger than the {k} outcome it guards (guards only raise)")
                if gd.get("if_entry_type"):
                    lf = (q["capability"].get("inputs") or {}).get("list")
                    types = set((b["facts"].get(lf) or {}).get("entry_types") or []) if isinstance(lf, str) else set()
                    if q["capability"]["name"] != "list.lookup" or not set(gd["if_entry_type"]) <= types:
                        err(gw, f"if_entry_type {gd['if_entry_type']} must name entry_types of the step's list ({sorted(types) or 'none'})")
                when = gd.get("when", ["yes"])
                if not when or set(when) - {"yes", "no"}:
                    err(gw, "when lists yes and/or no (unknown always flags)")
                gcap = caps.get(gq["capability"]["name"], {})
                if gcap.get("escalate_only") and "no" in when:
                    err(gw, f"escalate_only capability {gcap.get('name')}: a miss is never benign evidence")
                for ref_kind, fld in B.walk_refs(B.step_inputs(gq, gd)):
                    if fld == "subject_guid" or fld not in avail:
                        err(gw, f"{gq['id']} input {ref_kind}:{fld} not in alert fields")
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
            if cap.get("escalate_only") and st["on_yes"] not in ("escalate", "flag"):
                err(where, f"escalate_only capability {cap['name']}: a hit must escalate or flag")
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

    # use-case catalog
    ucs = b["use_cases"]
    src_to_bank = B.source_ids(b)
    if ucs:
        ids = [u["id"] for u in ucs]
        if len(set(ids)) != len(ids):
            err("bank/use_cases.yaml", "duplicate use-case ids")
        if sorted(u["rank"] for u in ucs) != list(range(1, len(ucs) + 1)):
            err("bank/use_cases.yaml", "ranks must be 1..n with no gaps")
        src_ids = None
        if sigma_ids is not None:
            src_ids = {"sigma": {f"sigma:{i}" for i in sigma_ids}}
            sent_dir = os.path.join(B.ROOT, "sources/Azure-Sentinel/Solutions")
            if os.path.isdir(sent_dir):
                src_ids["sentinel"] = set()
                for path in glob.glob(os.path.join(sent_dir, "*/Analytic Rules/**/*.yaml"), recursive=True):
                    with open(path, encoding="utf-8-sig") as fh:
                        for line in fh:
                            if line.startswith("id:"):
                                src_ids["sentinel"].add("sentinel:" + line[3:].split("#")[0].strip().strip("'\""))
                                break
            escu_dir = os.path.join(B.ROOT, "sources/security_content/detections")
            if os.path.isdir(escu_dir):
                src_ids["escu"] = {"escu:" + os.path.basename(p)[:-4] for p in glob.glob(os.path.join(escu_dir, "*/*.yml")) if "/deprecated/" not in p}
        for u in ucs:
            w = f"bank/use_cases.yaml {u['id']}"
            for k in ("name", "domain", "family", "rank", "volume_reason", "techniques", "linked", "coverage", "covered_detections", "linked_detections"):
                if k not in u:
                    err(w, f"missing {k}")
            if u.get("family") == "vendor" and not u.get("triage_hints"):
                err(w, "vendor-alert family needs triage_hints")
            for t in u.get("techniques", []):
                if attack_ids is not None and t not in attack_ids:
                    err(w, f"technique {t} not active in ATT&CK v20.0")
            for src, block in (u.get("linked") or {}).items():
                for x in block.get("shown", []):
                    if src_ids and src in src_ids and x["id"] not in src_ids[src]:
                        err(w, f"linked {x['id']} not found in cloned {src} sources")
                    if src == "vendor" and x["id"] not in b["detections"]:
                        err(w, f"linked {x['id']} is not a bank vendor detection")
            covered = u.get("covered_by", [])
            shown = {x["id"] for blk in u["linked"].values() for x in blk.get("shown", [])}
            for d in covered:
                if d not in src_to_bank:
                    err(w, f"covered_by {d} has no bank flow")
                if d not in shown:
                    err(w, f"covered_by {d} is not among the shown linked detections")
            for d in sorted(shown & set(src_to_bank) - set(covered)):
                err(w, f"{d} has a bank flow ({src_to_bank[d]}) but is missing from covered_by")
            n_linked = sum(blk.get("total", 0) for blk in u["linked"].values())
            if u.get("linked_detections") != n_linked:
                err(w, f"linked_detections {u.get('linked_detections')} != sum of linked totals {n_linked}")
            if u.get("covered_detections") != len(covered):
                err(w, f"covered_detections {u.get('covered_detections')} != len(covered_by) {len(covered)}")
            fallbacks = [t for t in u.get("techniques", []) if t in b["techniques"]]
            if sorted(u.get("technique_fallbacks", [])) != sorted(fallbacks):
                err(w, f"technique_fallbacks should be {sorted(fallbacks)}")
            want = ("generic" if u.get("family") == "vendor" and covered and all(x.startswith("vendor:") for x in covered)
                    else ("rule-level-full" if len(covered) == n_linked else "rule-level-partial") if covered
                    else "technique-only" if fallbacks else "none")
            if u.get("coverage") != want:
                err(w, f"coverage is {u.get('coverage')}, bank says {want}")
    # Vendor value mapping: a family with any unverified row is capped at Recommend.
    norm = os.path.join(B.ROOT, "docs", "normalization.md")
    unverified_families = {}
    if os.path.exists(norm):
        families, cols = [], None
        with open(norm) as fh:
            for line in fh:
                line = line.strip()
                if line.startswith("## "):
                    families, cols = [], None
                elif line.startswith("Families:"):
                    families = re.findall(r"`([^`]+)`", line)
                    for fam in families:
                        if fam not in b["detections"]:
                            err("docs/normalization.md", f"Families names unknown detection {fam}")
                elif line.startswith("|") and families:
                    cells = [c.strip() for c in line.strip("|").split("|")]
                    if cols is None:
                        cols = [c.lower() for c in cells]
                        if "verified" not in cols:
                            err("docs/normalization.md", f"mapping table for {families} has no Verified column")
                    elif not set(line) <= set("|-: ") and "verified" in cols:
                        v = cells[cols.index("verified")].lower()
                        if v not in ("true", "false"):
                            err("docs/normalization.md", f"row '{cells[0]} / {cells[1]}' must be verified true or false")
                        elif v == "false":
                            for fam in families:
                                unverified_families.setdefault(fam, []).append(f"{cells[0]}: {cells[1]}")
    for fam, rows in sorted(unverified_families.items()):
        d = b["detections"].get(fam)
        if d and "vendor_mapping_verified" not in (d.get("auto_requires") or []):
            err(d["_file"], f"family mapping has {len(rows)} unverified rows in docs/normalization.md: declare auto_requires: [vendor_mapping_verified] "
                            "(capped at Recommend for each customer whose product rows are unverified)")
        elif d:
            info.append(f"{fam}: capped at Recommend per customer until that customer's product rows ({len(rows)} unverified overall) are verified")
    for did, d in b["detections"].items():
        if d.get("family") == "vendor" and d.get("max_mode") == "recommend" and did not in unverified_families and not d.get("max_mode_reason"):
            err(d["_file"], "max_mode recommend needs a max_mode_reason")
    for x in b["pilot"]["detections"]:
        if x["id"] not in b["detections"]:
            err("bank/pilot.yaml", f"{x['id']} has no detection file")
    used_q = {st["question"] for _, d in B.flows(b) for st in d["flow"]} | {
        gd["question"] for _, d in B.flows(b) for st in d["flow"] for gd in st.get("guards") or []}
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
