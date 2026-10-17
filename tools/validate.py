#!/usr/bin/env python3
"""Validate the question bank. Exit 1 on any error.

Beyond structure, it enforces the bank's design rules:
- no schema field names in bank logic: detections declare required_roles and refer to roles (tools/roles.py);
  known CIM, ECS and Sysmon names (tools/field_names.py) and old value:/process:/file:/module: references are rejected
- typed answers: every capability declares one answer type; a step on a non-bool question carries a Triage-side rule
- no thresholds in questions: counts and lists are compared on the step, against bounded parameters
- every parameter has a default, bounds and a scrutiny direction; overrides stay in bounds, and a reduce-scrutiny
  override needs approved_by, owner and expiry
- every question is tagged context or triage; context questions C-01..C-07 exist and are wired
- honest ratings: no question rated below its capability's floor without a written reason; change.window needs an
  independent approver
- value tables: every row has an id and a kind (ambiguous or unverified); an ambiguous row never maps to a value that
  supports a close; verified is per customer (bank/broker/customers/<c>/verifications.yaml), and a detection set to Auto
  for a customer needs every value-table row on its close paths verified for that customer
"""
import glob
import json
import os
import re

import yaml
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402
from engine import executor as E  # noqa: E402
import export_bundle  # noqa: E402
import field_names  # noqa: E402
import roles as R  # noqa: E402
import vendors  # noqa: E402

REQUIRED = {
    "question": ["id", "text", "tests", "kind", "capability", "attacker_influence", "source", "license", "text_origin", "legal_review", "status", "version"],
    "context_question": ["id", "text", "kind", "capability", "feeds", "attacker_influence", "when_not_answered", "source", "license", "status", "version"],
    "explanation": ["id", "name", "description", "source", "license", "version"],
    "fact": ["id", "name", "description", "fields", "collected_by", "version"],
    "rule": ["id", "name", "techniques", "data_source", "sigma_logsource", "sigma_refs", "required_roles", "intent", "fp_quality", "fingerprint", "flow", "source", "license", "status", "version"],
    "technique": ["id", "name", "attack_version", "max_mode", "required_roles", "fingerprint", "flow", "source", "license", "status", "version"],
}
OLD_KEYS = {"required_alert_fields", "assumed_alert_fields", "optional_alert_fields", "precedent_validity"}
# Keys that hold prose or offline metadata, not bank logic: not scanned for field names.
PROSE = {"text", "name", "intent", "notes", "note", "description", "reason", "source", "license", "title", "path", "tests", "explanations",
         "template", "covers", "fp_quality", "status", "version", "id", "escu_uuid", "data_source", "sigma_logsource", "sigma_refs",
         "use_case", "family", "max_mode_reason", "attack_version", "techniques", "max_mode", "legal_review", "text_origin", "auto_requires",
         "changed_in_migration", "below_floor_reason", "approved_by", "pattern", "when", "then", "applies_to", "if_entry_type", "on_yes",
         "on_no", "on_unknown", "step", "question", "kind", "feeds", "when_not_answered", "sigma_logsource_none", "required_roles",
         "precedent_validity_reason", "parameters", "rule", "list", "context", "context_questions", "coverage", "fallback_rating", "rating",
         "join", "first", "all", "repo", "_file", "derived_from", "alert_type",
         "auto_excluded_reason", "q0_off_reason", "actor_identity", "evidence", "meaning", "applies_to"}
TODAY = __import__("datetime").date.today().isoformat()
ROW_KINDS = ("ambiguous", "unverified", "proposed", "standards_defined")
THRESHOLD_KEYS = {"min_count", "min_hosts", "min_days", "min_weeks", "of_weeks", "threshold", "op", "values", "unknown_op", "unknown_values", "max_count"}
WINDOW_KEYS = {"lookback_days", "lookback_weeks", "lookback_hours", "max_age_days", "validity_hours", "window"}   # windows may travel to the broker
QUERY_SYNTAX = re.compile(r"\b(tstats|sourcetype|inputlookup|index\s*=)|\|\s*stats\b", re.I)
# Vendor-leak gate (design-decisions: Version 1 scope). Vendor-specific content lives only in adapter folders,
# broker recipes and value tables (bank/broker/), and in offline metadata (data_source, the use-case catalog).
QUERY_LANGUAGE = re.compile(
    r"index\s*=|\|\s*(tstats|stats|inputlookup|lookup|eval|rex|search|table|dedup|where|summarize|project|extend|join|mv-expand|parse)\b"
    r"|\bsourcetype\b|\bdatamodel\b|\btstats\b|\binputlookup\b|(?-i:\bLAST\s+\d+\s+(MINUTES|HOURS|DAYS)\b)|\bSELECT\s+\S+.*\bFROM\s+events\b"
    r"|\bKQL\b|\bSPL\b|\bAQL\b|\bEQL\b|ES\|QL", re.I)
PRODUCT_TERMS = re.compile(
    r"\bnotables?\b|incident review|mission control|splunk es|enterprise security|sentinel incident|qradar offen[cs]e|\boffen[cs]es?\b"
    r"|correlation search|saved search|analytics rule|\bdata model\b", re.I)
DISTINCT_FIELD = ({f for f in field_names.KNOWN if "_" in f.strip("_") or "." in f or re.search("[A-Z]", f)} | {"_time"}) - set(R.ROLES)

EXEMPT_KEYS = {"data_source", "sigma_logsource", "sigma_refs", "source", "license", "derived_from"}
SIGMA = os.path.join(B.ROOT, "sources/sigma")
ATTACK = os.path.join(B.ROOT, "sources/attack-stix-data/enterprise-attack/enterprise-attack-20.0.json")
TYPES = {"bool", "count", "number", "enum", "time"}


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


LEAK_SKIP = {"data_source", "sigma_logsource", "sigma_refs", "source", "license", "use_case", "escu_uuid", "_file", "derived_from"}


def scan_leaks(obj, path=""):
    """Yield (path, kind, hit) for query-language tokens, SIEM product terms and distinctive schema field names in bank logic."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k not in LEAK_SKIP:
                yield from scan_leaks(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from scan_leaks(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        text = R.REF.sub(" ", obj)
        m = QUERY_LANGUAGE.search(text)
        if m:
            yield path, "query-language token", m.group(0)
        m = PRODUCT_TERMS.search(text)
        if m:
            yield path, "SIEM product term", m.group(0)
        for tok in re.findall(r"[A-Za-z_@][A-Za-z0-9_.@]*", text):
            if tok.rstrip(".") in DISTINCT_FIELD:
                yield path, "schema field name", tok.rstrip(".")
                break


# Triage-neutrality gate: the triage layer and the contract never name vendors, products or rule libraries, never refer to
# the broker's internals (its translations, rows, sources, recipes), and never hold field names or query-language tokens.
# derived_from metadata is the only exception.
BROKER_REF = re.compile(r"\bbank/broker\b|\bbroker/|\b(value|translation)[ -]?tables?\b|\btranslation rows?\b|\b(table|translation)/row\b|"
                        r"\brows?\b|\brecipes?\b|\bsiem_copy\b|\bedr_api\b|\bsource[_ ]authority\b|\bfallback[- ]sources?\b|"
                        r"\bauthoritative sources?\b|\brow kinds?\b|\bunverified mapping\b|\bintake/|\brule[- ]map\b|\bCF-\d{4}\b", re.I)


def _strip_derived(obj):
    if isinstance(obj, dict):
        return {k: _strip_derived(v) for k, v in obj.items() if k != "derived_from"}
    if isinstance(obj, list):
        return [_strip_derived(v) for v in obj]
    return obj


def neutrality_hits(path):
    """(where, kind, hit) for every neutrality violation in one triage/ or contract/ file (comments included)."""
    raw = open(path).read()
    doc = _strip_derived(yaml.safe_load(raw))
    texts = [("comment", line) for line in raw.split("\n") if line.lstrip().startswith("#")]
    texts.append(("content", yaml.safe_dump(doc, sort_keys=False, width=10000, allow_unicode=True)))
    out = []
    for where, text in texts:
        for kind, fn in (("vendor or product name", vendors.find), ("rule library name", vendors.find_library),
                         ("reference to the broker's internals", lambda t: (BROKER_REF.search(t) or [None])[0])):
            hit = fn(text)
            if hit:
                out.append((where, kind, hit))
    for p, kind, hit in scan_leaks(doc):
        if kind != "schema field name" or FIELD_SHAPED.search(hit):
            out.append((p, kind, hit))
    return out


# The executor (engine/) is held to the same neutrality as the triage layer, plus: no detection or technique IDs, no file
# formats (it reads the bank as loaded dictionaries and never opens or parses a file), and no schema field names anywhere.
ENGINE_DETECTION_ID = re.compile(r"\b(D-\d{4}|T\d{4}(\.\d{3})?|Q-\d{4}|C-\d{2})\b")   # detection, technique, question or context question
ENGINE_FILE_FORMAT = re.compile(r"^\s*(import|from)\s+(yaml|json|csv|xml|configparser|tomllib|glob|pathlib)\b|\bopen\(", re.M)


def engine_hits(path):
    """(kind, hit) for every neutrality violation in one engine/ source file."""
    text = open(path).read()
    out = []
    for kind, fn in (("vendor or product name", vendors.find), ("rule library name", vendors.find_library),
                     ("reference to the broker's internals", lambda t: (BROKER_REF.search(t) or [None])[0]),
                     ("detection, technique, question or context-question ID", lambda t: (ENGINE_DETECTION_ID.search(t) or [None])[0]),
                     ("file format", lambda t: (ENGINE_FILE_FORMAT.search(t) or [None])[0])):
        hit = fn(text)
        if hit:
            out.append((kind, hit.strip()))
    for tok in re.findall(r"[A-Za-z_@][A-Za-z0-9_.@]*", R.REF.sub(" ", text)):
        if tok.rstrip(".") in DISTINCT_FIELD and FIELD_SHAPED.search(tok.rstrip(".")):
            out.append(("schema field name", tok.rstrip(".")))
            break
    m = QUERY_LANGUAGE.search(text) or PRODUCT_TERMS.search(text)
    if m:
        out.append(("query-language token or SIEM product term", m.group(0)))
    return out


# In prose an English word can share a schema field's name (User, Signature); a field-shaped token cannot.
FIELD_SHAPED = re.compile(r"_|\.|[a-z][A-Z]")


def scan_fields(obj, path=""):
    """Yield (path, problem) for schema field names or direct field reads in structured (non-prose) values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and R.OLD_REF.search(k):
                yield f"{path}.{k}", f"key '{k}' reads a field directly"
            if isinstance(k, str) and k in field_names.KNOWN and path.endswith("derived_fields"):
                yield f"{path}.{k}", f"derived name '{k}' collides with a schema field name"
            if k in PROSE or k == "class":
                continue
            yield from scan_fields(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from scan_fields(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        for m in R.OLD_REF.finditer(obj):
            yield path, f"reads a field directly ({m.group(0)}); refer to a role (role:<role>.<attr>) or an entity"
        if obj in field_names.KNOWN:
            yield path, f"schema field name '{obj}'"


def refs_in(obj):
    for k, v in (obj.items() if isinstance(obj, dict) else enumerate(obj) if isinstance(obj, list) else []):
        if isinstance(k, str):
            for m in R.REF.finditer(k):
                yield m.groups()
        if isinstance(v, str):
            for m in R.REF.finditer(v):
                yield m.groups()
        else:
            yield from refs_in(v)


def param_check(err, where, params, name, value=None):
    p = params.get(name)
    if not p:
        err(where, f"unknown parameter {name}")
        return None
    if value is not None:
        msg = out_of_bounds(p, value)
        if msg:
            err(where, f"{name}={value!r} {msg}")
    return p


def out_of_bounds(p, v):
    bd = p.get("bounds") or {}
    if isinstance(p.get("default"), list):
        if not isinstance(v, list):
            return "must be a list"
        if len(v) < bd.get("min_items", 0) or len(v) > bd.get("max_items", 10 ** 6):
            return f"has {len(v)} items, outside {bd.get('min_items')}..{bd.get('max_items')}"
        if bd.get("allowed") is not None:
            bad = [x for x in v if x not in bd["allowed"]]
            if bad:
                return f"has values outside the allowed list: {bad}"
        return None
    try:
        if not bd.get("min") <= float(v) <= bd.get("max"):
            return f"outside bounds {bd.get('min')}..{bd.get('max')}"
    except TypeError:
        return "is not a number"
    return None


def reduces(p, base, v):
    """True if moving from base to v reduces scrutiny, by the parameter's declared direction."""
    d = p["reduces_scrutiny_when"]
    if d == "higher":
        return float(v) > float(base)
    if d == "lower":
        return float(v) < float(base)
    if d == "grows":
        return bool(set(v) - set(base))
    if d == "shrinks":
        return bool(set(base) - set(v))
    return True


def main():
    b = B.load()
    errors, warnings, info = [], [], []
    err = lambda where, msg: errors.append(f"{where}: {msg}")
    caps, params = b["capability_by_name"], b["parameters"]
    classes = b["capabilities"]["alert_classes"]
    budget = b["capabilities"]["scope"]["max_calls_per_alert"]
    sprofiles = {k for k in b["capabilities"]["source_profiles"] if k != "note"}
    all_derived = {n for _, d in B.flows(b) for n in (d.get("derived_fields") or {})}

    # ---------- capabilities and scope ----------
    for name, c in caps.items():
        w = f"bank/broker/capabilities.yaml {name}"
        a = c.get("answer") or {}
        if a.get("type") not in TYPES:
            err(w, f"answer.type must be one of {sorted(TYPES)}")
        if a.get("type") == "enum" and not (a.get("values") or a.get("values_from") == "alert_classes"):
            err(w, "enum answer needs its fixed values")
        if c.get("group") not in ("context", "triage", "write"):
            err(w, "group must be context, triage or write")
        if c.get("rating_floor") not in set(B.RATING_ORDER) | {"per_detection"}:
            err(w, "rating_floor must be none|low|medium|high|per_detection")
    if set(b["capabilities"]["scope"].get("profiles") or {}) != {"triage", "falsifier", "detection_engineering", "use_case_manager"}:
        err("bank/broker/capabilities.yaml scope", "profiles must be triage, falsifier, detection_engineering and use_case_manager")
    if "±" in json.dumps(b["capabilities"]["scope"], ensure_ascii=False):
        err("bank/broker/capabilities.yaml scope", "the triage window is a 24h look-back, never ±24h")
    # every window looks back only (round 6, §4): no question or capability measures "in the alert window" or around the alert time
    LOOKS_AROUND = re.compile(r"(?<!before )\bthe alert window\b|around the alert time|after the alert time", re.I)
    for qid, q in list(b["questions"].items()) + list(b["context_questions"].items()):
        if LOOKS_AROUND.search(q.get("text", "")):
            err(q["_file"], "windows look back only: say the look-back ending at the alert time, not the alert window")
    for c in b["capabilities"]["capabilities"]:
        for k in ("measures", "yes_means", "no_means"):
            if LOOKS_AROUND.search(str(c.get(k, ""))):
                err(f"bank/broker/capabilities.yaml {c['name']}", f"{k}: windows look back only (the look-back ending at the alert time)")
    for pname, p_ in b["parameters"].items():
        if LOOKS_AROUND.search(str(p_.get("description", ""))):
            err(f"parameters {pname}", "windows look back only (the look-back ending at the alert time)")
    for cname, spec in classes.items():
        if spec.get("default") not in spec.get("values", []):
            err(f"bank/broker/capabilities.yaml alert_classes {cname}", "default must be one of the class values")
        for role in spec.get("reads") or []:
            if role not in R.ATTRS:
                err(f"bank/broker/capabilities.yaml alert_classes {cname}", f"reads {role}, not a role attribute")
    sa_doc = b["capabilities"].get("source_authority") or {}
    known_sources, siem_ok = set(sa_doc.get("sources") or {}), set(sa_doc.get("siem_authoritative_only_for") or [])
    if not sa_doc.get("principle") or not known_sources:
        err("bank/broker/capabilities.yaml source_authority", "needs the principle and the list of sources")
    outside = set(b["capabilities"]["scope"].get("budget_counts_sources") or [])
    if not outside or outside - known_sources or outside & {"alert", "context_store", "case_memory", "derived"}:
        err("bank/broker/capabilities.yaml scope", "budget_counts_sources lists the outside tools the call budget counts (sources from source_authority.sources; never our own stores)")
    for name, c in caps.items():
        w = f"bank/broker/capabilities.yaml {name}"
        sa = c.get("source_authority") or {}
        auth, fb = sa.get("authoritative"), sa.get("fallback")
        if auth not in known_sources or not isinstance(fb, list) or set(fb) - known_sources:
            err(w, "source_authority needs an authoritative source and a fallback list, from source_authority.sources")
            continue
        if auth in ("siem", "siem_copy") and name not in siem_ok:
            extra = "; an endpoint API source exists, so it is authoritative and the SIEM copy is the fallback" if "edr_api" in fb else ""
            err(w, f"authoritative source is the SIEM, which is authoritative only for alert history and log searches ({', '.join(sorted(siem_ok))}){extra}")
    if (b["capabilities"]["capabilities"] and not caps.get("change.window", {}).get("requires_independent_approver")):
        err("bank/broker/capabilities.yaml change.window", "a yes must require an approver who is not an implementer")

    # ---------- parameters ----------
    c08 = [v for v in caps.get("asset.class", {}).get("answer", {}).get("values", []) if v != "unknown"]
    for name, p in params.items():
        w = f"bank/triage/parameters.yaml {name}"
        if isinstance(p.get("default"), dict) or {"map", "rows", "match", "pattern", "mapping"} & set(p) or re.search(r"_(pattern|map|mapping)$", name):
            err(w, "a parameter holds customer policy, never a mapping of a vendor's raw values (that belongs in a value table)")
        for cls_, v in (p.get("by_entity_class") or {}).items():
            if cls_ not in c08:
                err(w, f"by_entity_class {cls_} is not an asset class of C-08 ({', '.join(c08)})")
            else:
                msg = out_of_bounds(p, v)
                if msg:
                    err(w, f"by_entity_class {cls_}={v} {msg}")
        if "default" not in p or not isinstance(p.get("bounds"), dict) or p.get("reduces_scrutiny_when") not in ("higher", "lower", "grows", "shrinks"):
            err(w, "needs default, bounds and reduces_scrutiny_when (higher|lower|grows|shrinks)")
            continue
        if isinstance(p["default"], list) != (p["reduces_scrutiny_when"] in ("grows", "shrinks")):
            err(w, "lists reduce scrutiny when they grow or shrink; numbers when higher or lower")
        bd = p["bounds"]
        if not isinstance(p["default"], list) and not ({"min", "max"} <= set(bd) and bd["min"] <= bd["max"]):
            err(w, "numeric bounds need min <= max")
        msg = out_of_bounds(p, p["default"])
        if msg:
            err(w, f"default {msg}")
    if params.get("org_prevalence_min_weeks", {}).get("default", 0) > params.get("org_prevalence_of_weeks", {}).get("default", 99):
        err("bank/triage/parameters.yaml org_prevalence_min_weeks", "must not exceed org_prevalence_of_weeks")
    for cust, ov in b["overlays"].items():
        for o in ov.get("overrides") or []:
            w = f"{ov['_file']} {o.get('param')}"
            p = param_check(err, w, params, o.get("param"), o.get("value"))
            if not p or out_of_bounds(p, o.get("value")):
                continue
            base = p["default"]
            if o.get("detection"):
                d = b["detections"].get(o["detection"]) or b["techniques"].get(o["detection"])
                if not d:
                    err(w, f"unknown detection {o['detection']}")
                    continue
                base = (d.get("parameters") or {}).get(o["param"], base)
            if reduces(p, base, o["value"]):
                missing = [k for k in ("approved_by", "owner", "expiry") if not str(o.get(k) or "").strip()]
                if missing:
                    err(w, f"reduces scrutiny ({p['reduces_scrutiny_when']}): needs {', '.join(missing)}")

    # ---------- questions ----------
    for kind, coll in (("question", b["questions"]), ("explanation", b["explanations"]), ("fact", b["facts"]), ("context_question", b["context_questions"])):
        for i, doc in coll.items():
            for k in REQUIRED[kind]:
                if k not in doc:
                    err(doc["_file"], f"missing {k}")
    for fid, f in b["facts"].items():
        if f.get("supply_effort") not in ("low", "medium", "high") or not str(f.get("supply_effort_reason", "")).strip():
            err(f["_file"], "supply_effort must be low|medium|high, with a supply_effort_reason")
        if f.get("collected_by") == "bank_seed" and not f.get("seed_file"):
            err(f["_file"], "bank_seed fact needs a seed_file (with source and license)")

    def check_question(qid, q, context):
        w = q["_file"]
        if context and q.get("kind") != "context":
            err(w, "context questions are tagged kind: context")
        if not context and q.get("kind") not in ("context", "triage"):
            err(w, "kind must be context or triage (docs/broker-questions.md)")
        if not context and q.get("tests") not in b["explanations"]:
            err(w, f"tests unknown explanation {q.get('tests')}")
        cap = q.get("capability") or {}
        c = caps.get(cap.get("name")) if isinstance(cap, dict) else None
        if not c:
            err(w, f"unknown capability {cap}")
            return
        if c.get("flow_use") == "forbidden":
            err(w, f"capability {cap['name']} cannot back a question")
        if context != (c.get("group") == "context") and c.get("kind") != "derived":
            err(w, f"capability {cap['name']} is in group {c.get('group')}; context questions use context capabilities and flows use triage ones")
        inputs = cap.get("inputs") or {}
        stat_keys = set(c.get("statistic_inputs") or [])
        for k in set(inputs) | set(cap.get("params") or {}):
            if k in stat_keys:
                v = inputs.get(k)
                if not (isinstance(v, dict) and (params.get(v.get("param")) or {}).get("category") == "statistic_setting"):
                    err(w, f"statistic setting '{k}' must be bound to a statistic_setting parameter")
            elif k in THRESHOLD_KEYS:
                err(w, f"threshold or comparison '{k}' in the question; it belongs on the flow step as a rule with a parameter")
        for k, v in (cap.get("params") or {}).items():
            if k not in WINDOW_KEYS:
                err(w, f"params.{k}: only windows and lookbacks may travel to the broker")
        for k, v in list(inputs.items()) + list((cap.get("params") or {}).items()):
            if isinstance(v, dict) and "param" in v:
                param_check(err, w, params, v["param"])
        for kk, name in refs_in(inputs):
            msg = R.check_ref(kk, name, all_derived)
            if msg:
                err(w, msg)
        for path, problem in scan_fields(q, ""):
            err(w, f"{problem} at {path}")
        if cap["name"] == "alert.class":
            if inputs.get("class") not in classes:
                err(w, f"alert.class needs a class from alert_classes (got {inputs.get('class')})")
        if cap["name"] == "alert.measure" and not str(inputs.get("of", "")).startswith("role:"):
            err(w, "alert.measure reads one role attribute (of: role:<role>.<attr>)")
        if cap["name"] == "org.prevalence" and ({"window", "lookback_hours"} & set(inputs)) and ({"of_weeks", "min_weeks"} & set(inputs)):
            err(w, "org.prevalence: lookback_hours and of_weeks/min_weeks are exclusive")
        if "window" in inputs and cap["name"] != "context.rule" and not (isinstance(inputs["window"], dict) and "param" in inputs["window"]):
            err(w, "a window input is a bounded parameter that ends at the alert time (look-back only), never a role or a literal")
        if cap["name"] == "context.rule":
            reads = inputs.get("reads") or []
            used = set(re.findall(r"C-0\d", repr(q.get("context_rule"))))
            if not q.get("context_rule") or not used or not used <= set(reads) or not set(reads) <= set(b["context_questions"]):
                err(w, "context.rule needs a context_rule over the context questions it reads")
        for k in inputs:
            declared = {x.split(" ")[0] for x in (c.get("inputs") or [])}
            if declared and k not in declared:
                err(w, f"input '{k}' is not an input of {cap['name']}")
        # S6: an answer about who performed the action is tagged actor_identity (never the only hard-to-fake yes on a close path)
        actor_refs = {f"{kk}:{name}" for kk, name in refs_in(inputs)}
        who = any(r.startswith("role:actor.") for r in actor_refs) and cap["name"] in ("list.lookup", "change.window") or \
            cap["name"] == "change.window" and any(r.startswith("role:user.") for r in actor_refs)
        if who and not (q.get("actor_identity") or c.get("actor_identity")):
            err(w, "answers who performed the action (an actor account on a list, or a change implementer): tag it actor_identity: true")
        for item in (q.get("needs") or {}).get("coverage") or []:
            if item not in (b["capabilities"].get("coverage_items") or {}):
                err(w, f"needs.coverage {item} is not declared in capabilities.yaml coverage_items")
        for lid in B.list_refs(q):
            if lid not in b["facts"]:
                err(w, f"unknown context fact {lid}")
        ai = q.get("attacker_influence") or {}
        if ai.get("rating") not in B.RATING_ORDER or not str(ai.get("reason", "")).strip():
            err(w, "attacker_influence needs rating none|low|medium|high and a one-line reason")
        else:
            floor = c.get("rating_floor")
            if floor in B.RATING_ORDER and B.RATING_ORDER[ai["rating"]] < B.RATING_ORDER[floor] and not str(ai.get("below_floor_reason", "")).strip():
                err(w, f"rated {ai['rating']}, below its capability's rating {floor} (capability-spec): raise it or give below_floor_reason")
        for prof, r in (ai.get("by_source") or {}).items():
            if prof not in sprofiles or r not in B.RATING_ORDER:
                err(w, f"attacker_influence.by_source {prof}: {r} needs a known source profile and rating")
        if q.get("status") not in ("draft", "approved"):
            err(w, f"bad status {q.get('status')}")
        if q.get("status") == "approved" and not q.get("approved_by"):
            err(w, "approved without approved_by")
        lic = q["license"] if isinstance(q["license"], list) else [q["license"]]
        if q.get("text_origin") != "original" and any(l != "Apache-2.0" for l in lic) and not q.get("legal_review"):
            err(w, "text copied from non-Apache source needs legal_review: true")
        if any(B.has_unverified_seed(b["facts"][l]) for l in B.list_refs(q) if l in b["facts"]):
            info.append(f"{qid}: reads unverified seed data; its closes flag until onboarding verifies the entries")

    for qid, q in b["questions"].items():
        check_question(qid, q, False)
        hit = vendors.where_phrase(q["text"])
        if hit:
            err(q["_file"], f"question text says where or with which tool ('{hit}'); describe only what to check")
    want_c = [f"C-0{i}" for i in range(1, 9)]
    if sorted(b["context_questions"]) != want_c:
        err("bank/context", f"context questions must be exactly {', '.join(want_c)}")
    for cid, q in b["context_questions"].items():
        check_question(cid, q, True)
        w = q["_file"]
        if q.get("on_unknown") != "flag" or q.get("unknown_reason") != "context_unknown":
            err(w, "missing context never closes and never escalates: on_unknown: flag, unknown_reason: context_unknown")
        if "unanswered_value" in q or re.search(r"treated as|counts as", str(q.get("when_not_answered")), re.I):
            err(w, "no worst-case default for unknown context (treated as / counts as): it flags with context_unknown")
    if (b["reason_codes"].get("context_unknown") or {}).get("disposition") != "flag":
        err("bank/triage/reason_codes.yaml", "context_unknown must exist with disposition flag")
    # context rules: every referenced question and parameter exists
    cr = b["context_rules"] or {}
    for sect in ("entity_guard", "q0", "priority", "q0067"):
        if sect not in cr:
            err("bank/triage/context_rules.yaml", f"missing {sect}")
    for sect, want in (("entity_guard", ["C-01", "C-02", "C-08"]), ("q0", ["C-02", "C-03", "C-04", "C-06"]), ("priority", ["C-05", "C-06", "C-07"]),
                       ("q0067", ["C-06", "C-08"])):
        if sorted((cr.get(sect) or {}).get("reads") or []) != want:
            err("bank/triage/context_rules.yaml", f"{sect} reads {want}")
    for m in re.finditer(r"'param': '([a-z_0-9]+)'", repr(cr)):
        param_check(err, "bank/triage/context_rules.yaml", params, m.group(1))
    if (cr.get("q0") or {}).get("question") != "Q-0000" or b["questions"]["Q-0000"]["capability"]["name"] != "precedent.check":
        err("bank/triage/context_rules.yaml", "q0 is Q-0000, answered by precedent.check from the context questions")
    # B3: human evidence is defined once (bank/contract/evidence.yaml); every count of closes declares and uses it
    he = (b["evidence"] or {}).get("human_evidence") or {}
    ev_file = "bank/contract/evidence.yaml"
    if set(he.get("counts") or {}) != {"manual_shadow_close", "analyst_override", "audited_close", "flag_own_close", "flag_override"}:
        err(ev_file, "human_evidence counts exactly manual_shadow_close, analyst_override, audited_close, flag_own_close and flag_override")
    if not {"accepted_recommendation", "auto_close", "precedent_match", "flag_accepted_suggestion"} <= set(he.get("never") or {}) or set(he.get("counts") or {}) & set(he.get("never") or {}):
        err(ev_file, "accepted recommendations, accepted flag suggestions, Auto closes and precedent matches never count as human evidence")
    if set(he.get("independent_kinds") or []) != {"manual_shadow_close", "analyst_override", "flag_own_close", "flag_override"}:
        err(ev_file, "independent_kinds are the human closes counted per distinct analyst: manual_shadow_close, analyst_override, flag_own_close, flag_override")
    props = (b["proposals"] or {}).get("proposals") or {}
    places = {"C-04": b["context_questions"].get("C-04") or {}, "q0": cr.get("q0") or {},
              "routine_pairs": props.get("routine_pairs") or {}, "list_entries": props.get("list_entries") or {},
              "closure_mining": props.get("closure_mining") or {}, "thresholds": props.get("thresholds") or {},
              "routine (context_rules)": (cr.get("entity_guard") or {}).get("routine") or {},
              "case.precedent": caps.get("case.precedent") or {}, "list.propose_update": caps.get("list.propose_update") or {}}
    listed = {x.get("place") for x in he.get("counted_by") or []}
    for place, doc in places.items():
        if doc.get("evidence") != "human_evidence":
            err(ev_file if not doc else f"evidence count {place}", f"counts closes without the one definition: needs evidence: human_evidence (got {doc.get('evidence')!r})")
    for place in {"C-04", "q0", "routine_pairs", "list_entries", "closure_mining", "thresholds"} - listed:
        err(ev_file, f"counted_by must list {place}")
    for name, pr in props.items():
        for k in ("min_closes", "min_analysts", "min_days"):
            if not isinstance(pr.get(k), dict) or "param" not in pr[k]:
                err(f"bank/triage/proposals.yaml {name}", f"{k} must be a bounded parameter")
            else:
                param_check(err, f"bank/triage/proposals.yaml {name}", params, pr[k]["param"])
    if set((b["contract"]["questions"].get("C-04") or {}).get("answer", {}).get("components") or []) != {"audited", "independent_human"}:
        err("bank/contract/questions.yaml C-04", "components are audited and independent_human (bank/contract/evidence.yaml)")
    for ev_key in re.findall(r"'evidence': '([^']*)'", repr([cr, props, b["context_questions"], b["capabilities"]["capabilities"]])):
        if ev_key != "human_evidence":
            err("evidence", f"evidence: {ev_key}: a count of closes uses human_evidence only")
    q0_yes = repr((cr.get("q0") or {}).get("yes_when"))
    if "'C-04.audited'" not in q0_yes or "'modes': ['shadow', 'recommend']" not in q0_yes:
        err("bank/triage/context_rules.yaml q0", "in Auto a precedent needs an audited close: the independent_human branch is limited to modes [shadow, recommend]")
    if "{'C-02.distinct_detections': {'lte': 1}}" not in q0_yes:
        err("bank/triage/context_rules.yaml q0", "Q0 needs C-02.distinct_detections lte 1 (S2)")
    if "day_detections" not in repr((cr.get("entity_guard") or {}).get("hot_when")) or not (cr.get("entity_guard") or {}).get("refresh"):
        err("bank/triage/context_rules.yaml entity_guard", "needs the 24h distinct-detection rule (S2) and the refresh rule (S1)")

    # §3: every severity comparison uses the normalized scale (bank/contract/severity.yaml)
    scale = (b["severity"] or {}).get("scale") or []
    if scale != ["informational", "low", "medium", "high", "critical"]:
        err("bank/contract/severity.yaml", "scale must be informational, low, medium, high, critical")
    sev_values = (b["capabilities"].get("alert_classes", {}).get("severity") or {}).get("values") or []
    if set(sev_values) - set(scale) - {"other"}:
        err("bank/broker/capabilities.yaml alert_classes severity", f"values outside the normalized scale: {sorted(set(sev_values) - set(scale) - {'other'})}")
    if [v for v in (b["contract"]["questions"].get("C-03") or {}).get("answer", {}).get("values") or [] if v != "none"] != scale:
        err("bank/contract/questions.yaml C-03", "values are none plus the normalized scale")
    for m in re.finditer(r"'not_above': '([^']*)'", repr(cr)):
        if m.group(1) != "this_alert_severity":
            err("bank/triage/context_rules.yaml", f"severity comparison on {m.group(1)!r}: compare normalized severities only (this_alert_severity, bank/contract/severity.yaml)")
    for pname, p in params.items():
        if "severit" in pname:
            bad = sorted(set(p["default"] if isinstance(p["default"], list) else [p["default"]]) | set((p.get("bounds") or {}).get("allowed") or []))
            bad = [v for v in bad if v not in scale and v != "other"]
            if bad:
                err(f"parameters {pname}", f"severity values outside the normalized scale (a raw SIEM or product severity?): {bad}")
    for siem, spec in ((b["severity_map"] or {}).get("siems") or {}).items():
        for raw, norm in (spec.get("map") or {}).items():
            if norm not in scale:
                err(f"bank/intake/severity-map.yaml {siem}", f"{raw} maps to {norm!r}, not a normalized severity")
    if not (b["severity_map"] or {}).get("siems", {}).get("splunk_es"):
        err("bank/intake/severity-map.yaml", "needs the Splunk ES mapping (version 1 SIEM)")
    if (b["reason_codes"].get("severity_unmapped") or {}).get("disposition") != "flag":
        err("bank/triage/reason_codes.yaml", "severity_unmapped must exist with disposition flag")
    # the executor names no context question: the entity class and the answers every close needs are declared here
    ec = (cr.get("entity_guard") or {}).get("entity_class") or {}
    ec_q = ec.get("question")
    if ec_q not in b["context_questions"]:
        err("bank/triage/context_rules.yaml entity_guard", "entity_class.question must name a context question (the one that gives the asset class)")
    else:
        enum = (b["contract"]["questions"].get(ec_q) or {}).get("answer", {}).get("values") or []
        if not ec.get("classes") or set(ec["classes"]) - set(enum) or "unknown" in ec["classes"]:
            err("bank/triage/context_rules.yaml entity_guard", f"entity_class.classes must be known answers of {ec_q} (never unknown)")
        for pname, p_ in params.items():
            extra = set((p_.get("by_entity_class") or {})) - set(ec.get("classes") or [])
            if extra:
                err(f"parameters {pname}", f"by_entity_class names {sorted(extra)}, not entity classes in context_rules entity_guard.entity_class")
    needs = cr.get("closes_need_known")
    if not isinstance(needs, list) or not needs:
        err("bank/triage/context_rules.yaml", "closes_need_known must list the context questions every close needs (at least the crown-jewel one)")
    for nd in needs or []:
        if nd.get("question") not in b["context_questions"] or (b["reason_codes"].get(nd.get("reason")) or {}).get("disposition") != "flag":
            err("bank/triage/context_rules.yaml closes_need_known", f"{nd}: needs a context question and a flag reason code")
    if "CF-0030" not in b["facts"] or not {"owner", "approved_by", "expiry"} <= set(b["facts"]["CF-0030"].get("fields") or []):
        err("bank/facts", "routine (entity, detection) pairs need CF-0030 with owner, approved_by and expiry")
    em = b["reason_codes"].get("entity_missing")
    if not em or em.get("disposition") != "flag":
        err("bank/triage/reason_codes.yaml", "reason code entity_missing (disposition flag) is required")

    # ---------- vendor-leak gate ----------
    leak_docs = [("bank/broker/capabilities.yaml", b["capabilities"]), ("bank/triage/parameters.yaml", b["parameters"]), ("bank/triage/context_rules.yaml", cr)]
    leak_docs += [(q["_file"], q) for q in list(b["questions"].values()) + list(b["context_questions"].values())]
    leak_docs += [(d["_file"], {"flow": d.get("flow"), "required_roles": d.get("required_roles")}) for _, d in B.flows(b)]
    for where, doc in leak_docs:
        for path, kind, hit in scan_leaks(doc):
            err(where, f"vendor leak ({kind}) '{hit}' at {path}: allowed only in adapter folders, broker recipes and value tables")

    # ---------- triage-neutrality gate: triage/ and contract/ ----------
    for path in sorted(glob.glob(os.path.join(B.TRIAGE, "**", "*.yaml"), recursive=True) + glob.glob(os.path.join(B.CONTRACT, "*.yaml"))):
        rel = os.path.relpath(path, B.ROOT)
        for where, kind, hit in neutrality_hits(path):
            err(rel, f"triage-neutral layer: {kind} '{hit}' ({where}); vendors, libraries and the broker's internals belong to the broker or intake (derived_from is the only exception)")

    # replay coverage (tests/replay/coverage.yaml): every detection is listed; a detection that is not replayable has a reason
    # and is capped at Recommend (no_tp_replay_data); a replayable one names its test files and has a fires_on rule
    cov_path = os.path.join(B.ROOT, "tests", "replay", "coverage.yaml")
    cov = ((yaml.safe_load(open(cov_path)) or {}).get("detections") or {}) if os.path.exists(cov_path) else {}
    fires = {os.path.basename(p)[:-5] for p in glob.glob(os.path.join(B.ROOT, "tests", "replay", "fires_on", "D-*.yaml"))}
    py_rules = os.path.join(B.ROOT, "tests", "replay", "fires_on_python.py")
    fires |= set(re.findall(r'"(D-\d{4})"\s*:', open(py_rules).read())) if os.path.exists(py_rules) else set()
    for did, d in sorted(b["detections"].items()):
        c = cov.get(did)
        if c is None:
            err("tests/replay/coverage.yaml", f"{did} is not listed (replayable, or not replayable with a reason)")
        elif not c.get("replayable"):
            if not str(c.get("reason") or "").strip():
                err("tests/replay/coverage.yaml", f"{did}: not replayable needs a reason")
            if d.get("max_mode") != "recommend" or "no_tp_replay_data" not in E.auto_excluded(d):
                err("tests/replay/coverage.yaml", f"{did}: not replayable, so it must be capped at Recommend with auto_excluded_reason no_tp_replay_data")
        else:
            if not c.get("tests_from"):
                err("tests/replay/coverage.yaml", f"{did}: replayable needs tests_from (the security_content test files)")
            if did not in fires:
                err("tests/replay/coverage.yaml", f"{did}: replayable needs a fires_on rule (tests/replay/fires_on/{did}.yaml)")
    for did in sorted(set(cov) - set(b["detections"])):
        err("tests/replay/coverage.yaml", f"{did} is not a detection in the bank")

    for path in sorted(glob.glob(os.path.join(B.ROOT, "engine", "**", "*.py"), recursive=True)):
        rel = os.path.relpath(path, B.ROOT)
        for kind, hit in engine_hits(path):
            err(rel, f"neutral executor: {kind} '{hit}'; the executor names no vendor, detection, file format, field or broker internal")
    if not glob.glob(os.path.join(B.ROOT, "engine", "executor.py")):
        err("engine/executor.py", "missing: the executor is the only flow-walking code")

    # ---------- contract: question IDs and answer types, status and trust, message envelope ----------
    con = b["contract"]
    cq = con["questions"]
    asked = set(b["questions"]) | set(b["context_questions"])
    if set(cq) != asked:
        err("bank/contract/questions.yaml", f"must list every question exactly once: missing {sorted(asked - set(cq))[:5]}, extra {sorted(set(cq) - asked)[:5]}")
    ans = con.get("answer") or {}
    if set(ans.get("status") or {}) != {"answered", "unknown", "source_unavailable", "sources_disagree"}:
        err("bank/contract/answer.yaml", "status values are answered, unknown, source_unavailable, sources_disagree")
    if set(ans.get("trust") or {}) != set(E.TRUST):
        err("bank/contract/answer.yaml", "trust values are checked and not_checked")
    for qid in sorted(asked & set(cq)):
        q = b["questions"].get(qid) or b["context_questions"][qid]
        cap = caps.get(q["capability"]["name"]) or {}
        want = dict(cap.get("answer") or {})
        if want.pop("values_from", None):
            want["values"] = (classes.get(q["capability"]["inputs"].get("class")) or {}).get("values")
        got = cq[qid].get("answer") or {}
        if got.get("type") not in (ans.get("answer_types") or {}):
            err("bank/contract/questions.yaml", f"{qid}: answer type {got.get('type')} is not a contract answer type")
        if got != want:
            err("bank/contract/questions.yaml", f"{qid}: contract answer {got} differs from what the broker implements ({want})")
    env = con.get("envelope") or {}
    for kind, need in (("request", E.ENVELOPE_REQUEST), ("answer", E.ENVELOPE_ANSWER)):
        req = set((env.get(kind) or {}).get("required") or [])
        missing = (set(need) | {"run_or_window"}) - req
        if missing:
            err("bank/contract/envelope.yaml", f"{kind} schema must require {', '.join(sorted(missing))}")
    if set(env.get("ids") or {}) != {"alert_id", "run_id", "entity_window_id", "request_id", "measurement_id"}:
        err("bank/contract/envelope.yaml", "ids are alert_id, run_id, entity_window_id, request_id and measurement_id")
    if "question_timeout_seconds" not in params:
        err("bank/triage/parameters.yaml", "question_timeout_seconds (the per-question deadline) must be a bounded parameter")
    # B4: a missed deadline and a defer past its maximum wait are source_unavailable; source_unavailable is never cached
    ef = "bank/contract/envelope.yaml"
    if (env.get("deadline") or {}).get("on_miss") != "source_unavailable":
        err(ef, "deadline.on_miss must be source_unavailable (a missed deadline never answers unknown and never supports a close)")
    if (env.get("defer_rule") or {}).get("past_max_wait") != "source_unavailable":
        err(ef, "defer_rule.past_max_wait must be source_unavailable")
    if (env.get("defer_rule") or {}).get("max_wait_parameter") not in params or set((env.get("defer") or {}).get("reasons") or []) != {"overload", "rate_limited"}:
        err(ef, "defer needs reasons overload and rate_limited and a bounded max_wait_parameter")
    for p_ in ("question_timeout_seconds", (env.get("defer_rule") or {}).get("max_wait_parameter")):
        if p_ in params and params[p_].get("reduces_scrutiny_when") != "higher":
            err(f"bank/triage/parameters.yaml {p_}", "a longer deadline or wait lets more answers arrive instead of flagging: reduces_scrutiny_when higher")
    cache = env.get("cache") or {}
    if "source_unavailable" in (cache.get("cached_statuses") or []) or "source_unavailable" not in (cache.get("never_cached") or []):
        err(ef, "source_unavailable is never cached: only completed measurements are idempotent per request_id")
    if "deliberately" not in str((env.get("ids") or {}).get("request_id")) or "transport retry" not in str((env.get("ids") or {}).get("request_id")):
        err(ef, "request_id: the attempt grows only on a deliberate re-ask; a transport retry reuses the request_id")
    if "deadline" in str((ans.get("status") or {}).get("unknown")):
        err("bank/contract/answer.yaml", "status unknown must not cover a missed deadline (that is source_unavailable)")
    exs = con.get("examples") or {}
    pending = {}
    for r in exs.get("pending") or []:
        for m in E.envelope_missing(r, "request"):
            err("bank/contract/envelope_examples.yaml", f"request {r.get('request_id')}: missing {m}")
        pending[r.get("request_id")] = r
    for a in exs.get("answers") or []:
        for m in E.envelope_missing(a.get("message") or {}, "answer"):
            err("bank/contract/envelope_examples.yaml", f"answer '{a.get('name')}': missing {m}")
        ok, why = E.accept_answer(pending, a.get("message") or {}, a.get("received_at"))
        if ok != (a.get("expect") == "accept") or (not ok and a.get("reason") and a["reason"] != why):
            err("bank/contract/envelope_examples.yaml", f"answer '{a.get('name')}': expected {a.get('expect')}, the acceptance rule says {why}")
    if not env.get("deadline") or not env.get("defer_rule") or not env.get("cache"):
        pass   # reported above
    else:
        for sq in exs.get("sequences") or []:
            got, why = E.resolve_request(b, sq["request"], sq.get("events") or [])
            if got != sq.get("expect"):
                err("bank/contract/envelope_examples.yaml", f"sequence '{sq.get('name')}': expected {sq.get('expect')}, the resolution rule says {got} ({why})")
        for rt in exs.get("retries") or []:
            probs = B.cache_problems(b, rt["served"])
            if (rt.get("expect") == "valid") != (not probs) or (probs and not any(rt["expect"] in p_ for p_ in probs)):
                err("bank/contract/envelope_examples.yaml", f"retries '{rt.get('name')}': expected {rt.get('expect')}, the cache rule says {probs or 'valid'}")
        if not any(sq.get("expect") == "source_unavailable" and any("defer" in e for e in sq.get("events") or []) for sq in exs.get("sequences") or []) or \
                not any(rt.get("expect") != "valid" for rt in exs.get("retries") or []):
            err("bank/contract/envelope_examples.yaml", "needs a defer-past-max-wait sequence and a cached-source_unavailable retry example")

    # S7: each translation's known-answer tests run through the broker's run_status
    for tname, tdoc in b["value_tables"].items():
        for ka in tdoc.get("known_answers") or []:
            got, _, prov = B.run_status(b, {"tables": [tname], "matches": [ka["alert"]]}, None, sha256=ka.get("sha256"))
            if got != ka.get("expect"):
                err(tdoc["_file"], f"known answer '{ka.get('name')}': expected {ka.get('expect')}, the broker answers {got} ({prov})")
    if not any(ka for t in b["value_tables"].values() for ka in t.get("known_answers") or [] if t.get("evidence")):
        err("bank/broker/translations", "a table with an evidence spec needs known-answer tests (S7)")

    # ---------- vendor names, bundle ----------
    named = [("bank/broker/capabilities.yaml", b["capabilities"]), ("bank/triage/parameters.yaml", b["parameters"]), ("bank/triage/context_rules.yaml", cr),
             ("bank/triage/reason_codes.yaml", list(b["reason_codes"].values())), ("bank/intake/pilot.yaml", {**b["pilot"], "detections": [{k: v for k, v in x.items() if k != "source_rule"} for x in b["pilot"]["detections"]]})]
    for coll in ("questions", "explanations", "facts", "detections", "techniques", "context_questions"):
        named += [(d["_file"], {k: v for k, v in d.items() if k != "seed"}) for d in b[coll].values()]
    for where, doc in named:
        for path, hit in scan_text(doc):
            err(where, f"vendor/product name or query syntax '{hit}' at {path}")
    for u in b["use_cases"]:
        for path, hit in scan_text(u, exempt=EXEMPT_KEYS | {"linked", "covered_by"}):
            err(f"bank/intake/use_cases.yaml {u['id']}", f"vendor/product name '{hit}' at {path}")
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
    if any(k in bundle[x] for x in bundle for k in ("value_tables", "translations", "recipes")):
        err("runtime bundle", "translations are recipe data and never enter a runtime bundle")
    # the triage bundle carries the contract and the triage layer only: nothing the broker implements
    tjson = json.dumps(bundle["triage"])
    for needle, what in (('"capability"', "a capability"), ('"question_map"', "the broker's question map"), ("CF-0", "a context-list ID"),
                         ('"source_authority"', "source authority"), ('"alert_classes"', "translation classes")):
        if needle in tjson:
            err("triage bundle", f"carries {what}; the Triage agent sees only questions and answers with status and trust")

    # ---------- value tables ----------
    row_kinds = {}
    n_close = n_auto_today = n_auto_rows = 0
    for tname, t in b["value_tables"].items():
        w = t["_file"]
        for k in ("vendor", "product", "feed", "source", "references", "license", "classes"):
            if k not in t:
                err(w, f"missing {k}")
        if t.get("source") not in ("edr_api", "siem_copy", "alert"):
            err(w, "source must be edr_api, siem_copy or alert")
        generic = t.get("scope") == "generic"
        answers = t.get("answers")
        for cname, spec in (t.get("classes") or {}).items():
            if answers:
                vals = (caps.get(answers) or {}).get("answer", {}).get("values")
                if not vals or cname != "run_status":
                    err(w, f"a table answering {answers} holds the class run_status with that capability's values")
                    continue
                cdef = {"values": vals, "default": "unknown"}
            elif cname not in classes:
                err(w, f"unknown alert class {cname}")
                continue
            else:
                cdef = classes[cname]
            policy_keys = {"param", "cidr_param", "policy", "customer_policy", "accepted", "allowed", "low_risk_list", "high_risk_list"}
            if policy_keys & set(spec) or any(policy_keys & set((r.get("match") or {})) for r in spec.get("rows") or []):
                err(w, f"{cname}: a value table holds what a vendor's values mean, never a customer's policy or context (parameters or context lists)")
            if spec.get("default", cdef["default"]) not in cdef["values"]:
                err(w, f"{cname}: default not a class value")
            for i, r in enumerate(spec.get("rows") or []):
                if r.get("value") not in cdef["values"]:
                    err(w, f"{cname} row {i}: value {r.get('value')!r} is not a value of the class")
                rid = r.get("id") or f"row {i}"
                if not r.get("id") or [x.get("id") for x in spec["rows"]].count(r["id"]) > 1:
                    err(w, f"{cname} row {i}: needs an id, unique in the table")
                if r.get("kind") not in ROW_KINDS:
                    err(w, f"{cname} {rid}: kind must be one of {', '.join(ROW_KINDS)} (verified is per customer, in the customer layer)")
                if "verified" in r:
                    err(w, f"{cname} {rid}: verified is per customer (bank/broker/customers/<c>/verifications.yaml), not a row key")
                if r.get("kind") == "ambiguous" and r.get("value") != "unknown":
                    err(w, f"{cname} {rid}: an ambiguous row maps to {r.get('value')!r}, which could support a close; it must answer unknown")
                if r.get("kind") == "standards_defined" and not r.get("standard"):
                    err(w, f"{cname} {rid}: a standards-defined row cites its standard (for example RFC 9110 section 15)")
                if r.get("kind") == "proposed" and r.get("proposed_by") != "model":
                    err(w, f"{cname} {rid}: a proposed row records proposed_by: model (build mode only; it answers not_checked until checked and frozen)")
                if r.get("questions") and set(r["questions"]) - set(b["questions"]):
                    err(w, f"{cname} {rid}: questions lists unknown question IDs")
                if not isinstance(r.get("match"), dict) or not r["match"]:
                    err(w, f"{cname} {rid}: needs a match")
                row_kinds[r.get("kind")] = row_kinds.get(r.get("kind"), 0) + 1
    # a translation limited to some questions (questions: [...]) is never read by an endpoint question; quarantine rows
    # for messages and documents are always limited to the email and DLP questions (round 5 decision)
    users = {}
    for _, d in B.flows(b):
        for st in d["flow"]:
            for x in [st] + (st.get("guards") or []):
                users.setdefault(x.get("question"), set()).add(d.get("family", "technique_fallback"))
    for tname, t in b["value_tables"].items():
        for cname, spec in (t.get("classes") or {}).items():
            for r in spec.get("rows") or []:
                vals = [str(v).lower() for v in (r.get("match") or {}).get("value", []) if isinstance(v, str)] if isinstance((r.get("match") or {}).get("value"), list) else []
                if cname == "control_action" and {"quarantined", "quarantine"} & set(vals) and not r.get("questions"):
                    err(t["_file"], f"{cname} {r.get('id')}: a quarantine translation lists the email and DLP questions it serves (questions: [...])")
                stage = {"email.delivery_stage": "email", "dlp.egress_stage": "data_protection"}
                for key, fam in stage.items():
                    if key in (r.get("match") or {}):
                        wrong = {f for qid in r.get("questions") or [] for f in users.get(qid, set())} - {fam}
                        if not r.get("questions") or wrong:
                            err(t["_file"], f"{cname} {r.get('id')}: a row on {key} serves {fam} questions only (each stage is its own concept; round 6)")
                for qid in r.get("questions") or []:
                    bad = users.get(qid, set()) - {"email", "data_protection"}
                    if bad:
                        err(t["_file"], f"{cname} {r.get('id')}: {qid} is used by {', '.join(sorted(bad))} flows; this translation is limited to email and DLP questions")
    for tname, t in b["value_tables"].items():
        if bool(t.get("fallback")) != (t.get("source") == "siem_copy"):
            err(t["_file"], "a table whose source is a fallback (siem_copy) declares fallback: true, and only such a table")
    info.append(f"value-table rows: {row_kinds.get('unverified', 0)} unverified (may support a close in Shadow and Recommend, marked; never in Auto), "
                f"{row_kinds.get('ambiguous', 0)} ambiguous (unknown in every mode)")
    for tname, t in b["value_tables"].items():
        if t.get("source") == "siem_copy" and t.get("fallback_for") and t["fallback_for"] not in b["value_tables"]:
            err(t["_file"], f"fallback_for {t['fallback_for']} is not a value table")
    if "generic" not in b["value_tables"]:
        err("bank/broker/translations", "a generic table is required")

    # ---------- sources (Sigma, ATT&CK) ----------
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

    # ---------- flows ----------
    for kind, d in B.flows(b):
        w = d["_file"]
        for k in REQUIRED[kind]:
            if k not in d:
                err(w, f"missing {k}")
        for k in OLD_KEYS & set(d):
            err(w, f"old key {k}: use required_roles, role references and the precedent_validity_hours parameter")
        if kind == "technique" and d.get("max_mode") != "recommend":
            err(w, "technique fallback must be capped at recommend")
        techs = d.get("techniques", [d["id"]] if kind == "technique" else [])
        for t in techs:
            if attack_ids is not None and t not in attack_ids:
                err(w, f"technique {t} not active in ATT&CK v20.0")
            if kind == "rule" and d.get("alert_type") != "control" and t not in b["techniques"]:
                warnings.append(f"{d['id']}: no technique fallback for {t}")
        if kind == "rule":
            vendor = d.get("alert_type") == "control"
            if d.get("alert_type") not in ("control", "analytic") or d.get("family") not in B.BATCHES or d["family"] == "technique_fallback":
                err(w, f"alert_type must be control or analytic, family one of {', '.join(f for f in B.BATCHES if f != 'technique_fallback')}")
            if not re.fullmatch(r"D-\d{4}", d["id"]) or os.path.basename(os.path.dirname(w)) != d.get("family"):
                err(w, "detections have neutral IDs (D-0001...) and live in triage/detections/<family>/")
            if d.get("fp_quality") not in ("good", "vague", "none", "generic"):
                err(w, f"fp_quality {d.get('fp_quality')} must be good|vague|none|generic")
            if vendor:
                if b["use_cases"] and d.get("use_case") not in {u["id"] for u in b["use_cases"]}:
                    err(w, f"use_case {d.get('use_case')} not in the catalog")
            ls = d.get("sigma_logsource") or []
            if not ls and not (vendor and d.get("sigma_logsource_none")):
                err(w, "sigma_logsource (intake/rule-map.yaml) must list at least one entry (control-alert families may leave it empty with sigma_logsource_none)")
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
        # roles: every reference the flow makes needs its role in required_roles (else the alert flags entity_missing)
        roles = d.get("required_roles") or []
        for r in roles:
            if r not in R.ROLES:
                err(w, f"required_roles: {r} is not a role of normalized alert v1")
        derived = set(d.get("derived_fields") or {})
        for path, problem in scan_fields({k: v for k, v in d.items() if k not in ("flow",)}, ""):
            err(w, f"{problem} at {path}")
        for n, spec in (d.get("derived_fields") or {}).items():
            src = spec.get("from") if isinstance(spec.get("from"), list) else [spec.get("from")]
            for s_ in src:
                m = R.REF.fullmatch(str(s_)) if s_ else None
                if not m or m.group(1) not in ("role", "derived"):
                    err(w, f"derived_fields.{n}: from must be role: or derived: references")
        used_refs = list(refs_in(d.get("fingerprint") or [])) + list(refs_in(d.get("fingerprint_influence") or {}))
        used_refs += list(refs_in([d.get("precedent_entity"), d.get("precedent_entity_fallback")] if d.get("precedent_entity_fallback") else [d.get("precedent_entity")]))
        used_refs += list(refs_in(d.get("derived_fields") or {}))
        for kk, name in used_refs:
            msg = R.check_ref(kk, name, derived)
            if msg:
                err(w, msg)
        if set(d.get("fingerprint") or []) != set(d.get("fingerprint_influence") or {}):
            err(w, "fingerprint_influence must rate exactly the fingerprint's references")
        fi = d.get("fingerprint_influence") or {}
        for fp in d.get("fingerprint", []):
            e = fi.get(fp) or {}
            if e.get("rating") not in B.RATING_ORDER or not str(e.get("reason", "")).strip():
                err(w, f"fingerprint_influence must rate {fp} (none|low|medium|high, with a reason)")
            fb = e.get("fallback")
            if fb and (not R.REF.fullmatch(str(fb.get("field"))) or fb.get("rating") not in B.RATING_ORDER):
                err(w, f"fingerprint_influence {fp}: fallback needs a role reference and a rating")
        pe = str(d.get("precedent_entity"))
        if not R.REF.fullmatch(pe) or pe.split(":")[0] not in ("role", "derived", "alert"):
            err(w, "precedent_entity must be a role (or derived) reference")
        for k, v in (d.get("parameters") or {}).items():
            param_check(err, f"{w} parameters", params, k, v)
        if "auto_requires" in d:
            err(w, "auto_requires is replaced by per-customer verification: a detection is Auto-eligible for a customer only when every value-table row on its close paths is verified for that customer")
        flow = d.get("flow", [])
        if not 1 <= len(flow) <= 5:
            err(w, f"flow has {len(flow)} steps (1-5 allowed)")
        refs_ok = all(st.get("question") in b["questions"] for st in flow) and all(
            gd.get("question") in b["questions"] for st in flow for gd in st.get("guards") or [])
        if refs_ok:
            calls = max((B.path_calls(b, p, o, gs) for p, o, gs in E.enumerate_paths(flow)), default=0)
            if calls > budget:
                err(w, f"worst path makes {calls} capability calls (steps plus guards), over the budget of {budget}")

        def check_item(where, item, q):
            """A step or guard: its rule matches the question's answer type; its inputs resolve to roles the detection requires."""
            cap = caps[q["capability"]["name"]]
            atype = cap["answer"]["type"]
            rule = item.get("rule")
            if atype == "bool" or cap.get("kind") == "derived":
                if rule:
                    err(where, f"{q['id']} answers {atype}: no rule")
            elif not rule:
                err(where, f"{q['id']} answers {atype}: the step needs a rule (thresholds live on the step, as parameters)")
            elif atype in ("count", "number"):
                ops = set(rule) & {"gte", "lte"}
                if len(ops) != 1 or set(rule) - {"gte", "lte"}:
                    err(where, f"{q['id']}: a {atype} rule is exactly one of gte or lte")
                else:
                    v = rule[ops.pop()]
                    if isinstance(v, dict):
                        p = param_check(err, where, params, v.get("param"))
                        if p and isinstance(p.get("default"), list):
                            err(where, f"{v['param']} is a list; a {atype} rule compares with a number")
                    elif v != 0:
                        err(where, f"{q['id']}: compare with a parameter, not the literal {v} (only 0 is structural)")
            elif atype == "enum":
                allowed = (classes.get((B.step_inputs(q, item)).get("class")) or {}).get("values") if cap["answer"].get("values_from") else cap["answer"]["values"]
                if not (set(rule) & {"yes", "yes_unless"}) or set(rule) - {"yes", "yes_unless", "unknown"} or {"yes", "yes_unless"} <= set(rule):
                    err(where, f"{q['id']}: an enum rule has yes or yes_unless, and optionally unknown")
                for k, v in rule.items():
                    if isinstance(v, dict):
                        p = param_check(err, where, params, v.get("param"))
                        vals = (p or {}).get("bounds", {}).get("allowed") if p else []
                        if p and not isinstance(p.get("default"), list):
                            err(where, f"{v['param']} is not a list")
                        if p and allowed and not set(vals or []) <= set(allowed):
                            err(where, f"{v['param']} allows values outside the class: {sorted(set(vals or []) - set(allowed))}")
                    elif not isinstance(v, list) or (allowed and set(v) - set(allowed)):
                        err(where, f"{q['id']}: rule {k} values must be from {allowed}")
            inputs = B.step_inputs(q, item)
            for kk, name in refs_in(inputs):
                msg = R.check_ref(kk, name, derived)
                if msg:
                    err(where, f"{q['id']} {msg}")
                ref = f"{kk}:{name}"
                if ref in R.PLACEHOLDERS or ref == "bind:precedent_entity":
                    err(where, f"{q['id']} needs a bind for {ref}")
                role = R.role_of(ref)
                if role and role not in roles:
                    err(where, f"{q['id']} uses {ref}; add {role} to required_roles")
            for path, problem in scan_fields({k: v for k, v in item.items() if k not in ("guards",)}, ""):
                err(where, f"{problem} at {path}")

        def reads_context(q):
            c = caps.get(q["capability"]["name"], {})
            return c.get("kind") == "derived" or c.get("group") == "context"

        for n, st in enumerate(flow, 1):
            where = f"{w} step {n}"
            if st.get("step") != n:
                err(where, "steps must be numbered 1..n")
            q = b["questions"].get(st.get("question"))
            if not q:
                err(where, f"unknown question {st.get('question')}")
                continue
            check_item(where, st, q)
            if reads_context(q) and E.outcome_kind(st.get("on_unknown", "")) == "escalate":
                err(where, f"{q['id']} reads context: an unknown context answer flags (context_unknown), it never escalates")
            if n == 1:
                want, got = B.q0_rating(d), (st.get("attacker_influence") or {}).get("rating")
                if q["id"] != "Q-0000":
                    err(where, "flow must start with Q-0000")
                elif got != want or not str((st.get("attacker_influence") or {}).get("reason", "")).strip():
                    err(where, f"Q0 attacker_influence is {got}; the fingerprint fields give {want} (with a reason)")
                elif d.get("q0_off_reason"):
                    if st["on_yes"] != "next":
                        err(where, "q0_off_reason is set: Q0's on_yes must be next (a precedent never closes this detection)")
                elif st["on_yes"] != ("next" if want == "high" else "close:inherit:precedent_match"):
                    err(where, f"Q0 rated {want}: on_yes must be {'next' if want == 'high' else 'close:inherit:precedent_match'}")
                fb = B.q0_fallback_rating(d)
                if fb and fb != want and (st.get("attacker_influence") or {}).get("fallback_rating") != fb:
                    err(where, f"Q0 needs attacker_influence.fallback_rating {fb} (fingerprint fallback)")
                if (st.get("bind") or {}).get("entity") != d.get("precedent_entity"):
                    err(where, "Q0 must bind entity to the detection's precedent_entity")
            elif st.get("attacker_influence"):
                err(where, "step-level attacker_influence is only for Q0")
            kinds = {E.outcome_kind(st.get(e, "")) for e in ("on_yes", "on_no", "on_unknown")} - {"next"}
            for gd in st.get("guards") or []:
                gw = f"{where} guard {gd.get('question')}"
                gq = b["questions"].get(gd.get("question"))
                if not gq:
                    err(gw, "unknown question")
                    continue
                check_item(gw, gd, gq)
                if reads_context(gq) and "unknown" in (gd.get("when") or []) and gd.get("then") == "escalate":
                    err(gw, f"{gq['id']} reads context: an unknown context answer flags (context_unknown), it never escalates")
                if gd.get("then") not in ("flag", "escalate"):
                    err(gw, "then must be flag or escalate")
                applies = gd.get("applies_to", ["close"])
                if not applies or set(applies) - {"close", "flag"}:
                    err(gw, "applies_to lists close and/or flag; a guard never attaches to an escalate outcome")
                for k in applies:
                    if k not in kinds:
                        err(gw, f"applies to {k}, but the step has no {k} outcome")
                    elif E.SEVERITY.get(gd.get("then"), -1) <= E.SEVERITY[k]:
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
            cap = caps.get(q["capability"]["name"], {})
            for edge in ("on_yes", "on_no", "on_unknown"):
                v = st.get(edge)
                m = E.OUTCOME.match(v or "")
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
        if not any(E.OUTCOME.match(st.get(e, "")) and st.get(e, "").startswith("close") for st in flow[1:] for e in ("on_yes", "on_no")):
            info.append(f"{d['id']}: no close outside Q0 (escalate/flag only)")
        # close paths: usable in Shadow/Recommend; Auto-eligible only with every value-table row on them verified per customer
        for path, out, guards in E.enumerate_paths(flow):
            if out.startswith("close"):
                n_close += 1
                needs = B.close_path_rows(b, path, guards, detection=d)
                eligible = not needs and E.auto_eligible_path(d, path)
                n_auto_rows += eligible
                n_auto_today += eligible and E.path_proven(b, d, E.path_id(d, path))

    # use-case catalog
    ucs = b["use_cases"]
    src_to_bank = B.source_ids(b, ("escu", "product_alert"))
    if ucs:
        ids = [u["id"] for u in ucs]
        if len(set(ids)) != len(ids):
            err("bank/intake/use_cases.yaml", "duplicate use-case ids")
        if sorted(u["rank"] for u in ucs) != list(range(1, len(ucs) + 1)):
            err("bank/intake/use_cases.yaml", "ranks must be 1..n with no gaps")
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
            w = f"bank/intake/use_cases.yaml {u['id']}"
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
                    if src == "product_alert" and x["id"] not in src_to_bank:
                        err(w, f"linked {x['id']} is not a product-alert source in intake/rule-map.yaml")
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
            want = ("generic" if u.get("family") == "vendor" and covered and all(x.startswith("product_alert:") for x in covered)
                    else ("rule-level-full" if len(covered) == n_linked else "rule-level-partial") if covered
                    else "technique-only" if fallbacks else "none")
            if u.get("coverage") != want:
                err(w, f"coverage is {u.get('coverage')}, bank says {want}")
    # Auto exclusions (bank/triage/auto_exclusions.yaml): detection-level codes cap at Recommend, step-level codes flag that close in Auto
    ax = b["auto_exclusions"]
    destructive = set((ax.get("destructive_or_anti_forensic") or {}).get("techniques") or [])
    for did, d in list(b["detections"].items()) + list(b["techniques"].items()):
        if d.get("max_mode") == "recommend" and not d.get("max_mode_reason"):
            err(d["_file"], "max_mode recommend needs a max_mode_reason")
        codes = E.auto_excluded(d)
        for code in codes:
            if (ax.get(code) or {}).get("applies_to") != "detection":
                err(d["_file"], f"auto_excluded_reason {code} is not a detection-level code in bank/triage/auto_exclusions.yaml")
        if codes and d.get("max_mode") != "recommend":
            err(d["_file"], "auto_excluded_reason at detection level needs max_mode: recommend")
        if d.get("max_mode") == "recommend" and not codes:
            err(d["_file"], "max_mode recommend needs an auto_excluded_reason code (bank/triage/auto_exclusions.yaml)")
        if did in b["techniques"] and "no_tp_replay_data" not in codes:
            err(d["_file"], "technique fallback needs auto_excluded_reason no_tp_replay_data")
        if did in b["detections"] and set(d.get("techniques") or []) & destructive and "destructive_or_anti_forensic" not in codes:
            err(d["_file"], f"destructive or anti-forensic technique {sorted(set(d['techniques']) & destructive)}: needs max_mode recommend with auto_excluded_reason destructive_or_anti_forensic")
        for st in d["flow"]:
            for code in E.auto_excluded(d, st):
                if (ax.get(code) or {}).get("applies_to") != "step":
                    err(d["_file"], f"step {st['step']}: auto_excluded_reason {code} is not a step-level code in bank/triage/auto_exclusions.yaml")
                if not any(st[e].startswith("close") for e in ("on_yes", "on_no")):
                    err(d["_file"], f"step {st['step']}: auto_excluded_reason on a step that never closes")
    info.append(f"close paths: {n_close} usable in Shadow and Recommend; {n_auto_today} Auto-eligible today with no customer verifications "
                f"({n_auto_rows} pass the row and cap rules but are not proven; the rest need value-table rows verified per customer, "
                "or are capped at Recommend)")

    # proof records for close paths (bank/contract/proof.yaml)
    pf = (b["contract"].get("proof") or {})
    close_ids = {E.path_id(d, path): d["id"] for _, d in B.flows(b) for path, out, g in E.enumerate_paths(d["flow"]) if out.startswith("close")}
    all_ids = {E.path_id(d, path) for _, d in B.flows(b) for path, out, g in E.enumerate_paths(d["flow"])}
    if not pf.get("record") or set(pf.get("statuses") or []) != {"draft", "reviewed"} or "proof_min_tp_events" not in params:
        err("bank/contract/proof.yaml", "needs the record schema, statuses draft and reviewed, and the bounded parameter proof_min_tp_events")
    seen_ids = set()
    for rec in b.get("proofs") or []:
        w = f"{rec.get('_file')} {rec.get('id')}"
        for k in (pf.get("record") or {}).get("required") or []:
            if not rec.get(k):
                err(w, f"proof record missing {k}")
        if rec.get("status") not in (pf.get("statuses") or []):
            err(w, f"status {rec.get('status')!r} must be draft or reviewed")
        if rec.get("status") == "reviewed" and not (str(rec.get("reviewer") or "").strip() and str(rec.get("reviewed_on") or "").strip()):
            err(w, "a reviewed proof record needs a reviewer and a review date")
        if rec.get("id") in seen_ids:
            err(w, "duplicate proof record id")
        seen_ids.add(rec.get("id"))
        for pid in rec.get("paths") or []:
            if pid not in all_ids:
                err(w, f"path {pid} does not exist in the current flows (stale or mistyped)")
            elif pid not in close_ids:
                err(w, f"path {pid} is not a close path")

    # suggested dispositions a bank flag declares (flag_suggests on a step): a real close disposition, on a flag edge
    for _, d in B.flows(b):
        for st in d["flow"]:
            for edge, spec in (st.get("flag_suggests") or {}).items():
                w = f"{d['_file']} step {st['step']} flag_suggests {edge}"
                m = E.OUTCOME.match(str((spec or {}).get("suggests") or ""))
                if edge not in ("on_yes", "on_no", "on_unknown") or st.get(edge) != "flag":
                    err(w, "a suggestion attaches to a flag edge of the step")
                if not m or not m.group(2):
                    err(w, f"suggests {spec.get('suggests')!r} is not a close disposition")
                elif m.group(2) == "inherit" or (b["reason_codes"].get(m.group(3)) or {}).get("disposition") != m.group(2):
                    err(w, f"suggests {spec.get('suggests')!r} is not a real close disposition of this detection (reason code and disposition must match; never a precedent)")
                if not str((spec or {}).get("reason") or "").strip():
                    err(w, "a suggestion needs a one-line reason (what blocks the close)")

    # designed contract entries and guard-only context questions
    designed = b["contract"].get("designed") or {}
    for did_, entry in designed.items():
        if did_ in b["questions"] or did_ in b["context_questions"] or did_ in b["contract"]["questions"]:
            err("bank/contract/questions.yaml designed", f"{did_} is designed but already in the bank or the contract's questions")
        if (entry.get("answer") or {}).get("type") not in (b["contract"]["answer"].get("answer_types") or {}):
            err("bank/contract/questions.yaml designed", f"{did_}: answer type must be a contract answer type")
    guard_only_ids = {c for c, e in list(b["contract"]["questions"].items()) + list(designed.items()) if e.get("guard_only")}
    for sect in ("entity_guard", "q0", "priority", "q0067"):
        reads = set(((cr.get(sect) or {}).get("reads")) or []) | E.rule_reads((cr.get(sect) or {}).get("yes_when") or (cr.get(sect) or {}).get("hot_when") or {})
        for cid in sorted(reads & guard_only_ids):
            err("bank/triage/context_rules.yaml", f"{sect} reads guard-only context question {cid}: only guards may read it")
    for nd in cr.get("closes_need_known") or []:
        if nd.get("question") in guard_only_ids:
            err("bank/triage/context_rules.yaml closes_need_known", f"{nd['question']} is guard-only")
    for _, d in B.flows(b):
        for st in d["flow"]:
            q = b["questions"].get(st["question"]) or {}
            used = (E.rule_reads(q.get("context_rule") or {}) | set((q.get("inputs") or {}).get("reads") or [])) & guard_only_ids
            if used:
                err(f"{d['_file']} step {st['step']}", f"{q.get('id')} reads guard-only context question(s) {sorted(used)}; it may only be a guard")

    # shared verifications per product version (bank/contract/verification.yaml)
    sv = (b["contract"].get("verification") or {})
    for (prod, ver), rec in (b.get("shared_verifications") or {}).items():
        w = rec.get("_file")
        for k in (sv.get("shared_record") or {}).get("required") or []:
            if not rec.get(k):
                err(w, f"shared verification missing {k}")
        if os.path.basename(os.path.dirname(w)) != prod or os.path.basename(w)[:-5] != ver:
            err(w, f"a shared verification lives at bank/broker/verifications/shared/{prod}/{ver}.yaml")
        if prod not in b["value_tables"]:
            err(w, f"{prod} is not a translation")
        else:
            rows = {r["id"] for spec in (b["value_tables"][prod].get("classes") or {}).values() for r in spec.get("rows") or []}
            for rid in rec.get("covers") or []:
                if rid not in rows:
                    err(w, f"covers {rid}, not a row of {prod}")
    for cust, c in b["customers"].items():
        for smp in c.get("sanity_samples") or []:
            for k in (sv.get("sanity_sample") or {}).get("required") or []:
                if smp.get(k) in (None, ""):
                    err(c["_file"], f"sanity sample missing {k}")

    # customer layer: per-customer verifications, product versions and detection modes
    for cust, c in b["customers"].items():
        w = c["_file"]
        for rec in c.get("verifications") or []:
            for problem in B.verification_problems(b, cust, rec, TODAY):
                err(w, f"verification {rec.get('table')}/{rec.get('row')}: {problem}")
        for did, mode in (c.get("modes") or {}).items():
            d = b["detections"].get(did) or b["techniques"].get(did)
            if mode not in E.MODES or not d:
                err(w, f"mode {did}: {mode} must be shadow, recommend or auto for a detection or technique fallback in the bank")
                continue
            if mode != "auto":
                continue
            if did in b["techniques"]:
                err(w, f"{did}: technique fallbacks are capped at Recommend (no true-positive replay data)")
            elif d.get("max_mode") == "recommend":
                err(w, f"{did}: capped at Recommend ({d.get('max_mode_reason')})")
            unproven = sorted(E.path_id(d, path) for path, out, guards in E.enumerate_paths(d["flow"])
                              if out.startswith("close") and not E.path_proven(b, d, E.path_id(d, path)))
            if unproven:
                err(w, f"{did}: set to Auto with unproven close paths (no reviewed proof with enough replay): {len(unproven)}, e.g. {unproven[0]}")
            missing = sorted({f"{t}/{r}" for path, out, guards in E.enumerate_paths(d["flow"]) if out.startswith("close")
                              for t, r in B.close_path_rows(b, path, guards, customer=cust, detection=d) if not B.row_verified(b, cust, t, r, TODAY)})
            if missing:
                err(w, f"{did}: set to Auto while unverified value-table rows sit on its close paths: {', '.join(missing[:6])}"
                       + (f" and {len(missing) - 6} more" if len(missing) > 6 else ""))
    for x in b["pilot"]["detections"]:
        if x["id"] not in b["detections"]:
            err("bank/intake/pilot.yaml", f"{x['id']} has no detection file")
    used_q = {st["question"] for _, d in B.flows(b) for st in d["flow"]} | {
        gd["question"] for _, d in B.flows(b) for st in d["flow"] for gd in st.get("guards") or []}
    for qid in sorted(set(b["questions"]) - used_q):
        warnings.append(f"{qid}: not used by any flow")
    used_rc = {E.OUTCOME.match(st[e]).group(3) for _, d in B.flows(b) for st in d["flow"] for e in ("on_yes", "on_no") if st[e].startswith("close")}
    for rc in sorted(set(b["reason_codes"]) - used_rc):
        if b["reason_codes"][rc].get("disposition") != "flag" and not b["reason_codes"][rc].get("retired"):
            warnings.append(f"reason code {rc}: not used")

    for title, items in (("ERROR", errors), ("WARN", warnings), ("INFO", info)):
        for i in items:
            print(f"{title} {i}")
    print(f"\n{len(b['detections'])} detections, {len(b['techniques'])} technique fallbacks, {len(b['questions'])} questions, "
          f"{len(b['context_questions'])} context questions, {len(b['facts'])} context facts, {len(caps)} capabilities, "
          f"{len(b['parameters'])} parameters, {len(b["value_tables"])} translations: {len(errors)} errors, {len(warnings)} warnings")
    B.require_loaded("validate", detections=len(b["detections"]), flows=sum(1 for _ in B.flows(b)), questions=len(b["questions"]))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
