"""Shared loader for the YAML question bank."""
import glob
import os
import re
import sys

import yaml

import roles as ROLES_MOD

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BANK = os.path.join(ROOT, "bank")
REF = ROLES_MOD.REF
OUTCOME = re.compile(r"^(next|escalate|flag|close:(\w+):(\w+))$")


def _load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def _by_id(pattern):
    out = {}
    for path in sorted(glob.glob(os.path.join(BANK, pattern))):
        doc = _load(path)
        doc["_file"] = os.path.relpath(path, ROOT)
        out[doc["id"]] = doc
    return out


def load():
    caps = _load(os.path.join(BANK, "capabilities.yaml"))
    facts = _by_id("facts/CF-*.yaml")
    seeds = {}
    for path in sorted(glob.glob(os.path.join(BANK, "seeds", "*.yaml"))):
        doc = _load(path)
        doc["_file"] = os.path.relpath(path, ROOT)
        seeds[doc["fact"]] = doc
        if doc["fact"] in facts:
            facts[doc["fact"]]["seed"] = doc.get("entries", doc.get("data"))
    tables = {}
    for path in sorted(glob.glob(os.path.join(BANK, "recipes", "value_tables", "*.yaml"))):
        doc = _load(path)
        doc["_file"] = os.path.relpath(path, ROOT)
        tables[os.path.basename(path)[:-5]] = doc
    overlays = {}
    for path in sorted(glob.glob(os.path.join(BANK, "overlays", "customer", "*", "parameters.yaml"))):
        overlays[os.path.basename(os.path.dirname(path))] = dict(_load(path) or {}, _file=os.path.relpath(path, ROOT))
    params_doc = _load(os.path.join(BANK, "parameters.yaml"))
    return {
        "seeds": seeds,
        "value_tables": tables,
        "overlays": overlays,
        "context_questions": _by_id("context/C-*.yaml"),
        "context_rules": _load(os.path.join(BANK, "context_rules.yaml")),
        "precedence": params_doc.get("precedence"),
        "capabilities": caps,
        "capability_by_name": {c["name"]: c for c in caps["capabilities"]},
        "parameters": params_doc["parameters"],
        "reason_codes": {r["code"]: r for r in _load(os.path.join(BANK, "reason_codes.yaml"))["reason_codes"]},
        "questions": _by_id("questions/Q-*.yaml"),
        "explanations": _by_id("explanations/BE-*.yaml"),
        "facts": facts,
        "detections": _by_id("detections/*/*.yaml"),
        "techniques": _by_id("techniques/T*.yaml"),
        "pilot": _load(os.path.join(BANK, "pilot.yaml")),
        "use_cases": (_load(os.path.join(BANK, "use_cases.yaml")) or {}).get("use_cases", []) if os.path.exists(os.path.join(BANK, "use_cases.yaml")) else [],
    }


def source_ids(b):
    """Map each rule-level detection's source-library id (e.g. escu:<file stem>) to its bank id."""
    out = {}
    for did, d in b["detections"].items():
        if did.startswith("vendor:"):
            out[did] = did
            continue
        src = d.get("source")
        if isinstance(src, dict) and src.get("path"):
            stem = os.path.splitext(os.path.basename(src["path"]))[0]
            out[did.split(":", 1)[0] + ":" + stem] = did
    return out


def flows(b):
    """All flows: rule-level detections first, then technique fallbacks."""
    for d in b["detections"].values():
        yield "rule", d
    for t in b["techniques"].values():
        yield "technique", t


# Batches the gates run over. No batch argument means every batch; an unknown name is an error, never "nothing to check".
BATCHES = {"escu": "rule-level detections from the public rule library (escu:)",
           "vendor": "generic vendor-alert families (vendor:)",
           "technique": "technique fallbacks (ATT&CK technique IDs)"}


def batch_of(level, flow_id):
    return "technique" if level == "technique" else flow_id.split(":", 1)[0]


def select_batches(args):
    """Batch names from the command line: none means all; an unknown name exits 2 naming the known ones."""
    unknown = [a for a in args if a not in BATCHES]
    if unknown:
        sys.exit(f"unknown batch {', '.join(unknown)}: expected one of {', '.join(BATCHES)} (or none for all)")
    return set(args) or set(BATCHES)


def require_loaded(gate, **counts):
    """A gate that loaded nothing has checked nothing: fail, saying what it expected to load."""
    empty = [k for k, v in counts.items() if not v]
    if empty:
        sys.exit(f"FAIL {gate}: loaded 0 {', 0 '.join(empty)}; expected at least one of each "
                 f"(loaded: {', '.join(f'{k}={v}' for k, v in counts.items())})")


def walk_refs(obj):
    """Yield (kind, field) for every entity reference in a capability input value."""
    if isinstance(obj, str):
        yield from REF.findall(obj)
    elif isinstance(obj, list):
        for x in obj:
            yield from walk_refs(x)
    elif isinstance(obj, dict):
        for x in obj.values():
            yield from walk_refs(x)


def step_inputs(question, step):
    """Capability inputs for a question after the step's bind overrides."""
    inputs = dict(question["capability"].get("inputs", {}))
    inputs.update(step.get("bind") or {})
    return inputs


def list_refs(question):
    """Context list ids (CF-xxxx) the question's capability reads."""
    ids = []
    for v in question["capability"].get("inputs", {}).values():
        for x in v if isinstance(v, list) else [v]:
            if isinstance(x, str) and x.startswith("CF-"):
                ids.append(x.split(".")[0])
    for x in (question.get("needs") or {}).get("context", []):
        if x not in ids:
            ids.append(x)
    return ids


def close_paths(b, flow):
    """For each non-precedent close: (step, edge, steps whose answer it rests on).

    A close at step k rests on step k and on every earlier gate step (yes goes on;
    no and unknown both stop the flow), since only a yes gets past a gate.
    """
    paths, gates = [], []
    for st in flow[1:]:
        for edge in ("on_yes", "on_no"):
            if st[edge].startswith("close"):
                paths.append((st["step"], edge, gates + [st["step"]]))
        if st["on_yes"] == "next" and st["on_no"] != "next" and st["on_unknown"] != "next":
            gates.append(st["step"])
    return paths


def tainted_closes(b, flow):
    """Closes that flag until onboarding: reached through a yes (a step's, or a guard's that needs one)
    that reads unverified seed data. Returns (step, edge, [steps or 'step:guard Q-xxxx'])."""
    unverified = {fid for fid, f in b["facts"].items() if has_unverified_seed(f)}
    reads = lambda qid: set(list_refs(b["questions"][qid])) & unverified
    out = {}
    for path, outcome, guards in enumerate_paths(flow):
        last, ans = path[-1]
        if not outcome.startswith("close") or last["step"] == 1:
            continue
        bad = [st["step"] for st, a in path if a == "yes" and reads(st["question"])]
        bad += [f"{last['step']}:guard {g['question']}" for g in guards if guard_requires_yes(g) and reads(g["question"])]
        if bad:
            key = (last["step"], "on_" + ans)
            out[key] = sorted(set(out.get(key, [])) | set(bad), key=str)
    return [(s, e, bad) for (s, e), bad in sorted(out.items())]


def close_edges(flow):
    """Distinct (step, edge) pairs that close, outside Q0."""
    return sorted({(st["step"], e) for st in flow[1:] for e in ("on_yes", "on_no") if st[e].startswith("close")})


def has_unverified_seed(fact):
    def scan(o):
        if isinstance(o, dict):
            if o.get("verified") is False:
                return True
            return any(scan(v) for v in o.values())
        if isinstance(o, list):
            return any(scan(v) for v in o)
        return False
    return scan(fact.get("seed"))


# ---------- flow execution model shared by the gates ----------
ANS = (("yes", "on_yes"), ("no", "on_no"), ("unknown", "on_unknown"))
RATING_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
LOCAL_KINDS = {"alert"}   # answered from the normalized alert (source: alert): no tool call, no call budget


def is_local(b, qid):
    """No call budget: the budget counts calls to outside tools only (scope.budget_counts_sources). The normalized alert,
    our cached context and list store, case memory and rules over cached context answers are our own and do not count."""
    cap = b["capability_by_name"].get(b["questions"][qid]["capability"]["name"], {})
    outside = set(b["capabilities"]["scope"].get("budget_counts_sources") or [])
    return cap.get("kind") in LOCAL_KINDS or (cap.get("source_authority") or {}).get("authoritative") not in outside


def guard_requires_yes(g):
    """A guard that fires on 'no' (and always on unknown) means the close needs a yes from it."""
    return "no" in g.get("when", ["yes"])


SEVERITY = {"close": 0, "flag": 1, "escalate": 2}


def outcome_kind(out):
    return "close" if out.startswith("close") else out


def guard_applies(g, out):
    """Guards attach to close outcomes by default; applies_to may add flag. Never escalate."""
    return outcome_kind(out) in g.get("applies_to", ["close"])


def raise_outcome(out, guard_results):
    """Apply guard answers to an outcome: the strongest result wins, order does not matter.
    guard_results: [(guard, answer)]. An unknown answer raises to flag; a triggered guard to its then."""
    best = SEVERITY[outcome_kind(out)]
    for g, a in guard_results:
        if a == "unknown":
            best = max(best, SEVERITY["flag"])
        elif a in g.get("when", ["yes"]):
            best = max(best, SEVERITY[g["then"]])
    if best == SEVERITY[outcome_kind(out)]:
        return out
    return {1: "flag", 2: "escalate"}[best]


def enumerate_paths(flow):
    """Yield (path, outcome, guards). path = [(step, answer)]; guards = the step's guards that apply to that outcome."""
    def walk(i, path):
        if i >= len(flow):
            return
        st = flow[i]
        for ans, edge in ANS:
            out = st[edge]
            here = path + [(st, ans)]
            if out == "next":
                yield from walk(i + 1, here)
            else:
                yield here, out, [g for g in st.get("guards") or [] if guard_applies(g, out)]
    yield from walk(0, [])


def _call_key(item):
    return (item["question"], repr(sorted((item.get("bind") or {}).items())))


def path_calls(b, path, outcome, guards):
    """Capability calls on one path: distinct (question, bind) pairs among steps and applicable guards,
    since the same question with the same inputs is answered once per alert."""
    keys = {_call_key(st) for st, _ in path if not is_local(b, st["question"])}
    keys |= {_call_key(g) for g in guards if not is_local(b, g["question"])}
    return len(keys)


def rating(b, item, profile=None):
    """Attacker influence for a step or guard: a step-level override wins over the question's own."""
    ai = item.get("attacker_influence") or b["questions"][item["question"]]["attacker_influence"]
    if profile == "fingerprint_fallback" and ai.get("fallback_rating"):
        return ai["fallback_rating"]
    if profile and profile in (ai.get("by_source") or {}):
        return ai["by_source"][profile]
    return ai["rating"]


def yes_ratings(b, path, outcome, guards, profile=None):
    """Ratings of every yes a close rests on: yes answers on the path, plus guards that need a yes."""
    out = [(st["question"], rating(b, st, profile)) for st, a in path if a == "yes"]
    if outcome.startswith("close"):
        out += [(g["question"], rating(b, g, profile)) for g in guards if guard_requires_yes(g)]
    return out


def q0_rating(d):
    """Q0's influence follows the detection's fingerprint: if any fingerprint field is none/low, an
    attacker cannot freely reproduce it; if every field is attacker-chosen, Q0 is high."""
    return _q0(d, fallback=False)


def q0_fallback_rating(d):
    """Q0's rating when fingerprint fields fall back to their declared fallback field (None if no fallback)."""
    fi = d.get("fingerprint_influence") or {}
    if not any("fallback" in (fi.get(f) or {}) for f in d.get("fingerprint", [])):
        return None
    return _q0(d, fallback=True)


def _q0(d, fallback):
    fi = d.get("fingerprint_influence") or {}
    ranks = [RATING_ORDER[fi[f]["rating"]] for f in d.get("fingerprint", []) if f in fi]
    if not ranks:
        return None
    best = min(ranks)
    if fallback:
        # A fallback field weakens the precedent entity itself, so it caps how good Q0 can be.
        best = max([best] + [RATING_ORDER[fi[f]["fallback"]["rating"]] for f in d.get("fingerprint", []) if "fallback" in (fi.get(f) or {})])
    return {0: "low", 1: "low", 2: "medium", 3: "high"}[best]


# ---------- typed answers and Triage-side rules ----------
def answer_type(b, qid):
    q = b["questions"].get(qid) or b["context_questions"].get(qid)
    return b["capability_by_name"][q["capability"]["name"]]["answer"]["type"]


def param_value(b, name, detection=None, customer=None, entity_class=None):
    """Resolve a parameter by precedence: customer + detection > customer > detection > global.
    A parameter with by_entity_class takes the entity's class value (C-08) at the global level."""
    ov = (b["overlays"].get(customer) or {}).get("overrides") or [] if customer else []
    did = (detection or {}).get("id")
    for want_det in (True, False):
        for o in ov:
            if o.get("param") == name and bool(o.get("detection")) == want_det and (not want_det or o["detection"] == did):
                return o["value"]
    if detection and name in (detection.get("parameters") or {}):
        return detection["parameters"][name]
    p = b["parameters"][name]
    if entity_class and entity_class in (p.get("by_entity_class") or {}):
        return p["by_entity_class"][entity_class]
    return p["default"]


def _vals(b, v, detection):
    if isinstance(v, dict) and "param" in v:
        v = param_value(b, v["param"], detection)
    return v if isinstance(v, list) else [v]


def apply_rule(b, rule, value, atype, detection=None):
    """Turn a typed broker value into yes / no / unknown on the Triage side. value None means status unknown."""
    if value is None:
        return "unknown"
    if atype == "bool":
        return "yes" if value else "no"
    if not rule:
        raise ValueError(f"a {atype} answer needs a step rule")
    if atype in ("count", "number"):
        if "gte" in rule:
            return "yes" if float(value) >= float(_vals(b, rule["gte"], detection)[0]) else "no"
        if "lte" in rule:
            return "yes" if float(value) <= float(_vals(b, rule["lte"], detection)[0]) else "no"
        raise ValueError(f"count rule needs gte or lte: {rule}")
    if atype == "enum":
        v = str(value).lower()
        if "unknown" in rule and v in {str(x).lower() for x in _vals(b, rule["unknown"], detection)}:
            return "unknown"
        if "yes" in rule:
            return "yes" if v in {str(x).lower() for x in _vals(b, rule["yes"], detection)} else "no"
        if "yes_unless" in rule:
            return "no" if v in {str(x).lower() for x in _vals(b, rule["yes_unless"], detection)} else "yes"
        raise ValueError(f"enum rule needs yes or yes_unless: {rule}")
    raise ValueError(atype)


def context_rule(b, rule, answers):
    """Evaluate a Triage-side rule over cached context answers ({"C-06": False, "C-08": "workstation"}), in three values:
    True, False, or None when the result depends on a context answer that is unknown (missing, or None for source unavailable).
    None makes the step or guard answer unknown, which flags (context_unknown); missing context never escalates."""
    if "any" in rule:
        got = [context_rule(b, r, answers) for r in rule["any"]]
        return True if True in got else (None if None in got else False)
    if "all" in rule:
        got = [context_rule(b, r, answers) for r in rule["all"]]
        return False if False in got else (None if None in got else True)
    (cid, want), = rule.items()
    got = answers.get(cid)
    if got is None or got == "unknown":
        return None
    if isinstance(want, dict) and "in" in want:
        return got in want["in"]
    return got == want


def classify(b, cls, values, product_tables=(), answers=None):
    """Map raw alert values to an alert-class value through value tables. A product table that defines the class
    is authoritative (no row matched gives the class default); otherwise the generic table applies.
    values: ordered dict of the raw properties or role values the class reads ("value" in a row means the first one).
    Returns (class value, matching row with its table, or None)."""
    first = str(next(iter(values.values()), "") or "")
    joined = " ".join(str(v or "") for v in values.values()).strip()
    if answers:
        default = "unknown"
        generic = [t for t, d in b["value_tables"].items() if d.get("scope") == "generic" and d.get("answers") == answers]
    else:
        default = b["capabilities"]["alert_classes"][cls]["default"]
        generic = ["generic"]
    for tname in [t for t in product_tables if t in b["value_tables"]] + generic:
        spec = (b["value_tables"][tname].get("classes") or {}).get(cls)
        if not spec:
            continue
        for r in spec["rows"]:
            m, ok = r["match"], True
            if "pattern" in m:
                ok = bool(joined) and re.search(m["pattern"], joined, re.I) is not None
            else:
                for k, want in m.items():
                    got = (first if k == "value" else str(values.get(k, "") or "")).lower()
                    if got not in {str(w).lower() for w in (want if isinstance(want, list) else [want])}:
                        ok = False
            if ok:
                return r["value"], dict(r, table=tname)
        return spec.get("default", default), None
    return default, None


def kth_lowest_weekly_hosts(weekly_hosts, of_weeks, min_weeks):
    """org.prevalence statistic: the k-th lowest weekly distinct-host count over the last of_weeks weeks, k = of_weeks - min_weeks + 1.
    It is >= N exactly when at least min_weeks of the of_weeks weeks reach N hosts (tools/test_prevalence.py)."""
    weeks = sorted(weekly_hosts[-of_weeks:])
    if len(weeks) < of_weeks or not 1 <= min_weeks <= of_weeks:
        return None
    return weeks[of_weeks - min_weeks]


def class_values(b, cls, answers=None):
    """(values, raise_only) of an alert class, or of the enum a value table answers (endpoint.run_status)."""
    spec = b["capability_by_name"][answers]["answer"] if answers else b["capabilities"]["alert_classes"][cls]
    return spec["values"], set(spec.get("raise_only") or [])


def raise_only(b, cls, value, row, answers=None):
    """The raise-only rule: an answer read from an unverified value-table row, or from a fallback source's table,
    stands only if it can only raise scrutiny (raise_only: ran, high risk, a malicious category). Anything that
    could lead to a close (pre_execution, low risk, blocked, a benign category) becomes unknown: None, the status
    unknown, so the step follows on_unknown whatever its rule says. A class default (no row matched) is the bank's
    own value, not a vendor reading, and stands."""
    if row is None or value == "unknown":
        return value
    _, ro = class_values(b, cls, answers)
    table = b["value_tables"].get(row.get("table"), {})
    if value in ro or (row.get("verified") and not table.get("fallback")):
        return value
    return None


def classify_effective(b, cls, values, product_tables=(), answers=None):
    v, row = classify(b, cls, values, product_tables, answers=answers)
    return raise_only(b, cls, v, row, answers), row


def run_status(b, api, siem_copy):
    """endpoint.run_status as the Tool Broker answers it.
    api: None when the endpoint API is unavailable or not granted; otherwise {"tables": [...], "matches": [raw evidence dicts]}
         (an empty or multiple match list answers unknown). siem_copy: {"tables": [...], "raw": {...}} or None.
    Returns (value, source). The API is authoritative; the SIEM copy is a fallback. Both go through the raise-only rule:
    pre_execution counts only from a verified row of the API table; a fallback answer never supports a close."""
    if api is not None:
        if len(api.get("matches") or []) != 1:
            return "unknown", "edr_api"
        v, _ = classify_effective(b, "run_status", api["matches"][0], api.get("tables") or [], answers="endpoint.run_status")
        return v or "unknown", "edr_api"
    if siem_copy:
        v, _ = classify_effective(b, "run_status", siem_copy.get("raw") or {}, siem_copy.get("tables") or [], answers="endpoint.run_status")
        return v or "unknown", "siem_copy"
    return None, None
