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


# Layout (docs/design-decisions.md §9): contract/ is the interface both sides share (question IDs, answer types, status,
# trust, message envelope); triage/ is what the Triage agent uses (detections, flows, questions, context questions,
# parameters, reason codes, modes); broker/ is what the Tool Broker uses (capabilities, sources, translations,
# verifications, context lists); intake/ is what the normalizer and the Detection Engineer use (rule map, use cases, pilot).
CONTRACT, TRIAGE, BROKER, INTAKE = (os.path.join(BANK, x) for x in ("contract", "triage", "broker", "intake"))


def _provenance(doc):
    """Flatten a triage file's derived_from (source, license) into the in-memory keys the gates read."""
    df = doc.get("derived_from") or {}
    if "source" in df and "source" not in doc:
        doc["source"] = df["source"]
    if "license" in df and "license" not in doc:
        doc["license"] = df["license"]
    return doc


def _with_broker_side(questions, qmap):
    """Rebuild each question's capability from its triage inputs and the broker's question map."""
    for qid, q in questions.items():
        m = qmap.get(qid) or {}
        cap = {"name": m.get("capability"), "inputs": dict(q.get("inputs") or {}, **(m.get("inputs") or {}))}
        if q.get("optional_inputs"):
            cap["optional_inputs"] = q["optional_inputs"]
        q["capability"] = cap
        needs = dict(q.get("needs") or {}, **(m.get("needs") or {}))
        if needs:
            q["needs"] = needs
        _provenance(q)
    return questions


def load():
    caps = _load(os.path.join(BROKER, "capabilities.yaml"))
    # the triage semantics (step rules, guards, influence scale, source profiles) and the answer contract are read by the
    # gates alongside the capabilities, so they are merged in memory; on disk they live in triage/ and contract/
    caps.update(_load(os.path.join(TRIAGE, "semantics.yaml")) or {})
    facts = _by_id("broker/facts/CF-*.yaml")
    seeds = {}
    for path in sorted(glob.glob(os.path.join(BROKER, "seeds", "*.yaml"))):
        doc = _load(path)
        doc["_file"] = os.path.relpath(path, ROOT)
        seeds[doc["fact"]] = doc
        if doc["fact"] in facts:
            facts[doc["fact"]]["seed"] = doc.get("entries", doc.get("data"))
    tables = {}
    for path in sorted(glob.glob(os.path.join(BROKER, "translations", "*.yaml"))):
        doc = _load(path)
        doc["_file"] = os.path.relpath(path, ROOT)
        tables[os.path.basename(path)[:-5]] = doc
    overlays = {}
    for path in sorted(glob.glob(os.path.join(TRIAGE, "customers", "*", "parameters.yaml"))):
        overlays[os.path.basename(os.path.dirname(path))] = dict(_load(path) or {}, _file=os.path.relpath(path, ROOT))
    customers = {}   # the customer layer: product versions and verifications (broker), detection modes (triage)
    for path in sorted(glob.glob(os.path.join(BROKER, "customers", "*", "verifications.yaml"))):
        customers[os.path.basename(os.path.dirname(path))] = dict(_load(path) or {}, _file=os.path.relpath(path, ROOT))
    for path in sorted(glob.glob(os.path.join(TRIAGE, "customers", "*", "modes.yaml"))):
        c = customers.setdefault(os.path.basename(os.path.dirname(path)), {"_file": os.path.relpath(path, ROOT)})
        c["modes"] = (_load(path) or {}).get("modes") or {}
        c["_modes_file"] = os.path.relpath(path, ROOT)
    params_doc = _load(os.path.join(TRIAGE, "parameters.yaml"))
    broker_params = (_load(os.path.join(BROKER, "parameters.yaml")) or {}).get("parameters") or {}
    for name, p in broker_params.items():
        p["layer"] = "broker"
    qmap = (_load(os.path.join(BROKER, "question_map.yaml")) or {}).get("questions") or {}
    rule_map = (_load(os.path.join(INTAKE, "rule-map.yaml")) or {}).get("rules") or []
    detections = _by_id("triage/detections/*/*.yaml")
    for r in rule_map:   # offline metadata from intake, for the gates that check it; never part of the triage files
        d = detections.get(r["d_id"])
        if d:
            for k in ("data_source", "sigma_logsource", "sigma_logsource_none", "sigma_refs", "use_case", "source", "escu_uuid"):
                if k in r:
                    d[k] = r[k]
            _provenance(d)
    use_cases_path = os.path.join(INTAKE, "use_cases.yaml")
    return {
        "seeds": seeds,
        "value_tables": tables,
        "overlays": overlays,
        "customers": customers,
        "contract": {"questions": {q["id"]: q for q in (_load(os.path.join(CONTRACT, "questions.yaml")) or {}).get("questions") or []},
                     "answer": _load(os.path.join(CONTRACT, "answer.yaml")) if os.path.exists(os.path.join(CONTRACT, "answer.yaml")) else {},
                     "envelope": _load(os.path.join(CONTRACT, "envelope.yaml")) if os.path.exists(os.path.join(CONTRACT, "envelope.yaml")) else {},
                     "examples": _load(os.path.join(CONTRACT, "envelope_examples.yaml")) if os.path.exists(os.path.join(CONTRACT, "envelope_examples.yaml")) else {}},
        "question_map": qmap,
        "rule_map": rule_map,
        "context_questions": _with_broker_side(_by_id("triage/context/C-*.yaml"), qmap),
        "context_rules": _load(os.path.join(TRIAGE, "context_rules.yaml")),
        "precedence": params_doc.get("precedence"),
        "capabilities": caps,
        "capability_by_name": {c["name"]: c for c in caps["capabilities"]},
        "parameters": dict(params_doc["parameters"], **broker_params),
        "reason_codes": {r["code"]: r for r in _load(os.path.join(TRIAGE, "reason_codes.yaml"))["reason_codes"]},
        "questions": _with_broker_side(_by_id("triage/questions/Q-*.yaml"), qmap),
        "explanations": {k: _provenance(v) for k, v in _by_id("triage/explanations/BE-*.yaml").items()},
        "facts": facts,
        "detections": detections,
        "techniques": {k: _provenance(v) for k, v in _by_id("triage/techniques/T*.yaml").items()},
        "pilot": _load(os.path.join(INTAKE, "pilot.yaml")),
        "use_cases": (_load(use_cases_path) or {}).get("use_cases", []) if os.path.exists(use_cases_path) else [],
        "auto_exclusions": (_optional(os.path.join(TRIAGE, "auto_exclusions.yaml")).get("reasons") or {}),
        "evidence": _optional(os.path.join(CONTRACT, "evidence.yaml")),
        "severity": _optional(os.path.join(CONTRACT, "severity.yaml")),
        "severity_map": _optional(os.path.join(INTAKE, "severity-map.yaml")),
        "proposals": _optional(os.path.join(TRIAGE, "proposals.yaml")),
    }


def _optional(path):
    return (_load(path) or {}) if os.path.exists(path) else {}


def auto_excluded(d, st=None):
    """The auto_excluded_reason codes of a detection (max_mode recommend) or of one of its close steps (bank/triage/auto_exclusions.yaml)."""
    x = (st if st is not None else d).get("auto_excluded_reason")
    return [] if not x else [x] if isinstance(x, str) else list(x)


def auto_eligible_path(d, path):
    """A close path can close in Auto only if the detection is not capped at Recommend and no step on it is auto-excluded."""
    return d.get("max_mode") != "recommend" and not any(auto_excluded(d, st) for st, _ in path if st["on_" + _].startswith("close"))


ENVELOPE_REQUEST = ("request_id", "question_id", "scope_profile", "deadline")
ENVELOPE_ANSWER = ("request_id", "measurement_id", "answer", "status", "trust", "provenance")


def envelope_missing(msg, kind):
    """Required envelope fields a request or answer lacks (contract/envelope.yaml), with run_or_window: exactly one of
    run_id or entity_window_id."""
    need = ENVELOPE_REQUEST if kind == "request" else ENVELOPE_ANSWER
    out = [k for k in need if k not in msg or msg[k] in (None, "")]
    if ("run_id" in msg) == ("entity_window_id" in msg):
        out.append("run_id or entity_window_id (exactly one)")
    return out


def accept_answer(pending, msg, received_at):
    """The Triage agent's acceptance rule for one broker answer (contract/envelope.yaml). pending: {request_id: request}.
    Returns (accepted, reason). Rejected answers are logged; a late answer is logged and discarded, never applied."""
    missing = envelope_missing(msg, "answer")
    if missing:
        return False, f"missing {', '.join(missing)}"
    req = pending.get(msg["request_id"])
    if not req:
        return False, "no pending request"
    for k in ("run_id", "entity_window_id"):
        if req.get(k) != msg.get(k):
            return False, f"{k.replace('_', ' ').replace('entity window id', 'entity_window_id').replace('run id', 'run_id')} does not match the pending request"
    if _ts(received_at) > _ts(req["deadline"]):
        return False, "late"
    return True, "accepted"


def _ts(t):
    from datetime import datetime
    return datetime.fromisoformat(str(t).replace("Z", "+00:00")).timestamp()


def resolve_request(b, request, events):
    """What the Triage agent records for one request (contract/envelope.yaml deadline, defer_rule): the status of the
    accepted answer, or source_unavailable when no answer was accepted by the effective deadline. events: [{at, defer: {...}}
    or {at, answer: {...}}] in time order. A defer (overload or rate limiting) makes the request wait: its deadline moves to
    the first defer plus defer_max_wait_seconds and never further; it is never answered unknown.
    Returns (status, reason)."""
    env = b["contract"]["envelope"]
    deadline, first_defer = _ts(request["deadline"]), None
    max_wait = float(param_value(b, env["defer_rule"]["max_wait_parameter"]))
    for ev in events:
        at = _ts(ev["at"])
        if "defer" in ev:
            if at > deadline:
                break
            if (ev["defer"].get("reason") not in env["defer"]["reasons"]):
                return env["deadline"]["on_miss"], f"defer reason {ev['defer'].get('reason')!r} is not overload or rate limiting"
            first_defer = at if first_defer is None else first_defer
            deadline = first_defer + max_wait
            continue
        ok, why = accept_answer({request["request_id"]: dict(request, deadline=_iso(deadline))}, ev["answer"], ev["at"])
        if ok:
            return ev["answer"]["status"], "accepted"
    if first_defer is not None:
        return env["defer_rule"]["past_max_wait"], "deferred past defer_max_wait_seconds"
    return env["deadline"]["on_miss"], "no answer by the deadline"


def _iso(ts):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cache_problems(b, served):
    """Check the broker's answers to repeated sends of one request_id (transport retries) against the cache rule
    (contract/envelope.yaml cache): after a completed measurement a retry returns the same measurement_id; after
    source_unavailable a retry measures again, under a new measurement_id. served: [{status, measurement_id}]."""
    cache = b["contract"]["envelope"]["cache"]
    out = []
    for prev, cur in zip(served, served[1:]):
        if prev["status"] in cache["cached_statuses"] and cur["measurement_id"] != prev["measurement_id"]:
            out.append(f"measured twice: {prev['status']} {prev['measurement_id']} is a completed measurement, the retry must return it")
        if prev["status"] in cache["never_cached"] and cur["measurement_id"] == prev["measurement_id"]:
            out.append(f"{prev['status']} was cached: the retry returned {prev['measurement_id']} instead of measuring again")
    return out


def source_ids(b, libraries=None):
    """Map source rule IDs in the intake rule map (escu:<rule file>, sigma:<uuid>, product_alert:<kind>) to their D-IDs.
    libraries limits it to those libraries (the use-case catalog counts escu and product_alert matches as coverage;
    sigma references are closest-match leads)."""
    return {s["id"]: r["d_id"] for r in b["rule_map"] for s in r.get("sources") or [] if not libraries or s["library"] in libraries}


def legacy_ids(b):
    """The bank's own pre-round-5 detection IDs (escu:<name>, vendor:<family>) to D-IDs, for reports that compare rounds."""
    return {r["legacy_id"]: r["d_id"] for r in b["rule_map"] if r.get("legacy_id")}


def flows(b):
    """All flows: rule-level detections first, then technique fallbacks."""
    for d in b["detections"].values():
        yield "rule", d
    for t in b["techniques"].values():
        yield "technique", t


# Batches the gates run over. No batch argument means every batch; an unknown name is an error, never "nothing to check".
BATCHES = {"endpoint": "endpoint behaviour detections", "identity": "identity and account detections",
           "endpoint_malware": "endpoint malware alerts (AV/EDR)", "network": "network control alerts (firewall, IDS, WAF, proxy)",
           "email": "email alerts", "data_protection": "data-protection alerts (DLP, removable media)",
           "technique_fallback": "technique fallbacks (ATT&CK technique IDs)"}   # batches are detection families


def batch_of(level, d):
    """The family a flow belongs to: the detection's family, or technique_fallback."""
    return "technique_fallback" if level == "technique" else d["family"]


def select_batches(args):
    """Batch names from the command line: none means all; an unknown name exits 2 naming the known ones."""
    unknown = [a for a in args if a not in BATCHES]
    if unknown:
        sys.exit(f"unknown family {', '.join(unknown)}: expected one of {', '.join(BATCHES)} (or none for all)")
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


def severity_rank(b, level):
    """Position of a normalized severity (bank/contract/severity.yaml) on the scale, or None for anything else (raw or unmapped)."""
    scale = (b.get("severity") or {}).get("scale") or []
    return scale.index(level) if level in scale else None


def context_rule(b, rule, answers):
    """Evaluate a Triage-side rule over cached context answers ({"C-06": False, "C-08": "workstation", "C-02": {...}}), in three
    values: True, False, or None when the result depends on a context answer that is unknown (missing, or None for source
    unavailable). None makes the step or guard answer unknown, which flags (context_unknown); missing context never escalates.
    answers may also hold _mode (shadow, recommend, auto), _severity (this alert's normalized severity), _detection and
    _customer (for parameter values). A key C-xx.component reads one component of a count answer. Operators: in, gte, lte,
    not_above (normalized severity only), sum_of_severities (adds the day_detections_<severity> components) and modes (the
    condition holds only in those modes; elsewhere it is false)."""
    if "any" in rule:
        got = [context_rule(b, r, answers) for r in rule["any"]]
        return True if True in got else (None if None in got else False)
    if "all" in rule:
        got = [context_rule(b, r, answers) for r in rule["all"]]
        return False if False in got else (None if None in got else True)
    (key, want), = rule.items()
    cid, _, comp = key.partition(".")
    if isinstance(want, dict) and "modes" in want and answers.get("_mode", "recommend") not in want["modes"]:
        return False
    got = answers.get(cid)
    if got is None or got == "unknown":
        return None
    if comp and not (isinstance(want, dict) and "sum_of_severities" in want):
        got = got.get(comp) if isinstance(got, dict) else None
        if got is None:
            return None
    pv = lambda v: param_value(b, v["param"], answers.get("_detection"), answers.get("_customer"), answers.get("_entity_class")) if isinstance(v, dict) and "param" in v else v
    if not isinstance(want, dict):
        return got == want
    if "in" in want:
        return got in want["in"]
    if "not_above" in want:
        if want["not_above"] != "this_alert_severity":
            raise ValueError(f"not_above compares with this_alert_severity only: {want}")
        if got == "none":
            return True
        mine, other = severity_rank(b, answers.get("_severity")), severity_rank(b, got)
        return None if mine is None or other is None else other <= mine
    if "sum_of_severities" in want:
        if not isinstance(got, dict):
            return None
        levels = pv(want["sum_of_severities"])
        if any(severity_rank(b, lv) is None for lv in levels):
            raise ValueError(f"sum_of_severities lists a value outside the normalized scale: {levels}")
        parts = [got.get(f"{comp}_{lv}") for lv in levels]
        if None in parts:
            return None
        got = sum(parts)
    if "gte" in want:
        return float(got) >= float(pv(want["gte"]))
    if "lte" in want:
        return float(got) <= float(pv(want["lte"]))
    raise ValueError(f"unknown context rule operator: {want}")


def entity_hot(b, answers):
    """The entity guard (bank/triage/context_rules.yaml entity_guard): True (hot), False, or None (unknown: closes flag)."""
    return context_rule(b, b["context_rules"]["entity_guard"]["hot_when"], answers)


def q0(b, answers):
    """Q0 from the context answers (bank/triage/context_rules.yaml q0)."""
    return context_rule(b, b["context_rules"]["q0"]["yes_when"], answers)


def human_evidence(b, closures, analysts_distinct=True):
    """C-04's components from a list of recorded closes ({kind, analyst, ...}), by the one definition in
    bank/contract/evidence.yaml: audited closes, and independent human closes (manual closes in Shadow and analyst
    overrides, by distinct analysts). Kinds the definition lists under never (accepted recommendations, Auto closes,
    precedent matches) are not counted."""
    he = b["evidence"]["human_evidence"]
    counted = [c for c in closures if c["kind"] in he["counts"] and c["kind"] not in he["never"]]
    audited = sum(1 for c in counted if c["kind"] == "audited_close")
    human = [c for c in counted if c["kind"] in ("manual_shadow_close", "analyst_override")]
    return {"audited": audited, "independent_human": len({c.get("analyst") for c in human}) if analysts_distinct else len(human)}


def norm_value(v):
    """How a raw value is compared with a translation row: case-insensitive, surrounding space and trailing periods
    trimmed, inner whitespace collapsed ("Prevention, process killed." matches "Prevention, process killed")."""
    return re.sub(r"\s+", " ", str(v if v is not None else "")).strip().rstrip(".").strip().lower()


def classify(b, cls, values, product_tables=(), answers=None, question=None):
    """Map raw alert values to a class value through the broker's translations. A product translation that defines the class
    is authoritative (no row matched gives the class default); otherwise the generic translation applies.
    values: ordered dict of the raw properties or role values the class reads ("value" in a row means the first one).
    A row that lists the questions it serves (questions: [...]) is skipped for any other question.
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
            if r.get("questions") and question not in r["questions"]:
                continue
            m, ok = r["match"], True
            if "pattern" in m:
                ok = bool(joined) and re.search(m["pattern"], joined, re.I) is not None
            else:
                for k, want in m.items():
                    got = norm_value(first if k == "value" else values.get(k, ""))
                    if got not in {norm_value(w) for w in (want if isinstance(want, list) else [want])}:
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
    """(values, set()) of an alert class, or of the enum a translation answers (endpoint.run_status)."""
    spec = b["capability_by_name"][answers]["answer"] if answers else b["capabilities"]["alert_classes"][cls]
    return spec["values"], set(spec.get("raise_only") or [])


MODES = ("shadow", "recommend", "auto")
VERIFICATION_FIELDS = ("table", "row", "vendor_doc", "spot_check_alerts", "checked_by", "checked_on", "product_version", "expires")


def verification_problems(b, customer, rec, today):
    """Why a per-customer verification record does not verify its row ([] when it does)."""
    out = [f"missing {k}" for k in VERIFICATION_FIELDS if not rec.get(k)]
    t = b["value_tables"].get(rec.get("table"))
    row = next((r for spec in ((t or {}).get("classes") or {}).values() for r in spec.get("rows") or [] if r.get("id") == rec.get("row")), None)
    if row is None:
        out.append(f"no row {rec.get('table')}/{rec.get('row')}")
    elif row.get("kind") == "ambiguous":
        out.append("an ambiguous row cannot be verified")
    need = param_value(b, "verification_min_spot_check_alerts", customer=customer)
    if isinstance(rec.get("spot_check_alerts"), int) and rec["spot_check_alerts"] < need:
        out.append(f"spot check of {rec['spot_check_alerts']} alerts, below verification_min_spot_check_alerts ({need})")
    if rec.get("expires") and str(rec["expires"]) < str(today):
        out.append(f"expired {rec['expires']}")
    current = ((b["customers"].get(customer) or {}).get("products") or {}).get(rec.get("table"))
    if rec.get("product_version") and str(current) != str(rec["product_version"]):
        out.append(f"checked on product version {rec['product_version']}, customer runs {current}: the version change re-opens verification")
    return out


def row_verified(b, customer, table, row_id, today):
    """Verified is per customer: a complete, unexpired verification record for the customer's current product version."""
    if not customer:
        return False
    for rec in (b["customers"].get(customer) or {}).get("verifications") or []:
        if rec.get("table") == table and rec.get("row") == row_id and not verification_problems(b, customer, rec, today):
            return True
    return False


TRUST = ("checked", "not_checked")


def row_answer(b, cls, value, row, answers=None, ctx=None):
    """The broker's answer and trust from a matched translation row (contract: answer, status, trust).
    Returns (value or None for status unknown, trust, provenance). ctx: {"customer", "today"}.
    - ambiguous row: status unknown, in every mode (it never supports a close).
    - standards-defined row (for example HTTP status codes, RFC 9110): checked, once, in the shared broker layer.
    - row verified for this customer, read from the authoritative source: checked.
    - anything else (unverified row, model-proposed row, any fallback-source answer): not_checked.
    A class default (no row matched) is the bank's own value: checked.
    The Triage agent sees only the answer, status and trust; the provenance (<translation>/<row>) stays in the broker's log."""
    if row is None:
        return value, "checked", None
    prov = f"{row.get('table')}/{row.get('id')}"
    if row.get("kind") == "ambiguous":
        return None, "not_checked", prov
    ctx = ctx if ctx is not None else {}
    table = b["value_tables"].get(row.get("table"), {})
    if table.get("fallback"):
        return value, "not_checked", prov
    if row.get("kind") == "standards_defined" or row_verified(b, ctx.get("customer"), row.get("table"), row.get("id"), ctx.get("today", "")):
        return value, "checked", prov
    return value, "not_checked", prov


def close_path_rows(b, path, guards, customer=None, detection=None):
    """(translation, row id) pairs a close path may rest on, for Auto eligibility: the rows whose value, through the step's own
    rule, gives the answer the path takes (or, for a guard, an answer that lets the close stand). Ambiguous rows never do;
    standards-defined rows are checked in the shared layer and are left out. With a customer, only the product translations
    the customer runs plus the generic ones. Fallback-source translations are left out: their answers are always not_checked,
    so in Auto they flag rather than close and can never be what an Auto close rests on."""
    items = [(st, a) for st, a in path if a in ("yes", "no")] + [(g, None) for g in guards]
    runs = set(((b["customers"].get(customer) or {}).get("products") or {})) if customer else None
    out = set()
    for it, taken in items:
        q = b["questions"][it["question"]]
        name = q["capability"]["name"]
        if name == "alert.class":
            cls, answers = step_inputs(q, it).get("class"), None
        elif name == "endpoint.run_status":
            cls, answers = "run_status", name
        else:
            continue
        for tname, t in b["value_tables"].items():
            if t.get("answers") != answers or t.get("fallback") or (runs is not None and tname not in runs and t.get("scope") != "generic"):
                continue
            for r in ((t.get("classes") or {}).get(cls) or {}).get("rows") or []:
                if r.get("kind") in ("ambiguous", "standards_defined"):
                    continue
                try:
                    got = apply_rule(b, it.get("rule"), r.get("value"), "enum", detection)
                except ValueError:
                    got = None
                stands = got == taken if taken else (got not in (it.get("when") or ["yes"]) and got != "unknown")
                if stands:
                    out.add((tname, r["id"]))
    return out


def classify_effective(b, cls, values, product_tables=(), answers=None, ctx=None, question=None):
    """classify, then the row's answer and trust (row_answer). question limits rows that declare the questions they serve."""
    v, row = classify(b, cls, values, product_tables, answers=answers, question=question)
    return row_answer(b, cls, v, row, answers, ctx)


def alerted_evidence(b, alert, tables, sha256):
    """The raw run-status properties of the alerted file (S7). A product table with an evidence spec (Defender) lists the
    evidence items of the vendor alert: the broker picks the item whose file hash is the alerted file's, never the first
    item; none or several such items answer unknown. Each property is read only from the evidence types the spec allows
    (Defender: detectionStatus from the file, process and registry evidence subtypes; remediationStatus from the base type,
    so any item). A table without an evidence spec reads the alert's own properties. Returns (raw dict or None, reason)."""
    spec = next((b["value_tables"][t].get("evidence") for t in tables if (b["value_tables"].get(t) or {}).get("evidence")), None)
    if not spec:
        return alert, "alert properties"
    items = [e for e in alert.get("evidence") or [] if sha256 and any(
        str(_dig(e, path) or "").lower() == str(sha256).lower() for path in spec["hash_paths"].get(e.get("type"), []))]
    if len(items) != 1:
        return None, f"{len(items)} evidence items for the alerted file hash"
    item = items[0]
    raw = {}
    for prop, types in spec["properties"].items():
        if types == "base" or item.get("type") in types:
            raw[prop] = item.get(prop)
    return raw, f"evidence item {item.get('type')}"


def _dig(d, path):
    for k in path.split("."):
        d = (d or {}).get(k) if isinstance(d, dict) else None
    return d


def run_status(b, api, siem_copy, ctx=None, sha256=None):
    """endpoint.run_status as the Tool Broker answers it.
    api: None when the endpoint API is unavailable or not granted; otherwise {"tables": [...], "matches": [raw evidence dicts]}
         (an empty or multiple match list answers unknown). siem_copy: {"tables": [...], "raw": {...}} or None.
    Returns (value, trust, provenance). The API is authoritative; the SIEM copy is a fallback (always not_checked).
    No match, several matches or an ambiguous row answer unknown."""
    if api is not None:
        if len(api.get("matches") or []) != 1:
            return "unknown", "checked", "edr_api: no single matching alert"
        raw, why = alerted_evidence(b, api["matches"][0], api.get("tables") or [], sha256)
        if raw is None:
            return "unknown", "checked", f"edr_api: {why}"
        v, trust, prov = classify_effective(b, "run_status", raw, api.get("tables") or [], answers="endpoint.run_status", ctx=ctx)
        return v or "unknown", trust, prov
    if siem_copy:
        v, trust, prov = classify_effective(b, "run_status", siem_copy.get("raw") or {}, siem_copy.get("tables") or [], answers="endpoint.run_status", ctx=ctx)
        return v or "unknown", "not_checked", prov
    return None, "not_checked", None
