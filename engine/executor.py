"""The flow executor: the only code that walks a flow (docs/design-decisions.md §9, §14).

Everything that turns answers into an outcome lives here, and every tool imports it (tools/replay.py, tools/validate.py,
tools/redteam_paths.py, tools/equivalence.py, tools/rank_facts.py):
- running one alert through one flow (run_flow), with guards that only raise (the strongest wins);
- answer statuses (answered, unknown, source_unavailable, sources_disagree) and defer, through the message envelope;
- the trust and mode rule: a not_checked answer may support a close in Shadow and Recommend (marked), never in Auto, and
  in Auto the outcome is the stricter of that rule and the same flow with every not_checked answer read as unknown;
- Auto exclusions (a detection capped at Recommend, or an excluded close step);
- Q0 and the entity guard from the context answers, the guard re-evaluated before a close is written, and closes already
  written reopened when the entity turns hot;
- the human-evidence definition (bank/contract/evidence.yaml);
- step rules over typed answers and bounded parameters, derived fields and the fingerprint;
- static walks over a flow's paths for the gates (enumerate_paths, walk_outcomes).

The executor reads the bank as loaded dictionaries (the triage layer and the contract); it never reads files, never names a
detection, product or schema field, and talks to the Tool Broker only through the contract envelope: it sends a request
(request_id, run_id or entity_window_id, question ID, scope profile, deadline) to an injected answerer and accepts an
answer (answer, status, trust, measurement_id, provenance) only by the envelope's rules.

The answerer is any object with ask(request) -> [event], each event {"at": <RFC3339>, "answer": {...}} or
{"at": <RFC3339>, "defer": {...}} in time order (tests/replay/clean_room.py is the clean-room one).
The current time is a required argument of every public function that sends requests (run_flow, context_answers,
reopen_on_hot): an RFC3339 time; there is no default clock. Which context answers a close needs, and which context
question gives the entity class, come from the bank's context rules (closes_need_known, entity_guard.entity_class); the
executor names no context question.
(designed, not built: the runtime that hosts this executor and a live Tool Broker answerer.)
"""
import re
from datetime import datetime, timezone

OUTCOME = re.compile(r"^(next|escalate|flag|close:(\w+):(\w+))$")
ANS = (("yes", "on_yes"), ("no", "on_no"), ("unknown", "on_unknown"))
SEVERITY = {"close": 0, "flag": 1, "escalate": 2}
MODES = ("shadow", "recommend", "auto")
TRUST = ("checked", "not_checked")
ENVELOPE_REQUEST = ("request_id", "question_id", "scope_profile", "deadline")
ENVELOPE_ANSWER = ("request_id", "measurement_id", "answer", "status", "trust", "provenance")
REF = re.compile(r"\b(role|entity|derived|alert|bind):([A-Za-z_][A-Za-z0-9_.]*)")


# ---------- outcomes and guards ----------
def outcome_kind(out):
    return "close" if out.startswith("close") else out


def guard_applies(g, out):
    """Guards attach to close outcomes by default; applies_to may add flag. Never escalate."""
    return outcome_kind(out) in g.get("applies_to", ["close"])


def guard_requires_yes(g):
    """A guard that fires on 'no' (and always on unknown) means the close needs a yes from it."""
    return "no" in g.get("when", ["yes"])


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


# ---------- static walks over a flow (for the gates) ----------
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


def walk_outcomes(flow, fixed, read_unknown, i=0):
    """Outcome kinds a flow can reach from step i when every answer read_unknown(question) holds for is unknown (guards on
    such questions raise to at least flag), steps in fixed (by step number) take their fixed answer, other guards let the
    outcome stand, and every other step may take any answer. A flow that ends without an outcome flags."""
    if i >= len(flow):
        return {"flag"}
    st = flow[i]
    if read_unknown(st["question"]):
        answers = ["unknown"]
    elif st["step"] in fixed:
        answers = [fixed[st["step"]]]
    else:
        answers = ["yes", "no", "unknown"]
    outs = set()
    for a in answers:
        out = st["on_" + a]
        if out == "next":
            outs |= walk_outcomes(flow, fixed, read_unknown, i + 1)
            continue
        results = [(g, "unknown" if read_unknown(g["question"]) else ("no" if "no" not in g.get("when", ["yes"]) else "yes"))
                   for g in st.get("guards") or [] if guard_applies(g, out)]
        outs.add(outcome_kind(raise_outcome(out, results)))
    return outs


def close_paths(flow):
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


def close_edges(flow):
    """Distinct (step, edge) pairs that close, outside Q0."""
    return sorted({(st["step"], e) for st in flow[1:] for e in ("on_yes", "on_no") if st[e].startswith("close")})


# ---------- Auto exclusions ----------
def auto_excluded(d, st=None):
    """The auto_excluded_reason codes of a detection (max_mode recommend) or of one of its close steps (bank/triage/auto_exclusions.yaml)."""
    x = (st if st is not None else d).get("auto_excluded_reason")
    return [] if not x else [x] if isinstance(x, str) else list(x)


def auto_eligible_path(d, path):
    """A close path can close in Auto only if the detection is not capped at Recommend and no step on it is auto-excluded."""
    return d.get("max_mode") != "recommend" and not any(auto_excluded(d, st) for st, _ in path if st["on_" + _].startswith("close"))


# ---------- parameters and step rules ----------
def answer_type(b, qid):
    """A question's answer type, from the contract (bank/contract/questions.yaml)."""
    return b["contract"]["questions"][qid]["answer"]["type"]


def param_value(b, name, detection=None, customer=None, entity_class=None):
    """Resolve a parameter by precedence: customer + detection > customer > detection > global.
    A parameter with by_entity_class takes the entity's class value (the context rules' entity_class) at the global level."""
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


# ---------- context rules: Q0, the entity guard, human evidence ----------
def severity_rank(b, level):
    """Position of a normalized severity (bank/contract/severity.yaml) on the scale, or None for anything else (raw or unmapped)."""
    scale = (b.get("severity") or {}).get("scale") or []
    return scale.index(level) if level in scale else None


def context_rule(b, rule, answers):
    """Evaluate a Triage-side rule over cached context answers ({<context question>: answer, ...}), in three
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


def rule_reads(rule):
    """The context questions a context rule reads (its condition keys, without a .component suffix)."""
    if isinstance(rule, dict):
        out = set()
        for k, v in rule.items():
            if k in ("any", "all"):
                for r in v:
                    out |= rule_reads(r)
            else:
                out.add(k.partition(".")[0])
        return out
    return set()


def guard_only(b, cid):
    """A context question the contract declares guard_only: only guards may read it, never a flow step or Q0."""
    entry = (b["contract"].get("questions") or {}).get(cid) or (b["contract"].get("designed") or {}).get(cid) or {}
    return bool(entry.get("guard_only"))


def entity_hot(b, answers):
    """The entity guard (bank/triage/context_rules.yaml entity_guard): True (hot), False, or None (unknown: closes flag)."""
    return context_rule(b, b["context_rules"]["entity_guard"]["hot_when"], answers)


def q0(b, answers):
    """Q0 from the context answers (bank/triage/context_rules.yaml q0)."""
    return context_rule(b, b["context_rules"]["q0"]["yes_when"], answers)


def human_evidence(b, closures, analysts_distinct=True):
    """The precedent counts (audited, independent_human) from a list of recorded closes ({kind, analyst, ...}), by the one definition in
    bank/contract/evidence.yaml: audited closes, and independent human closes (the definition's independent_kinds: manual
    closes in Shadow, analyst overrides, an analyst's own close of a flag, an override of a flag's suggestion; by distinct
    analysts). Kinds the definition lists under never (accepted recommendations and flag suggestions, Auto closes,
    precedent matches) are not counted."""
    he = b["evidence"]["human_evidence"]
    counted = [c for c in closures if c["kind"] in he["counts"] and c["kind"] not in he["never"]]
    audited = sum(1 for c in counted if c["kind"] == "audited_close")
    human = [c for c in counted if c["kind"] in (he.get("independent_kinds") or [])]
    return {"audited": audited, "independent_human": len({c.get("analyst") for c in human}) if analysts_distinct else len(human)}


def flag_close_kind(decision, analyst_disposition):
    """How an analyst's close of a flagged alert counts (bank/contract/evidence.yaml flag_closes), from the decision record:
    no suggestion shown -> flag_own_close (counts); the shown suggestion accepted -> flag_accepted_suggestion (never counts);
    another disposition -> flag_override (counts)."""
    if decision.get("outcome") != "flag":
        raise ValueError("only a flagged alert's close is classified this way")
    if not decision.get("suggestion_shown") or not decision.get("suggests"):
        return "flag_own_close"
    return "flag_accepted_suggestion" if analyst_disposition == decision["suggests"] else "flag_override"


# ---------- the message envelope (bank/contract/envelope.yaml) ----------
def _ts(t):
    return datetime.fromisoformat(str(t).replace("Z", "+00:00")).timestamp()


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def await_answer(b, request, events):
    """The answer the Triage agent accepts for one request (contract/envelope.yaml deadline, defer_rule), from the broker's
    replies in time order: (status, accepted answer or None, reason). No answer accepted by the effective deadline is
    source_unavailable. A defer (overload or rate limiting) makes the request wait: its deadline moves to the first defer
    plus defer_max_wait_seconds and never further; it is never answered unknown. Rejected answers (a mismatched request_id
    or run_id, a late answer) are discarded and the request keeps waiting."""
    env = b["contract"]["envelope"]
    deadline, first_defer = _ts(request["deadline"]), None
    max_wait = float(param_value(b, env["defer_rule"]["max_wait_parameter"]))
    for ev in events:
        at = _ts(ev["at"])
        if "defer" in ev:
            if at > deadline:
                break
            if (ev["defer"].get("reason") not in env["defer"]["reasons"]):
                return env["deadline"]["on_miss"], None, f"defer reason {ev['defer'].get('reason')!r} is not overload or rate limiting"
            first_defer = at if first_defer is None else first_defer
            deadline = first_defer + max_wait
            continue
        ok, why = accept_answer({request["request_id"]: dict(request, deadline=_iso(deadline))}, ev["answer"], ev["at"])
        if ok:
            return ev["answer"]["status"], ev["answer"], "accepted"
    if first_defer is not None:
        return env["defer_rule"]["past_max_wait"], None, "deferred past defer_max_wait_seconds"
    return env["deadline"]["on_miss"], None, "no answer by the deadline"


def resolve_request(b, request, events):
    """The status the Triage agent records for one request: (status, reason). See await_answer."""
    status, _, why = await_answer(b, request, events)
    return status, why


# ---------- the alert: references, derived fields, fingerprint ----------
def ref_value(ref, n):
    """Value of a role:, derived: or alert: reference on the normalized alert (None if missing). entity: references are the
    Tool Broker's to resolve; the executor never resolves them."""
    kind, _, name = ref.partition(":")
    if kind in ("role", "derived", "alert"):
        return n.get(name)
    return None


def derive(d, n):
    """Fill the detection's derived fields and the alert's fingerprint on the normalized alert n."""
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


# ---------- asking the broker ----------
def _send(b, ctx, n, qid, item, window=False, inputs=None):
    """Send one request through the envelope to the injected answerer and wait for the answer it accepts.
    Returns (status, answer message or None)."""
    ctx["_seq"] = ctx.get("_seq", 0) + 1
    key = "entity_window_id" if window else "run_id"
    run = ctx.get("run_id") or f"run-{n.get('alert_id', id(n))}"
    owner = f"ew-{ref_value('alert:entity', n)}" if window else run
    step = item.get("step", "g") if item else 0
    sent = ctx["_now"]
    request = {"request_id": f"{owner}:{step}:{qid}:{ctx['_seq']}", key: owner, "question_id": qid, "scope_profile": "triage",
               "deadline": _iso(_ts(sent) + float(param_value(b, "question_timeout_seconds", ctx.get("_detection"), ctx.get("customer")))),
               "sent_at": sent, "alert_id": n.get("alert_id"), "bind": dict((item or {}).get("bind") or {}), "inputs": inputs or {}}
    events = ctx["answerer"].ask(request)
    status, msg, _ = await_answer(b, request, events)
    return status, msg


def _clock(ctx, now):
    """The caller's current time, required: an RFC3339 time (there is no default clock)."""
    _ts(now)   # raises on a missing or malformed time
    ctx["_now"] = now


def context_answers(b, n, ctx, d, now):
    """The context answers for one alert at time now, asked fresh through the envelope (nothing here is cached, so a new
    alert on the entity is always counted: S1), plus what the context rules read about this run (_mode, _severity,
    _detection, _customer, _entity_class). An answer whose status is not answered is None (unknown or source unavailable).
    The entity class comes from the context question the rules name (entity_guard.entity_class), and is asked first so
    that windows and thresholds set per class travel with the other requests."""
    _clock(ctx, now)
    ans = {}
    ec = b["context_rules"]["entity_guard"]["entity_class"]
    cls_answer = _ask_context(b, ctx, n, ec["question"], d, {})
    cls = cls_answer if cls_answer in ec["classes"] else None
    for cid in sorted(b["context_questions"]):
        if cid == ec["question"]:
            ans[cid] = cls_answer
            continue
        inputs = {k: param_value(b, v["param"], d, ctx.get("customer"), cls) if isinstance(v, dict) and "param" in v else v
                  for k, v in (b["context_questions"][cid].get("inputs") or {}).items()}
        ans[cid] = _ask_context(b, ctx, n, cid, d, inputs)
    ans.update(_mode=ctx.get("mode", "recommend"), _severity=ref_value("alert:severity", n), _detection=d, _customer=ctx.get("customer"),
               _entity_class=cls_answer)
    return ans


def _ask_context(b, ctx, n, cid, d, inputs):
    status, msg = _send(b, ctx, n, cid, None, window=True, inputs=inputs)
    return msg["answer"] if status == "answered" else None


def _answer(b, q, item, n, ctx, d):
    """The Triage side of one question: the broker's answer, status and trust, turned into yes / no / unknown by the step's rule.
    Q0 and context-rule questions are answered here from the context answers (no broker call of their own). Records
    (question, yes/no/unknown, trust, provenance) in ctx["answers"]; the triage side reads only the trust and status.
    source_unavailable and sources_disagree answer unknown and are recorded, so no close rests on them (run_flow)."""
    trust, prov = "checked", None
    if q["id"] == b["context_rules"]["q0"]["question"]:
        value = q0(b, context_answers(b, n, ctx, ctx.get("_detection"), ctx["_now"]))
    elif q.get("context_rule"):
        if "step" in item:
            only = sorted(c for c in rule_reads(q["context_rule"]) if guard_only(b, c))
            if only:
                raise ValueError(f"{q['id']} reads guard-only context question(s) {only} but is asked as a flow step; it may only be a guard")
        value = context_rule(b, q["context_rule"], context_answers(b, n, ctx, ctx.get("_detection"), ctx["_now"]))
    else:
        status, msg = _send(b, ctx, n, q["id"], item)
        value = msg["answer"] if status == "answered" else None
        if msg:
            trust, prov = msg.get("trust", "not_checked"), (msg.get("provenance") or {}).get("ref")
        if status in ("source_unavailable", "sources_disagree"):
            ctx.setdefault("_no_close", []).append(f"{q['id']} {status}")
    a = apply_rule(b, item.get("rule"), value, answer_type(b, q["id"]), d)
    if ctx.get("_nc_as_unknown") and trust == "not_checked":
        a = "unknown"   # run A of the stricter-of rule: every not_checked answer read as unknown
    ctx.setdefault("answers", []).append((q["id"], a, trust, prov))
    return a


# ---------- one alert through one flow ----------
def run_flow(b, d, n, ctx, now):
    """One alert through one flow at time now (RFC3339, required) in ctx["mode"] (shadow, recommend or auto; default
    recommend), asking ctx["answerer"]. Returns (outcome, trail) and leaves the decision record in ctx["decision"]:
    outcome, path_id, suggests and blocked_by (on a flag the executor made from a close, or a flag the bank declares
    with a suggestion), suggestion_shown (whether the analyst sees the suggestion: not in Shadow) and proven.
    The Auto rule, in triage terms: a not_checked answer may support a close in Shadow and Recommend (the close is marked
    "not_checked: <question>" in the explanation and decision log), never in Auto (the close becomes a flag). An answer of
    unknown supports nothing. The provenance in brackets is the broker's, shown here for the gate report only.
    Proof status (bank/contract/proof.yaml): in Auto a close on an unproven path becomes a flag; in Shadow and Recommend
    the close stands, marked "unproven path"."""
    ctx["_suggest"] = None
    out, trail = _decide(b, d, n, ctx, now)
    pid = path_id(d, ctx.get("_path") or [])
    proven = None
    if out.startswith("close"):
        proven = path_proven(b, d, pid)
        if not proven and ctx.get("mode") == "auto":
            _suggest(ctx, out, "unproven_path", "no reviewed proof with enough true-positive replay covers this close path")
            out, trail = "flag", trail + [f"unproven path in Auto: {pid} -> flag"]
        elif not proven:
            trail = trail + [f"unproven path: {pid}"]
    sug = ctx["_suggest"] if out == "flag" else None
    ctx["decision"] = {"outcome": out, "path_id": pid, "proven": proven,
                       "suggests": (sug or {}).get("suggests"), "blocked_by": (sug or {}).get("blocked_by"),
                       "suggestion_shown": bool(sug) and ctx.get("mode", "recommend") != "shadow"}
    return out, trail


def _suggest(ctx, close, rule, reason):
    """Record the close a flag would have been, and what blocked it (the first rule that turned the close into a flag)."""
    if close.startswith("close") and not ctx.get("_suggest"):
        ctx["_suggest"] = {"suggests": close, "blocked_by": {"rule": rule, "reason": reason}}


def _decide(b, d, n, ctx, now):
    _clock(ctx, now)
    ctx["answers"], ctx["_closing_step"], ctx["_detection"], ctx["_no_close"], ctx["_path"] = [], None, d, [], []
    out, trail = _run_flow(b, d, n, ctx)
    if out.startswith("close") and ctx["_no_close"]:
        _suggest(ctx, out, "status", f"{', '.join(ctx['_no_close'])}: never supports a close")
        return "flag", trail + [f"{', '.join(ctx['_no_close'])}: never supports a close -> flag"]
    if out.startswith("close"):
        # S1: the entity guard is re-evaluated on fresh context answers immediately before the close is written.
        hot = entity_hot(b, context_answers(b, n, ctx, d, now))
        if hot is not False:
            _suggest(ctx, out, "entity_guard", f"the entity is {'hot' if hot else 'not known to be quiet'} at write time")
            return "flag", trail + [f"entity guard {'hot' if hot else 'unknown'} at write time -> flag"]
    if out.startswith("close"):
        # Auto exclusions (bank/triage/auto_exclusions.yaml): a detection capped at Recommend, or an excluded close step,
        # never closes in Auto; in Shadow and Recommend the close stands, marked.
        step_codes = auto_excluded(d, ctx["_closing_step"] or {})
        excluded = (auto_excluded(d) if d.get("max_mode") == "recommend" else []) + step_codes
        if excluded and ctx.get("mode") == "auto":
            _suggest(ctx, out, "auto_excluded", ", ".join(excluded))
            return "flag", trail + [f"auto_excluded ({', '.join(excluded)}) in Auto -> flag"]
        if step_codes:
            trail = trail + [f"auto_excluded: {', '.join(step_codes)}"]
    nc = sorted({f"{qid} [{prov}]" for qid, a, trust, prov in ctx["answers"] if trust == "not_checked" and a != "unknown"})
    if ctx.get("mode") == "auto" and nc and not ctx.get("_nc_as_unknown"):
        # Auto: the stricter of (B) the trust rule (a close resting on a not_checked answer flags) and (A) the same flow with
        # every not_checked answer read as unknown (round 6, §5.1: the trust rule alone was weaker on 94 paths).
        b_out = "flag" if out.startswith("close") else out
        a_out, a_trail = _run_flow(b, d, n, dict(ctx, _nc_as_unknown=True, answers=[], _path=[], _suggest=None))
        if SEVERITY[outcome_kind(a_out)] > SEVERITY[outcome_kind(b_out)]:
            ctx["_suggest"] = None
            return a_out, trail + [f"not_checked answer in Auto: {', '.join(nc)}; read as unknown the flow gives {a_out} [{' > '.join(a_trail)}], the stricter -> {a_out}"]
        if out.startswith("close"):
            _suggest(ctx, out, "trust_rule", f"not_checked answer in Auto: {', '.join(nc)}")
            return "flag", trail + [f"not_checked answer in Auto: {', '.join(nc)} -> flag"]
        return out, trail
    if out.startswith("close") and nc:
        trail = trail + [f"not_checked: {x}" for x in nc]
    return out, trail


# ---------- path IDs and proof status ----------
def path_id(d, path):
    """The stable ID of a path (bank/contract/proof.yaml path_id): detection ID, detection version, and the step and answer
    sequence. path: [(step, answer)] as enumerate_paths gives it, or [(step number, question, answer)]."""
    parts = []
    for x in path:
        if len(x) == 2:
            st, a = x
            parts.append(f"{st['step']}:{st['question']}={a}")
        else:
            parts.append(f"{x[0]}:{x[1]}={x[2]}")
    return f"{d['id']}@v{d.get('version')}:" + " > ".join(parts)


def proof_record(b, pid):
    """The reviewed proof record that lists this path ID, or None. Drafts never count; a record whose IDs no longer match
    the flow is stale and simply lists no current ID."""
    for rec in b.get("proofs") or []:
        if rec.get("status") == "reviewed" and rec.get("reviewer") and rec.get("reviewed_on") and pid in (rec.get("paths") or []):
            return rec
    return None


def path_proven(b, d, pid):
    """A close path is proven when a reviewed record covers its current ID and the detection's true-positive replay meets
    the bar (bank/contract/proof.yaml proven_when): at least proof_min_tp_events events, none closed on this path, and at
    least one passing regression case aimed at it. b["replay_coverage"] is the replay gate's per-path report."""
    if not proof_record(b, pid):
        return False
    cov = ((b.get("replay_coverage") or {}).get("detections") or {}).get(d["id"]) or {}
    need = float(param_value(b, "proof_min_tp_events", d))
    on_path = (cov.get("paths") or {}).get(pid) or {}
    return cov.get("tp_events", 0) >= need and on_path.get("closes", 0) == 0 and bool((cov.get("aimed") or {}).get(pid))


def _run_flow(b, d, n, ctx):
    trail = []
    for st in d["flow"]:
        q = b["questions"][st["question"]]
        a = _answer(b, q, st, n, ctx, d)
        out = st["on_" + a]
        trail.append(f"{st['question']}={a}")
        ctx.setdefault("_path", []).append((st["step"], st["question"], a))
        if out == "flag":   # a flag the bank declares with the close it would have been (flag_suggests on the step)
            declared = (st.get("flag_suggests") or {}).get("on_" + a)
            if declared:
                _suggest(ctx, declared["suggests"], "bank", declared.get("reason", ""))
        if out != "next":
            results = []
            for gd in st.get("guards") or []:
                if not guard_applies(gd, out) or (gd.get("if_entry_type") and n.get("_matched_entry_type") not in gd["if_entry_type"]):
                    continue
                results.append((gd, _answer(b, b["questions"][gd["question"]], gd, n, ctx, d)))
            raised = raise_outcome(out, results)
            if raised == "flag" and out.startswith("close"):
                _suggest(ctx, out, "guard", "guard " + ", ".join(g["question"] for g, a in results if a == "unknown" or a in g.get("when", ["yes"])))
            if raised != out:
                trail.append("guards " + ",".join(f"{g['question']}={a}" for g, a in results) + f" -> {raised}")
                out = raised
        if out != "next":
            ctx["_closing_step"] = st
            return context_unknown(b, n, out, trail, ctx)
    return "flag", trail


def context_unknown(b, n, out, trail, ctx):
    """A close stands only when every context question the rules list under closes_need_known is answered; if one is
    unknown or its source unavailable, the close becomes a flag with that rule's reason. Missing context never escalates."""
    if out.startswith("close"):
        for need in b["context_rules"].get("closes_need_known") or []:
            if _ask_context(b, ctx, n, need["question"], ctx.get("_detection"), {}) is None:
                _suggest(ctx, out, need["reason"], f"{need['question']} unknown or unavailable")
                return "flag", trail + [f"{need['reason']} {need['question']} -> flag"]
    return out, trail


# ---------- several alerts on one entity ----------
def _minutes(t):
    try:
        return _ts(t) / 60
    except (TypeError, ValueError):
        return 0.0


def reopen_on_hot(b, results, n, ctx, d, now):
    """S1, S2: after alert n (the last of results, [[alert, outcome, trail], ...] in arrival order) is triaged, if the entity
    is hot, the closes already written on it reopen as flags with reason entity_hot: inside the grouping window for the
    window rule (or an open escalation), inside the look-back for the 24h rule. Raise-only."""
    eg = b["context_rules"]["entity_guard"]["hot_when"]["any"]
    ans = context_answers(b, n, ctx, d, now)
    window_hot = context_rule(b, {"any": eg[:2]}, ans) is not False
    day_hot = context_rule(b, eg[2], ans) is not False
    span = float(param_value(b, "triage_lookback_hours")) * 60 if day_hot else float(param_value(b, "entity_grouping_window_minutes"))
    if window_hot or day_hot:
        when = ref_value("role:event.time", n)
        for r in results[:-1]:
            if r[1].startswith("close") and ref_value("alert:entity", r[0]) == ref_value("alert:entity", n) and \
                    _minutes(when) - _minutes(ref_value("role:event.time", r[0])) <= span:
                r[1], r[2] = "flag", r[2] + [f"reopened: entity hot at {when} (reason entity_hot)"]
    return results
