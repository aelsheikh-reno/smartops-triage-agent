"""Executor tests on synthetic flows: no real detection, question or broker. Run: python3 -m unittest discover tests/engine"""
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from engine import executor as E  # noqa: E402

T0 = "2026-10-17T00:00:00Z"


def bank(flow, extra_questions=(), **detection):
    """A minimal bank: one synthetic detection, bool questions X-1..X-9, the contract, parameters and context rules."""
    qids = sorted({st["question"] for st in flow} | {g["question"] for st in flow for g in st.get("guards") or []} | set(extra_questions))
    b = {
        "questions": {q: {"id": q} for q in qids + ["P0"]},
        "context_questions": {c: {"id": c, "inputs": {}} for c in ("C-01", "C-02", "C-04", "C-06", "C-08")},
        "contract": {"questions": {q: {"answer": {"type": "bool"}} for q in qids + ["P0"]},
                     "envelope": {"deadline": {"on_miss": "source_unavailable"},
                                  "defer": {"reasons": ["overload", "rate_limited"]},
                                  "defer_rule": {"max_wait_parameter": "defer_max_wait_seconds", "past_max_wait": "source_unavailable"}}},
        "parameters": {"question_timeout_seconds": {"default": 10}, "defer_max_wait_seconds": {"default": 300},
                       "entity_grouping_window_minutes": {"default": 10}, "triage_lookback_hours": {"default": 24},
                       "min_alerts": {"default": 3}, "proof_min_tp_events": {"default": 5}},
        "overlays": {},
        "context_rules": {"q0": {"question": "P0", "yes_when": {"all": [{"C-04.audited": {"gte": 1}}, {"C-06": False}]}},
                          "closes_need_known": [{"question": "C-06", "reason": "context_unknown"}],
                          "entity_guard": {"entity_class": {"question": "C-08", "classes": ["server", "workstation"]}, "hot_when": {"any": [{"C-01": True}, {"C-02.alerts": {"gte": {"param": "min_alerts"}}}, {"C-02.day": {"gte": 99}}]}}},
        "evidence": {"human_evidence": {"counts": {"manual_shadow_close": "", "analyst_override": "", "audited_close": "", "flag_own_close": "", "flag_override": ""},
                                        "never": {"accepted_recommendation": "", "auto_close": "", "precedent_match": "", "flag_accepted_suggestion": ""},
                                        "independent_kinds": ["manual_shadow_close", "analyst_override", "flag_own_close", "flag_override"]}},
        "severity": {"scale": ["informational", "low", "medium", "high", "critical"]},
    }
    d = dict({"id": "SYN-1", "fingerprint": ["role:host.name"], "flow": [dict(st, step=i + 1) for i, st in enumerate(flow)]}, **detection)
    return b, d


def step(q, yes, no="next", unknown="next", **kw):
    return dict({"question": q, "on_yes": yes, "on_no": no, "on_unknown": unknown}, **kw)


class Scripted:
    """An answerer that replies from a script: {question: value | (value, trust) | callable(request) -> events}."""

    def __init__(self, script, context=None):
        self.script, self.context, self.requests = script, dict({"C-01": False, "C-02": {"alerts": 1, "day": 0}, "C-04": {"audited": 0}, "C-06": False}, **(context or {})), []

    def ask(self, request):
        self.requests.append(request)
        qid = request["question_id"]
        spec = self.context.get(qid) if qid.startswith("C-") else self.script.get(qid)
        if callable(spec):
            return spec(request)
        value, trust = spec if isinstance(spec, tuple) else (spec, "checked")
        return [{"at": request["sent_at"], "answer": reply(request, value, trust=trust)}]


def reply(request, value, status=None, trust="checked", **override):
    msg = {"request_id": request["request_id"], "measurement_id": "m-1", "answer": "unknown" if value is None else value,
           "status": status or ("unknown" if value is None else "answered"), "trust": trust, "provenance": {"source": "test", "ref": "t/1"}}
    for k in ("run_id", "entity_window_id"):
        if k in request:
            msg[k] = request[k]
    msg.update(override)
    return msg


def run(flow, script, mode="recommend", context=None, proofs=None, coverage=None, ctx_out=None, **detection):
    b, d = bank(flow, **detection)
    b["proofs"], b["replay_coverage"] = proofs or [], coverage or {}
    n = E.derive(d, {"alert_id": "a-1", "entity": "h-1", "host.name": "h-1", "event.time": T0})
    ctx = {"answerer": Scripted(dict({"P0": False}, **script), context), "mode": mode, "customer": None}
    out = E.run_flow(b, d, n, ctx, T0)
    if ctx_out is not None:
        ctx_out.update(ctx["decision"])
    return out


CLOSE_PATH = "SYN-1@vNone:1:P0=no > 2:X-1=yes"   # the synthetic detection has no version


def proof(status="reviewed", paths=(CLOSE_PATH,), **kw):
    return dict({"id": "PR-1", "paths": list(paths), "aimed_cases": ["x-1-attack"], "status": status, "reviewer": "soc lead",
                 "reviewed_on": "2026-10-17"}, **kw)


COVERED = {"detections": {"SYN-1": {"tp_events": 5, "paths": {}, "aimed": {"x-1-attack": "pass"}}}}


def run_proven(flow, script, **kw):
    return run(flow, script, proofs=[proof()], coverage=COVERED, **kw)


Q0 = step("P0", "close:inherit:precedent_match")


class Routing(unittest.TestCase):
    def test_yes_no_unknown_edges(self):
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "escalate", "flag")]
        self.assertEqual(run(flow, {"X-1": True})[0], "close:benign_true_positive:a")
        self.assertEqual(run(flow, {"X-1": False})[0], "escalate")
        self.assertEqual(run(flow, {"X-1": None})[0], "flag")

    def test_next_then_terminal(self):
        flow = [Q0, step("X-1", "next", "escalate"), step("X-2", "close:benign_true_positive:a", "flag", "flag")]
        out, trail = run(flow, {"X-1": True, "X-2": True})
        self.assertEqual(out, "close:benign_true_positive:a")
        self.assertEqual(trail[:3], ["P0=no", "X-1=yes", "X-2=yes"])

    def test_flow_ending_without_outcome_flags(self):
        flow = [Q0, step("X-1", "next", "next", "next")]
        self.assertEqual(run(flow, {"X-1": True})[0], "flag")

    def test_q0_from_context(self):
        flow = [Q0, step("X-1", "escalate", "escalate", "escalate")]
        b, d = bank(flow)
        n = E.derive(d, {"alert_id": "a-1", "entity": "h-1", "event.time": T0})
        audited = {"C-04": {"audited": 1}}
        self.assertEqual(E.run_flow(b, d, n, {"answerer": Scripted({}, audited), "mode": "recommend"}, T0)[0], "close:inherit:precedent_match")
        self.assertEqual(E.run_flow(b, d, n, {"answerer": Scripted({}, dict(audited, **{"C-06": True})), "mode": "recommend"}, T0)[0], "escalate")
        self.assertEqual(E.run_flow(b, d, n, {"answerer": Scripted({}), "mode": "recommend"}, T0)[0], "escalate")


class Guards(unittest.TestCase):
    def flow(self, *guards):
        return [Q0, step("X-1", "close:benign_true_positive:a", "flag", "flag", guards=list(guards))]

    def test_guard_only_raises(self):
        flow = self.flow({"question": "X-2", "then": "flag"})
        self.assertEqual(run(flow, {"X-1": True, "X-2": True})[0], "flag")
        self.assertEqual(run(flow, {"X-1": True, "X-2": False})[0], "close:benign_true_positive:a")
        self.assertEqual(E.raise_outcome("escalate", [({"then": "flag"}, "yes")]), "escalate")
        self.assertEqual(E.raise_outcome("flag", [({"then": "flag", "applies_to": ["flag"]}, "unknown")]), "flag")

    def test_unknown_guard_flags(self):
        self.assertEqual(run(self.flow({"question": "X-2", "then": "escalate"}), {"X-1": True, "X-2": None})[0], "flag")

    def test_strongest_guard_wins(self):
        flow = self.flow({"question": "X-2", "then": "escalate"}, {"question": "X-3", "then": "flag"})
        self.assertEqual(run(flow, {"X-1": True, "X-2": True, "X-3": True})[0], "escalate")
        flow = self.flow({"question": "X-3", "then": "flag"}, {"question": "X-2", "then": "escalate"})
        self.assertEqual(run(flow, {"X-1": True, "X-2": True, "X-3": True})[0], "escalate")

    def test_guard_that_needs_a_yes(self):
        flow = self.flow({"question": "X-2", "when": ["no"], "then": "flag"})
        self.assertEqual(run(flow, {"X-1": True, "X-2": False})[0], "flag")
        self.assertEqual(run(flow, {"X-1": True, "X-2": True})[0], "close:benign_true_positive:a")

    def test_guards_never_on_escalate(self):
        flow = [Q0, step("X-1", "escalate", "flag", "flag", guards=[{"question": "X-2", "then": "flag"}])]
        self.assertEqual(run(flow, {"X-1": True, "X-2": True})[0], "escalate")


class Statuses(unittest.TestCase):
    flow = [Q0, step("X-1", "close:benign_true_positive:a", "escalate", "next"), step("X-2", "close:benign_true_positive:b", "flag", "flag")]

    def test_source_unavailable_never_closes(self):
        down = lambda r: [{"at": r["sent_at"], "answer": reply(r, None, status="source_unavailable")}]
        out, trail = run(self.flow, {"X-1": down, "X-2": True})
        self.assertEqual(out, "flag")
        self.assertIn("never supports a close", trail[-1])

    def test_sources_disagree_flags(self):
        split = lambda r: [{"at": r["sent_at"], "answer": reply(r, True, status="sources_disagree")}]
        self.assertEqual(run(self.flow, {"X-1": split, "X-2": True})[0], "flag")

    def test_no_answer_by_the_deadline(self):
        self.assertEqual(run(self.flow, {"X-1": lambda r: [], "X-2": True})[0], "flag")

    def test_defer_waits_then_is_answered(self):
        def later(r):
            return [{"at": r["sent_at"], "defer": {"reason": "rate_limited"}},
                    {"at": E._iso(E._ts(r["sent_at"]) + 200), "answer": reply(r, True)}]
        self.assertEqual(run(self.flow, {"X-1": later})[0], "close:benign_true_positive:a")

    def test_defer_past_the_maximum_wait(self):
        def too_late(r):
            return [{"at": r["sent_at"], "defer": {"reason": "overload"}},
                    {"at": E._iso(E._ts(r["sent_at"]) + 299), "defer": {"reason": "overload"}},
                    {"at": E._iso(E._ts(r["sent_at"]) + 301), "answer": reply(r, True)}]
        b, _ = bank(self.flow)
        req = {"request_id": "r:1:X-1:1", "run_id": "r", "deadline": E._iso(E._ts(T0) + 10), "sent_at": T0}
        self.assertEqual(E.resolve_request(b, req, too_late(req))[0], "source_unavailable")
        self.assertEqual(run(self.flow, {"X-1": too_late, "X-2": True})[0], "flag")


class Trust(unittest.TestCase):
    flow = [Q0, step("X-1", "close:benign_true_positive:a", "escalate", "next"), step("X-2", "flag", "escalate", "escalate")]

    def test_not_checked_closes_in_recommend_marked(self):
        out, trail = run(self.flow, {"X-1": (True, "not_checked")})
        self.assertEqual(out, "close:benign_true_positive:a")
        self.assertTrue(any(t.startswith("not_checked: X-1") for t in trail))

    def test_not_checked_never_closes_in_auto(self):
        out, _ = run(self.flow, {"X-1": (True, "not_checked"), "X-2": True}, mode="auto")
        self.assertEqual(out, "flag")

    def test_auto_takes_the_stricter_of_the_two_readings(self):
        # read as unknown, X-1 goes on to X-2, which escalates on no: stricter than the trust rule's flag
        out, trail = run(self.flow, {"X-1": (True, "not_checked"), "X-2": False}, mode="auto")
        self.assertEqual(out, "escalate")
        self.assertIn("the stricter", trail[-1])

    def test_checked_proven_close_closes_in_auto(self):
        self.assertEqual(run_proven(self.flow, {"X-1": True}, mode="auto")[0], "close:benign_true_positive:a")

    def test_capped_detection_never_closes_in_auto(self):
        out, _ = run(self.flow, {"X-1": True}, mode="auto", max_mode="recommend", auto_excluded_reason="no_tp_replay_data")
        self.assertEqual(out, "flag")


class Proof(unittest.TestCase):
    flow = [Q0, step("X-1", "close:benign_true_positive:a", "escalate", "flag")]

    def test_unproven_close_in_auto_flags_with_suggestion(self):
        dec = {}
        out, trail = run(self.flow, {"X-1": True}, mode="auto", ctx_out=dec)
        self.assertEqual(out, "flag")
        self.assertEqual(dec["suggests"], "close:benign_true_positive:a")
        self.assertEqual(dec["blocked_by"]["rule"], "unproven_path")
        self.assertTrue(dec["suggestion_shown"])
        self.assertEqual(dec["path_id"], CLOSE_PATH)

    def test_unproven_close_in_recommend_stays_marked(self):
        out, trail = run(self.flow, {"X-1": True}, mode="recommend")
        self.assertEqual(out, "close:benign_true_positive:a")
        self.assertIn(f"unproven path: {CLOSE_PATH}", trail)

    def test_proven_close_in_recommend_is_not_marked(self):
        out, trail = run_proven(self.flow, {"X-1": True}, mode="recommend")
        self.assertFalse(any(t.startswith("unproven path") for t in trail))

    def test_stale_proof_is_ignored(self):
        stale = proof(paths=["SYN-1@v1:1:P0=no > 2:X-1=yes"])   # written for an earlier version of the detection
        self.assertEqual(run(self.flow, {"X-1": True}, mode="auto", proofs=[stale], coverage=COVERED)[0], "flag")

    def test_draft_proof_is_ignored(self):
        self.assertEqual(run(self.flow, {"X-1": True}, mode="auto", proofs=[proof(status="draft")], coverage=COVERED)[0], "flag")

    def test_reviewed_proof_without_reviewer_is_ignored(self):
        self.assertEqual(run(self.flow, {"X-1": True}, mode="auto", proofs=[proof(reviewer="")], coverage=COVERED)[0], "flag")

    def test_proof_needs_the_replay_bar(self):
        few = {"detections": {"SYN-1": {"tp_events": 4, "paths": {}, "aimed": {"x-1-attack": "pass"}}}}
        closed = {"detections": {"SYN-1": {"tp_events": 50, "paths": {CLOSE_PATH: {"events": 1, "closes": 1}}, "aimed": {"x-1-attack": "pass"}}}}
        unaimed = {"detections": {"SYN-1": {"tp_events": 50, "paths": {}, "aimed": {}}}}
        aimed_closed = {"detections": {"SYN-1": {"tp_events": 50, "paths": {}, "aimed": {"x-1-attack": "fail"}}}}
        for cov in (few, closed, unaimed, aimed_closed):
            self.assertEqual(run(self.flow, {"X-1": True}, mode="auto", proofs=[proof()], coverage=cov)[0], "flag")

    def test_proof_without_aimed_cases_is_ignored(self):
        self.assertEqual(run(self.flow, {"X-1": True}, mode="auto", proofs=[proof(aimed_cases=[])], coverage=COVERED)[0], "flag")

    def test_flags_made_from_closes_carry_the_suggestion(self):
        dec = {}
        run(self.flow, {"X-1": True}, context={"C-01": True}, ctx_out=dec)
        self.assertEqual((dec["suggests"], dec["blocked_by"]["rule"]), ("close:benign_true_positive:a", "entity_guard"))
        dec = {}
        run(self.flow, {"X-1": True}, context={"C-06": None}, ctx_out=dec)
        self.assertEqual(dec["blocked_by"]["rule"], "context_unknown")
        dec = {}
        run(self.flow, {"X-1": (True, "not_checked")}, mode="auto", ctx_out=dec)
        self.assertEqual(dec["blocked_by"]["rule"], "trust_rule")
        dec = {}
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "flag", "flag", guards=[{"question": "X-2", "then": "flag"}])]
        run(flow, {"X-1": True, "X-2": True}, ctx_out=dec)
        self.assertEqual((dec["suggests"], dec["blocked_by"]["rule"]), ("close:benign_true_positive:a", "guard"))

    def test_bank_declared_flag_suggestion_and_shadow_hides_it(self):
        flow = [Q0, step("X-1", "flag", "escalate", "flag", flag_suggests={"on_yes": {"suggests": "close:benign_true_positive:a", "reason": "actor identity only"}})]
        dec = {}
        self.assertEqual(run(flow, {"X-1": True}, ctx_out=dec)[0], "flag")
        self.assertEqual((dec["suggests"], dec["blocked_by"]["rule"], dec["suggestion_shown"]), ("close:benign_true_positive:a", "bank", True))
        dec = {}
        run(flow, {"X-1": True}, mode="shadow", ctx_out=dec)
        self.assertFalse(dec["suggestion_shown"])

    def test_escalations_carry_no_suggestion(self):
        dec = {}
        run(self.flow, {"X-1": False}, ctx_out=dec)
        self.assertEqual((dec["outcome"], dec["suggests"]), ("escalate", None))


class FlagCloses(unittest.TestCase):
    """#28: how an analyst's close of a flag counts as human evidence."""

    def test_no_suggestion_shown_is_own_judgement_and_counts(self):
        kind = E.flag_close_kind({"outcome": "flag", "suggests": None, "suggestion_shown": False}, "close:benign_true_positive:a")
        b, _ = bank([Q0])
        self.assertEqual(kind, "flag_own_close")
        self.assertEqual(E.human_evidence(b, [{"kind": kind, "analyst": "a"}])["independent_human"], 1)

    def test_accepting_the_shown_suggestion_never_counts(self):
        kind = E.flag_close_kind({"outcome": "flag", "suggests": "close:benign_true_positive:a", "suggestion_shown": True}, "close:benign_true_positive:a")
        b, _ = bank([Q0])
        self.assertEqual(kind, "flag_accepted_suggestion")
        self.assertEqual(E.human_evidence(b, [{"kind": kind, "analyst": "a"}]), {"audited": 0, "independent_human": 0})

    def test_a_different_disposition_is_an_override_and_counts(self):
        kind = E.flag_close_kind({"outcome": "flag", "suggests": "close:benign_true_positive:a", "suggestion_shown": True}, "close:false_positive:b")
        b, _ = bank([Q0])
        self.assertEqual(kind, "flag_override")
        self.assertEqual(E.human_evidence(b, [{"kind": kind, "analyst": "a"}])["independent_human"], 1)

    def test_a_suggestion_hidden_in_shadow_is_own_judgement(self):
        self.assertEqual(E.flag_close_kind({"outcome": "flag", "suggests": "close:x:y", "suggestion_shown": False}, "close:x:y"), "flag_own_close")


class GuardOnly(unittest.TestCase):
    def test_guard_only_question_refused_as_a_step(self):
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "flag", "flag")]
        b, d = bank(flow)
        b["questions"]["X-1"]["context_rule"] = {"C-09": {"in": ["business_hours"]}}
        b["contract"]["designed"] = {"C-09": {"guard_only": True, "answer": {"type": "enum"}}}
        n = E.derive(d, {"alert_id": "a-1", "entity": "h-1", "event.time": T0})
        with self.assertRaises(ValueError):
            E.run_flow(b, d, n, {"answerer": Scripted({}), "mode": "recommend"}, T0)

    def test_guard_only_question_allowed_in_a_guard(self):
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "flag", "flag", guards=[{"question": "X-2", "then": "flag"}])]
        b, d = bank(flow)
        b["questions"]["X-2"]["context_rule"] = {"C-09": {"in": ["after_hours"]}}
        b["contract"]["designed"] = {"C-09": {"guard_only": True, "answer": {"type": "enum"}}}
        b["context_questions"]["C-09"] = {"id": "C-09", "inputs": {}}
        n = E.derive(d, {"alert_id": "a-1", "entity": "h-1", "event.time": T0})
        out, trail = E.run_flow(b, d, n, {"answerer": Scripted({"X-1": True}, {"C-09": "after_hours"}), "mode": "recommend"}, T0)
        self.assertEqual(out, "flag")


class Entity(unittest.TestCase):
    def test_guard_re_evaluated_before_the_close_is_written(self):
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "flag", "flag")]
        self.assertEqual(run(flow, {"X-1": True}, context={"C-02": {"alerts": 3, "day": 0}})[0], "flag")
        self.assertEqual(run(flow, {"X-1": True}, context={"C-01": True})[0], "flag")
        self.assertEqual(run(flow, {"X-1": True}, context={"C-02": None})[0], "flag")

    def test_missing_crown_jewel_answer_flags(self):
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "flag", "flag")]
        out, trail = run(flow, {"X-1": True}, context={"C-06": None})
        self.assertEqual(out, "flag")

    def test_human_evidence(self):
        b, _ = bank([Q0])
        closes = [{"kind": "accepted_recommendation", "analyst": "a"}, {"kind": "auto_close"}, {"kind": "manual_shadow_close", "analyst": "a"},
                  {"kind": "analyst_override", "analyst": "a"}, {"kind": "analyst_override", "analyst": "b"}, {"kind": "audited_close", "analyst": "c"}]
        self.assertEqual(E.human_evidence(b, closes), {"audited": 1, "independent_human": 2})


class Envelope(unittest.TestCase):
    def setUp(self):
        self.req = {"request_id": "r:1:X-1:1", "run_id": "r", "question_id": "X-1", "scope_profile": "triage", "deadline": E._iso(E._ts(T0) + 10)}
        self.pending = {self.req["request_id"]: self.req}

    def test_mismatched_request_id_rejected(self):
        ok, why = E.accept_answer(self.pending, reply(self.req, True, request_id="r:1:X-1:2"), T0)
        self.assertEqual((ok, why), (False, "no pending request"))

    def test_mismatched_run_id_rejected(self):
        ok, why = E.accept_answer(self.pending, reply(self.req, True, run_id="other"), T0)
        self.assertEqual((ok, why), (False, "run_id does not match the pending request"))

    def test_late_answer_discarded(self):
        ok, why = E.accept_answer(self.pending, reply(self.req, True), E._iso(E._ts(T0) + 11))
        self.assertEqual((ok, why), (False, "late"))

    def test_rejected_answers_never_applied_in_a_flow(self):
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "escalate", "flag")]
        wrong = lambda r: [{"at": r["sent_at"], "answer": reply(r, True, run_id="other")}]
        late = lambda r: [{"at": E._iso(E._ts(r["sent_at"]) + 60), "answer": reply(r, True)}]
        self.assertEqual(run(flow, {"X-1": wrong})[0], "flag")
        self.assertEqual(run(flow, {"X-1": late})[0], "flag")

    def test_requests_carry_the_envelope(self):
        flow = [Q0, step("X-1", "flag", "flag", "flag")]
        b, d = bank(flow)
        n = E.derive(d, {"alert_id": "a-1", "entity": "h-1", "event.time": T0})
        sc = Scripted({"X-1": True})
        E.run_flow(b, d, n, {"answerer": sc, "mode": "recommend"}, T0)
        for r in sc.requests:
            self.assertFalse(E.envelope_missing(r, "request"), r)
        self.assertTrue(all(("run_id" in r) != ("entity_window_id" in r) for r in sc.requests))
        self.assertTrue(any("entity_window_id" in r for r in sc.requests) and any("run_id" in r for r in sc.requests))


class Clock(unittest.TestCase):
    def setUp(self):
        self.b, self.d = bank([Q0, step("X-1", "flag", "flag", "flag")])
        self.n = E.derive(self.d, {"alert_id": "a-1", "entity": "h-1", "event.time": T0})

    def test_a_call_without_a_clock_fails(self):
        with self.assertRaises(TypeError):
            E.run_flow(self.b, self.d, self.n, {"answerer": Scripted({"X-1": True}), "mode": "recommend"})
        with self.assertRaises(TypeError):
            E.context_answers(self.b, self.n, {"answerer": Scripted({})}, self.d)
        with self.assertRaises(TypeError):
            E.reopen_on_hot(self.b, [[self.n, "flag", []]], self.n, {"answerer": Scripted({})}, self.d)

    def test_a_missing_or_malformed_clock_fails(self):
        for bad in (None, "", "yesterday"):
            with self.assertRaises((TypeError, ValueError)):
                E.run_flow(self.b, self.d, self.n, {"answerer": Scripted({"X-1": True}), "mode": "recommend"}, bad)

    def test_requests_are_sent_at_the_given_time(self):
        sc = Scripted({"X-1": True})
        E.run_flow(self.b, self.d, self.n, {"answerer": sc, "mode": "recommend"}, "2026-10-18T09:30:00Z")
        self.assertTrue(sc.requests and all(r["sent_at"] == "2026-10-18T09:30:00Z" for r in sc.requests))
        self.assertTrue(all(r["deadline"] == "2026-10-18T09:30:10Z" for r in sc.requests))


class ContextRulesFromTheBank(unittest.TestCase):
    def test_close_needs_the_answers_the_rules_list(self):
        flow = [Q0, step("X-1", "close:benign_true_positive:a", "flag", "flag")]
        b, d = bank(flow)
        b["context_rules"]["closes_need_known"] = [{"question": "C-01", "reason": "context_unknown"}]
        n = E.derive(d, {"alert_id": "a-1", "entity": "h-1", "event.time": T0})
        sc = Scripted({"P0": False, "X-1": True}, {"C-06": None})
        self.assertEqual(E.run_flow(b, d, n, {"answerer": sc, "mode": "recommend"}, T0)[0], "close:benign_true_positive:a")
        sc = Scripted({"P0": False, "X-1": True}, {"C-01": None})
        out, trail = E.run_flow(b, d, n, {"answerer": sc, "mode": "recommend"}, T0)
        self.assertEqual((out, trail[-1]), ("flag", "context_unknown C-01 -> flag"))

    def test_entity_class_question_and_classes_come_from_the_rules(self):
        b, d = bank([Q0])
        b["parameters"]["min_alerts"]["by_entity_class"] = {"server": 9}
        n = E.derive(d, {"alert_id": "a-1", "entity": "h-1", "event.time": T0})
        ans = E.context_answers(b, n, {"answerer": Scripted({}, {"C-08": "server"})}, d, T0)
        self.assertEqual(ans["_entity_class"], "server")
        b["context_rules"]["entity_guard"]["entity_class"] = {"question": "C-01", "classes": ["server"]}
        ans = E.context_answers(b, n, {"answerer": Scripted({}, {"C-01": "server", "C-08": "laptop"})}, d, T0)
        self.assertEqual(ans["_entity_class"], "server")


class StaticWalks(unittest.TestCase):
    def test_enumerate_paths_and_walk_outcomes(self):
        flow = [dict(Q0, step=1), dict(step("X-1", "close:benign_true_positive:a", "next", "flag"), step=2),
                dict(step("X-2", "flag", "escalate", "flag"), step=3)]
        outs = sorted(o for _, o, _ in E.enumerate_paths(flow))
        self.assertEqual(outs, sorted(["close:inherit:precedent_match", "close:benign_true_positive:a", "flag", "flag", "escalate", "flag",
                                       "close:benign_true_positive:a", "flag", "flag", "escalate", "flag"]))
        self.assertEqual(E.walk_outcomes(flow, {1: "no", 2: "yes"}, lambda q: q == "X-1"), {"flag"})


if __name__ == "__main__":
    unittest.main()
