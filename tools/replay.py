#!/usr/bin/env python3
"""Replay gate: run flows on true-positive events against a clean-room customer.

For each rule-level detection that tests/replay/coverage.yaml marks replayable, this fetches the datasets of its
security_content tests (pinned in tests/replay/sources.lock), normalises the events, keeps the events the source rule
would fire on (tests/replay/fires_on/<D-ID>.yaml) and runs the flow through the executor (engine/executor.py) with the
clean-room Tool Broker (tests/replay/clean_room.py): empty lists, no baselines, no change windows, no precedents, no
reputation hits. Telemetry in the dataset itself (alert fields, connection outcomes) is used as-is.

A close with disposition false_positive, benign_true_positive or inherit on a true-positive event FAILS. A close as
mitigated_true_positive (the control stopped it) is reported separately; with --strict it fails too. Guards run as the
bank defines them; alert.history counts the earlier true-positive events of the same detection in the replay (the
alerts that would already have fired). Vulnerability lookups report why they answered unknown: no_cve_mapping when the
signature names no CVE, otherwise no_data (the clean room holds no vulnerability data).

Coverage never drops silently: a failed download fails the gate, a replayable detection that replays zero true-positive
events fails it, and a detection that is not replayable must be capped at Recommend (no_tp_replay_data).
Then the regression cases (tests/cases/<D-ID>/*.yaml) and alert sequences (tests/cases/sequences/*.yaml) run.
Usage: tools/replay.py [--strict] [family ...]   families as in tools/gates.sh; none means all; fails if it replays 0 detections or 0 events
"""
import copy
import glob
import os
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import bank as B  # noqa: E402
from engine import executor as E  # noqa: E402
from tests.replay import datasets as DS, fires_on as FO  # noqa: E402
from tests.replay.clean_room import CleanRoom  # noqa: E402

import yaml  # noqa: E402

TODAY = "2026-10-17"
NOW = "2026-10-17T00:00:00Z"   # the executor's clock for every replayed run (fixed, so replays are reproducible)
COVERAGE = os.path.join(ROOT, "tests", "replay", "coverage.yaml")
CASES = os.path.join(ROOT, "tests", "cases")


def coverage_yaml():
    return (yaml.safe_load(open(COVERAGE)) or {}).get("detections") or {}


def synthetic_customer(b, tables):
    """A customer that verified every non-ambiguous row of these tables (cited doc, 20-alert spot check, version, expiry)."""
    recs = [{"table": t, "row": r["id"], "vendor_doc": (b["value_tables"][t].get("references") or ["doc"])[0], "spot_check_alerts": 20,
             "checked_by": "product operator", "checked_on": TODAY, "product_version": "1.0", "expires": "2027-10-17"}
            for t in tables for spec in b["value_tables"][t]["classes"].values() for r in spec.get("rows") or [] if r.get("kind") != "ambiguous"]
    return {"customer": "regression", "products": {t: "1.0" for t in tables}, "verifications": recs, "modes": {}}


def load_cases(kind):
    paths = glob.glob(os.path.join(CASES, "sequences" if kind == "sequences" else "D-*", "*.yaml"))
    return sorted((yaml.safe_load(open(p)) for p in paths), key=lambda c: c["order"])


def case_broker(b, case, alerts, context, timeline=None):
    """The clean-room broker for one case, with the case's context as given."""
    return CleanRoom(b, alerts=alerts, timeline=timeline, conns=[], context=dict(context or {}),
                     coverage=case.get("coverage") or [], overrides=case.get("overrides") or {}, closures=case.get("closures") or [],
                     not_checked=case.get("not_checked") or [], customer="regression" if case.get("verified") else None,
                     today=TODAY, vuln_unknown=Counter())


def with_customer(b, case):
    if not case.get("verified"):
        return b
    bb = copy.deepcopy(b)
    bb["customers"]["regression"] = synthetic_customer(bb, case["verified"])
    return bb


def run_regression(b, batches, aimed=None):
    """Run the regression cases. A case that names aims_at (path IDs whose yes answers it attacks) and passes is recorded in
    aimed[detection][path ID] for the per-path coverage report."""
    failures, n = [], 0
    for case in load_cases("cases"):
        did = case["detection"]
        if b["detections"][did]["family"] not in batches:
            continue
        n += 1
        bb = with_customer(b, case)
        alert = dict(case["alert"], _idx=0)
        cr = case_broker(bb, case, [], dict({"C-06": False}, **(case.get("context") or {})))   # the clean room: C-06 no, plus the case's own
        a = E.derive(bb["detections"][did], cr.register(alert))
        cr.case["alerts"] = [a]
        ctx = {"answerer": cr, "mode": case.get("mode", "recommend"), "customer": cr.case["customer"]}
        out, trail = E.run_flow(bb, bb["detections"][did], a, ctx, NOW)
        exp = case["expect"]
        marked = any(t.startswith("not_checked:") for t in trail)
        dec = ctx.get("decision") or {}
        if "not" in exp:
            ok = not out.startswith(exp["not"])
        else:
            want = exp["outcome"]
            ok = (out == want or (want.startswith("close:") and out.startswith(want)) or (not want.startswith("close:") and out.split(":")[0] == want)) \
                and marked == bool(exp.get("marked_not_checked"))
        if "suggests" in exp:
            ok = ok and str(dec.get("suggests") or "").startswith(exp["suggests"])
        if "blocked_by" in exp:
            ok = ok and (dec.get("blocked_by") or {}).get("rule") == exp["blocked_by"]
        print(f"  {'ok  ' if ok else 'FAIL'} {did}: {case['name']} -> {out}  [{' > '.join(trail)}]")
        if not ok:
            failures.append(case["name"])
        elif aimed is not None:
            for pid in case.get("aims_at") or []:
                aimed.setdefault(did, {}).setdefault(pid, []).append(case["name"])
    return failures, n


def run_sequences(b, batches):
    """Alert sequences on one entity (S1, S2): each alert is triaged when it arrives; the entity guard runs on a fresh C-02
    before each close is written, and when the entity turns hot the closes already written on it reopen as flags."""
    failures, n = [], 0
    for case in load_cases("sequences"):
        if any(b["detections"][x["detection"]]["family"] not in batches for x in case["alerts"]):
            continue
        n += 1
        timeline, results = [], []
        for i, x in enumerate(case["alerts"]):
            d = b["detections"][x["detection"]]
            cr = case_broker(b, x, timeline, case.get("context"), timeline=None)
            a = E.derive(d, cr.register(dict(x["alert"], _idx=i, _detection=x["detection"])))
            timeline.append(a)
            for earlier in timeline[:-1]:
                cr.register(earlier)
            cr.case.update(alerts=timeline, timeline=list(timeline))
            ctx = {"answerer": cr, "mode": x.get("mode", "recommend"), "customer": None}
            out, trail = E.run_flow(b, d, a, ctx, NOW)
            results.append([a, out, trail])
            E.reopen_on_hot(b, results, a, ctx, d, NOW)
        want = case["expect"]["every_alert"]
        ok = all(out == want or out.startswith(want + ":") or (want == "close" and out.startswith("close")) for _, out, _ in results)
        print(f"  {'ok  ' if ok else 'FAIL'} sequence {case['name']}")
        for a, out, trail in results:
            print(f"         {a['_detection']} {a['event.time']}: {out}  [{' > '.join(trail)}]")
        if not ok:
            failures.append(case["name"])
    return failures, n


def main():
    strict = "--strict" in sys.argv
    batches = B.select_batches([a for a in sys.argv[1:] if not a.startswith("--")])
    b = B.load()
    # Inside the replay gate nothing counts as proven (raise-only and reproducible): the per-path coverage it measures is
    # written to build/replay_coverage.json, which the validator and the runtime read with the proof records.
    b["replay_coverage"] = {}
    coverage_out = {}
    coverage = coverage_out
    cov, rules = coverage_yaml(), FO.load()
    lookups = os.path.join(DS.ESCU, "lookups", "csv")
    vuln_unknown = Counter()
    rows, cannot, fails, mitigated, gate_errors = [], [], [], [], []
    pin = DS.check_pins()
    if pin:
        sys.exit(f"FAIL replay: {pin}")
    for did, d in sorted(b["detections"].items()):
        if B.batch_of("rule", d) not in batches:
            continue
        c = cov.get(did)
        if not c:
            gate_errors.append(f"{did}: not in tests/replay/coverage.yaml")
            continue
        if not c.get("replayable"):
            cannot.append((did, c.get("reason") or "no reason given"))
            continue
        tests = []
        for r in c.get("tests_from") or []:
            y = B._load(os.path.join(DS.ESCU, r))
            for t in y.get("tests") or []:
                tests += t.get("attack_data", [])
        evs = []
        for t in tests:
            try:
                path = DS.fetch(t["data"])
            except DS.FetchError as e:
                gate_errors.append(f"{did}: download failed: {e}")
                continue
            evs += [x for x in (DS.normalise(e, t.get("sourcetype", "")) for e in DS.events(path, t.get("sourcetype", ""))) if x]
        fires = FO.predicate(rules[did], lookups) if did in rules else None
        if fires is None:
            gate_errors.append(f"{did}: replayable but has no tests/replay/fires_on rule")
            continue
        conns = [DS.to_roles(x) for x in evs if x.get("_kind") == "conn"]
        tp = [E.derive(d, DS.to_roles(x)) for x in evs if fires(x)]
        for i, x in enumerate(tp):
            x["_idx"] = i
        if not tp:
            gate_errors.append(f"{did}: replayable, but no event in its {len(tests)} datasets fires the source rule (0 true-positive events)")
            continue
        cr = CleanRoom(b, alerts=tp, timeline=None, conns=conns, context={"C-06": False}, customer=None, today=TODAY, vuln_unknown=vuln_unknown)
        for x in tp:
            cr.register(x)
        outcomes = Counter()
        paths = {}
        for n in tp:
            rctx = {"answerer": cr, "mode": "recommend", "customer": None}
            out, trail = E.run_flow(b, d, n, rctx, NOW)
            pc = paths.setdefault(rctx["decision"]["path_id"], {"events": 0, "closes": 0})
            pc["events"] += 1
            pc["closes"] += out.startswith("close")
            key = out.split(":")[0] if not out.startswith("close") else out
            outcomes[key] += 1
            if out.startswith("close:mitigated_true_positive"):
                mitigated.append((did, out, trail))
            elif out.startswith("close"):
                fails.append((did, out, trail))
        rows.append((did, len(tests), len(tp), outcomes))
        coverage[did] = {"tp_events": len(tp), "paths": paths}
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
    if vuln_unknown:
        print("\nVulnerability step answered unknown (never closes): " + ", ".join(f"{k} {v}" for k, v in sorted(vuln_unknown.items())))
    print("\nRegression cases:")
    aimed = {}
    reg_fail, n_cases = run_regression(b, batches, aimed)
    print("\nAlert sequences on one entity:")
    seq_fail, n_seq = run_sequences(b, batches)
    reg_fail += seq_fail
    n_reg = n_cases + n_seq
    # A detection without true-positive replay data must be capped at Recommend (no_tp_replay_data); a family run that
    # replays zero events passes only if every detection in it is so capped (round 6, §5.2).
    uncapped = [did for did, _ in cannot if "no_tp_replay_data" not in E.auto_excluded(b["detections"][did])]
    for did in uncapped:
        print(f"FAIL {did}: no true-positive replay data, but not capped at Recommend with auto_excluded_reason no_tp_replay_data")
    for msg in gate_errors:
        print(f"FAIL {msg}")
    if rows or uncapped or not cannot:
        B.require_loaded(f"replay ({', '.join(sorted(batches))})", detections=len(rows), events=sum(r[2] for r in rows))
    else:
        print(f"replay: 0 events, every one of the {len(cannot)} detections without replay data is capped at Recommend")
    bad = fails or reg_fail or (strict and mitigated) or uncapped or gate_errors
    # per-path replay coverage (bank/contract/proof.yaml proven_when): TP events and closes per path, and the passing cases aimed at each path
    for did, a in aimed.items():
        coverage_out.setdefault(did, {"tp_events": 0, "paths": {}})["aimed"] = a
    print("\nPer-path replay coverage (for proof status; written to build/replay_coverage.json):")
    need = E.param_value(b, "proof_min_tp_events")
    for did, c in sorted(coverage_out.items()):
        closes = sum(p["closes"] for p in c["paths"].values())
        print(f"  {did}: {c['tp_events']} TP events over {len(c['paths'])} paths, {closes} closes, "
              f"{sum(len(v) for v in (c.get('aimed') or {}).values())} aimed cases; "
              f"{'meets' if c['tp_events'] >= need else 'below'} the {need}-event bar")
    os.makedirs(os.path.dirname(B.COVERAGE_REPORT), exist_ok=True)
    with open(B.COVERAGE_REPORT, "w") as fh:
        import json
        json.dump({"detections": coverage_out, "proof_min_tp_events": need}, fh, indent=1, sort_keys=True)
    print(f"\nreplay: {sum(r[2] for r in rows)} TP events in {len(rows)} detections, {n_reg - len(reg_fail)}/{n_reg} regression cases; "
          f"{len(fails)} benign/FP closes, {len(mitigated)} mitigated closes"
          f" -> {'FAIL' if bad else 'PASS'}{' (strict)' if strict else ''}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
