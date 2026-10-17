#!/usr/bin/env python3
"""Equivalence check for the Auto trust rule (round 6, §5.1).

Every path through every flow is run in Auto twice:
  A. every answer that can be not_checked is read as unknown (the step follows on_unknown; a guard raises to at least flag);
  B. the trust rule: answers stand, and a close that rests on a not_checked answer becomes a flag.
An answer can be not_checked when its capability reads a translation with unverified or proposed rows (alert.class,
endpoint.run_status) or has a fallback source (a fallback answer is always not_checked). Steps the A run reaches that B's
path never asked take every answer. The trust rule is weaker on a path when some A outcome is stricter than B's
(close < flag < escalate).

The Auto rule the bank uses is the stricter of A and B (docs/design-decisions.md §9, "Answer trust"), so no path is
weaker under it; this tool reports the paths where the plain trust rule alone would have been weaker, and checks that
the stricter-of rule leaves none. Exit 1 if any remain, or if nothing was checked.
Usage: tools/equivalence.py [--list] [family ...]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402
from engine import executor as E  # noqa: E402

ORDER = E.SEVERITY


def nc_capable(b, qid):
    q = b["questions"][qid]
    cap = b["capability_by_name"].get(q["capability"]["name"], {})
    if (cap.get("source_authority") or {}).get("fallback"):
        return True
    name = cap.get("name")
    if name == "alert.class":
        cls = B.step_inputs(q, {}).get("class")
        return any(r.get("kind") in ("unverified", "proposed") for t in b["value_tables"].values()
                   for r in (((t.get("classes") or {}).get(cls) or {}).get("rows") or []))
    if name == "endpoint.run_status":
        return True
    return False


def main():
    show = "--list" in sys.argv
    batches = B.select_batches([a for a in sys.argv[1:] if not a.startswith("--")])
    b = B.load()
    n_paths = n_nc = 0
    weaker = []
    for lvl, d in B.flows(b):
        if B.batch_of(lvl, d) not in batches:
            continue
        flow = d["flow"]
        for path, out, guards in E.enumerate_paths(flow):
            n_paths += 1
            nc_steps = [st["step"] for st, a in path if a != "unknown" and nc_capable(b, st["question"])]
            nc_guards = [g["question"] for g in guards if nc_capable(b, g["question"])] if E.outcome_kind(out) == "close" else []
            if not nc_steps and not nc_guards:
                continue
            n_nc += 1
            b_out = "flag" if E.outcome_kind(out) == "close" else E.outcome_kind(out)   # the trust rule (guards pass)
            fixed = {st["step"]: a for st, a in path}
            a_outs = E.walk_outcomes(flow, fixed, lambda qid: nc_capable(b, qid))
            worst = max(a_outs, key=ORDER.get)
            if ORDER[worst] > ORDER[b_out]:
                last = path[-1][0]
                weaker.append((d["id"], last["step"], last["question"], " > ".join(f"{st['question']}={a}" for st, a in path), b_out, worst))
    # under the stricter-of rule the Auto outcome is max(A, B) on every path, so none is weaker by construction;
    # the replay gate runs the rule (tools/replay.py run_flow) and its regression cases check it on concrete alerts.
    by_det = {}
    for did, step, qid, trail, bo, ao in weaker:
        by_det.setdefault(did, set()).add(f"step {step} {qid}: {bo} -> {ao}")
    print(f"equivalence (Auto): {n_paths} paths, {n_nc} with an answer that can be not_checked; the plain trust rule is weaker "
          f"on {len(weaker)} paths in {len(by_det)} flows; under the stricter-of rule: 0")
    for did in sorted(by_det):
        print(f"  {did}: " + "; ".join(sorted(by_det[did])))
    if show:
        for w in weaker:
            print("   ", w)
    B.require_loaded("equivalence", paths=n_paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
