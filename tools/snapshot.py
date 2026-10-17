#!/usr/bin/env python3
"""Machine-readable snapshot of what the gates decide, for comparing a refactor with its baseline.

Writes JSON with: every path of every flow (path ID) and its outcome in Shadow, Recommend, Auto (answers that can be
not_checked are not_checked) and Auto with every answer checked; per-detection true-positive counts and outcome counts and
every regression and sequence line (from a replay report); the self-test count, the equivalence-check result and the
validate and close-path summaries (from a gates report). Paths run through the executor with a scripted answer per step
(guards let the outcome stand). Usage: tools/snapshot.py <replay.txt> <gates.txt> <out.json>
"""
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402
from engine import executor as E  # noqa: E402
import equivalence as EQ  # noqa: E402
from tests.replay.clean_room import CleanRoom  # noqa: E402

NOW = "2026-10-17T00:00:00Z"   # the executor's clock (required): the same fixed time the replay gate uses
MODES = {"shadow": ("shadow", True), "recommend": ("recommend", True), "auto": ("auto", True), "auto_checked": ("auto", False)}


def guard_pass(g):
    return "yes" if "no" in g.get("when", ["yes"]) else "no"


def scripted(fixed, nc_on):
    def answer(b_, q, item, n, ctx, d):
        a = fixed.get(item["step"], "unknown") if "step" in item else guard_pass(item)
        trust = "not_checked" if nc_on and a != "unknown" and EQ.nc_capable(b_, q["id"]) else "checked"
        if ctx.get("_nc_as_unknown") and trust == "not_checked":
            a = "unknown"
        ctx.setdefault("answers", []).append((q["id"], a, trust, "scripted" if trust == "not_checked" else None))
        return a
    return answer


def main():
    replay_txt, gates_txt, out_json = sys.argv[1:4]
    b = B.load()
    out = {"paths": {}, "flag_suggestions": {}}
    real = E._answer
    try:
        for lvl, d in B.flows(b):
            for path, o, guards in E.enumerate_paths(d["flow"]):
                pid = d["id"] + ":" + " > ".join(f"{st['step']}:{st['question']}={a}" for st, a in path)
                fixed = {st["step"]: a for st, a in path}
                res = {}
                for m, (mode, nc) in MODES.items():
                    E._answer = scripted(fixed, nc)
                    n = {"_idx": 0, "event.time": "2026-10-17T00:00:00Z"}
                    cr = CleanRoom(b, alerts=[n], timeline=[n], conns=[], context={"C-06": False}, customer=None, today="2026-10-17",
                                   closures=[], vuln_unknown=Counter())
                    E.derive(d, cr.register(n))
                    rctx = {"answerer": cr, "mode": mode, "customer": None}
                    r, trail = E.run_flow(b, d, n, rctx, NOW)
                    res[m] = r + (" +marked" if any(t.startswith("not_checked:") or t.startswith("auto_excluded:") for t in trail) else "")
                    dec = rctx.get("decision") or {}
                    if dec.get("suggests"):
                        out["flag_suggestions"].setdefault(pid, {})[m] = {"suggests": dec["suggests"], "blocked_by": dec["blocked_by"]["rule"],
                                                                          "shown": dec["suggestion_shown"]}
                out["paths"][pid] = res
    finally:
        E._answer = real
    rep = open(replay_txt).read()
    out["tp"] = {m.group(1): {"tp_events": int(m.group(3)), "outcomes": m.group(4).strip()}
                 for m in (re.match(r"^(D-\d{4})\s+(\d+)\s+(\d+)\s+(.*)$", line) for line in rep.splitlines()) if m}
    out["cases"] = sorted(l.strip() for l in rep.splitlines() if re.match(r"^\s+(ok  |FAIL) ", l) or l.startswith("         D-"))
    out["replay_summary"] = [l for l in rep.splitlines() if l.startswith("replay:")]
    g = open(gates_txt).read()
    out["selftest"] = re.findall(r"selftest: (\d+) of (\d+)", g)
    out["equivalence"] = re.findall(r"^equivalence.*$", g, re.M)
    out["redteam"] = re.findall(r"^\d+ flows, \d+ close paths.*$", g, re.M)
    out["validate"] = re.findall(r"^\d+ detections,.*$", g, re.M)
    json.dump(out, open(out_json, "w"), indent=1, sort_keys=True)
    print(len(out["paths"]), "paths;", len(out["tp"]), "detections;", len(out["cases"]), "case lines")


if __name__ == "__main__":
    sys.exit(main())
