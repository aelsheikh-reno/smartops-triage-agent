#!/usr/bin/env python3
"""Attacker-influence gate: every path to a close must rest on at least one yes the attacker
cannot easily produce.

Enumerates every answer sequence (yes / no / unknown at each step) that reaches a close. A path
passes if at least one question answered yes on it has attacker_influence none or low. A path whose
only yes answers are rated high (or that closes with no yes at all) fails: an attacker who controls
those values could steer the alert to a close.

Usage: tools/redteam_paths.py [--quiet] [ids...]   exit 1 on any failing path
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

ANSWERS = (("yes", "on_yes"), ("no", "on_no"), ("unknown", "on_unknown"))


def close_paths(flow):
    """Yield (path, outcome); path is a list of (step, question, answer)."""
    def walk(i, path):
        if i >= len(flow):
            return
        st = flow[i]
        for ans, edge in ANSWERS:
            out = st[edge]
            here = path + [(st["step"], st["question"], ans)]
            if out == "next":
                yield from walk(i + 1, here)
            elif out.startswith("close"):
                yield here, out
    yield from walk(0, [])


def check(b, d):
    q = b["questions"]
    results = []
    for path, outcome in close_paths(d["flow"]):
        yes = [(s, qid, q[qid]["attacker_influence"]["rating"]) for s, qid, a in path if a == "yes"]
        ok = any(r in ("none", "low") for _, _, r in yes)
        results.append((ok, path, outcome, yes))
    return results


def main():
    quiet = "--quiet" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    b = B.load()
    n_paths = n_fail = 0
    failing = {}
    for level, d in B.flows(b):
        if only and not any(d["id"].startswith(o) for o in only):
            continue
        for ok, path, outcome, yes in check(b, d):
            n_paths += 1
            if not ok:
                n_fail += 1
                failing.setdefault(d["id"], []).append((path, outcome, yes))
    for did, items in failing.items():
        print(f"FAIL {did}")
        for path, outcome, yes in items:
            trail = " > ".join(f"{s}:{qid}={a}" for s, qid, a in path)
            rated = ", ".join(f"{qid}={r}" for _, qid, r in yes) or "no yes answers"
            print(f"  {trail} -> {outcome}   [yes: {rated}]")
    if not quiet or failing:
        print(f"\n{n_paths} close paths checked, {n_fail} failing, in {len(failing)} flows")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
