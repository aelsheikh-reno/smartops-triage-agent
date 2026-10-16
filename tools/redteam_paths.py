#!/usr/bin/env python3
"""Attacker-influence gate: every path to a close must rest on at least one yes the attacker
cannot easily produce.

Enumerates every answer sequence (yes / no / unknown at each step) that reaches a close. A close
rests on the yes answers along its path, plus every guard on the closing step that needs a yes
(a guard that fires on no). Q-0000 uses its step-level rating, which follows the detection's
fingerprint fields. A path passes if at least one of those yes answers is rated none or low.

Each path is checked under the direct source profile (alert read from the product's API), where a
failure fails the gate. It is checked again under the forwarded profile (alert relayed over syslog),
where questions with by_source ratings may drop to medium: closes that fail there are reported as
closes that become flags for customers whose alerts arrive forwarded.

It is also checked under the fingerprint_fallback profile: a detection whose fingerprint field can
fall back (for example asset ID to hostname) rates Q0 at its fallback rating; precedent closes that
lose their none/low yes are reported as closes that flag when the fallback is used.

Usage: tools/redteam_paths.py [--quiet] [ids...]   exit 1 on any failing path
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

OK = ("none", "low")


def check(b, d, profile="direct"):
    results = []
    for path, outcome, guards in B.enumerate_paths(d["flow"]):
        if not outcome.startswith("close"):
            continue
        yes = B.yes_ratings(b, path, outcome, guards, profile)
        results.append((any(r in OK for _, r in yes), path, outcome, yes))
    return results


def main():
    quiet = "--quiet" in sys.argv
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    b = B.load()
    n_paths = n_fail = 0
    failing, forwarded, fallback = {}, {}, {}
    for level, d in B.flows(b):
        if only and not any(d["id"].startswith(o) for o in only):
            continue
        for ok, path, outcome, yes in check(b, d):
            n_paths += 1
            if not ok:
                n_fail += 1
                failing.setdefault(d["id"], []).append((path, outcome, yes))
        n_fwd = sum(1 for ok, *_ in check(b, d, "forwarded") if not ok)
        if n_fwd:
            forwarded[d["id"]] = n_fwd
        n_fb = sum(1 for ok, *_ in check(b, d, "fingerprint_fallback") if not ok)
        if n_fb:
            fallback[d["id"]] = n_fb
    for did, items in failing.items():
        print(f"FAIL {did}")
        for path, outcome, yes in items:
            trail = " > ".join(f"{st['step']}:{st['question']}={a}" for st, a in path)
            rated = ", ".join(f"{qid}={r}" for qid, r in yes) or "no yes answers"
            print(f"  {trail} -> {outcome}   [yes: {rated}]")
    if forwarded and not quiet:
        print("Closes that become flags when the family's alerts arrive forwarded (no none/low yes left):")
        for did, n in sorted(forwarded.items()):
            print(f"  {did}: {n}")
    if fallback and not quiet:
        print("Closes that become flags when the fingerprint falls back (Q0 at its fallback rating):")
        for did, n in sorted(fallback.items()):
            print(f"  {did}: {n}")
    if not quiet or failing:
        print(f"\n{n_paths} close paths checked, {n_fail} failing, in {len(failing)} flows; "
              f"{sum(forwarded.values())} closes flag under the forwarded profile, {sum(fallback.values())} under fingerprint fallback")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
