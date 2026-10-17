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

Identity group membership is never the only none/low yes on a close path: a path whose only
none/low yes answers come from identity.groups questions fails, because changing group membership
is exactly what an attacker with directory rights can do.

It is also checked under the fingerprint_fallback profile: a detection whose fingerprint field can
fall back (for example asset ID to hostname) rates Q0 at its fallback rating; precedent closes that
lose their none/low yes are reported as closes that flag when the fallback is used.

Usage: tools/redteam_paths.py [--quiet] [family ...]   exit 1 on any failing path, an unknown family, or 0 flows loaded
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402
from engine import executor as E  # noqa: E402

OK = ("none", "low")
def actor_identity(b, qid):
    """An answer about who performed the action: a capability tagged actor_identity (group membership, the implementer of a
    change) or a question tagged actor_identity (an actor account on a list, such as a provisioning service account)."""
    q = b["questions"][qid]
    return bool(q.get("actor_identity") or b["capability_by_name"].get(q["capability"]["name"], {}).get("actor_identity"))


def check(b, d, profile="direct"):
    results = []
    for path, outcome, guards in E.enumerate_paths(d["flow"]):
        if not outcome.startswith("close"):
            continue
        yes = B.yes_ratings(b, path, outcome, guards, profile)
        strong = [qid for qid, r in yes if r in OK and not actor_identity(b, qid)]
        results.append((bool(strong), path, outcome, yes))
    return results


def main():
    quiet = "--quiet" in sys.argv
    batches = B.select_batches([a for a in sys.argv[1:] if not a.startswith("--")])
    b = B.load()
    n_flows = n_paths = n_fail = 0
    failing, forwarded, fallback = {}, {}, {}
    for level, d in B.flows(b):
        if B.batch_of(level, d) not in batches:
            continue
        n_flows += 1
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
    B.require_loaded(f"attacker influence ({', '.join(sorted(batches))})", flows=n_flows, close_paths=n_paths)
    if not quiet or failing:
        print(f"\n{n_flows} flows, {n_paths} close paths checked, {n_fail} failing, in {len(failing)} flows; "
              f"{sum(forwarded.values())} closes flag under the forwarded profile, {sum(fallback.values())} under fingerprint fallback")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
