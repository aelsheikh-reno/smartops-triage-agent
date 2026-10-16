#!/usr/bin/env python3
"""Rank what each closure depends on, grouped by capability.

A close at step k needs that step's capability to answer, plus every earlier gate step
(one whose no and unknown edges both stop the flow). A detection is "unblocked" by a fact
if at least one of its non-precedent close paths needs it; "sole" means every one does.
Facts are context lists for lookups, and the question itself for baselines and prevalence.

Usage: tools/rank_facts.py [bank.sqlite]   (default: build/bank.sqlite)
"""
import collections
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402


def fact_keys(db, qid, cap):
    lists = [r[0] for r in db.execute("SELECT need_ref FROM question_needs WHERE question_id=? AND need_type='context'", (qid,))]
    if cap == "case.precedent":
        return []
    if lists and cap != "entity.baseline":
        return [(cap, l) for l in lists]
    return [(cap, qid)]


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(B.ROOT, "build", "bank.sqlite")
    db = sqlite3.connect(path)
    qcap = dict(db.execute("SELECT id, capability FROM questions"))
    qtext = dict(db.execute("SELECT id, text FROM questions"))
    names = dict(db.execute("SELECT id, name FROM context_facts"))
    unverified = {r[0] for r in db.execute("SELECT id FROM context_facts WHERE has_unverified_seed=1")}
    esc_only = {r[0] for r in db.execute("SELECT name FROM capabilities WHERE escalate_only=1")}
    stat = collections.defaultdict(lambda: {"rule": set(), "sole": set(), "technique": set(), "escalates": set()})
    no_close = []
    for did, level in db.execute("SELECT id, level FROM detections").fetchall():
        steps = db.execute("SELECT step, question_id, on_yes, on_no, on_unknown FROM flow_steps WHERE detection_id=? ORDER BY step", (did,)).fetchall()
        paths, gates = [], []
        for step, qid, y, n, u in steps[1:]:
            keys = fact_keys(db, qid, qcap[qid])
            if qcap[qid] in esc_only:
                for k in keys:
                    stat[k]["escalates"].add(did)
            if y.startswith("close") or n.startswith("close"):
                paths.append(set(keys) | set(gates))
            if y == "next" and n != "next" and u != "next":
                gates.extend(keys)
        if not paths and level == "rule":
            no_close.append(did)
        for k in set().union(*paths) if paths else set():
            stat[k]["technique" if level == "technique" else "rule"].add(did)
            if level == "rule" and all(k in p for p in paths):
                stat[k]["sole"].add(did)
    by_cap = collections.defaultdict(list)
    for (cap, ref), s in stat.items():
        by_cap[cap].append((len(s["rule"]), len(s["sole"]), len(s["technique"]), len(s["escalates"]), ref))
    total = db.execute("SELECT count(*) FROM detections WHERE level='rule'").fetchone()[0]
    print(f"What closures depend on, by capability ({total} rule-level detections).")
    print("rules = detections with at least one close path needing it; sole = every close path needs it; tech = technique fallbacks.\n")
    order = sorted(by_cap, key=lambda c: -max(x[0] for x in by_cap[c]))
    for cap in order:
        rows = sorted(by_cap[cap], key=lambda x: (-x[0], -x[1], -x[2], x[4]))
        print(f"{cap}")
        for r, sole, tech, esc, ref in rows:
            label = f"{ref} {names[ref]}" if ref in names else f"{ref} {qtext[ref][:70]}"
            flag = " [unverified seed: closes flag until onboarding]" if ref in unverified else ""
            extra = f"  escalates {esc}" if esc else ""
            print(f"  rules {r:>2}  sole {sole:>2}  tech {tech:>2}{extra}  {label}{flag}")
        print()
    flat = sorted(((r, s, t, cap, ref) for cap in by_cap for r, s, t, _, ref in by_cap[cap]), key=lambda x: (-x[0], -x[1], -x[2]))
    print("Top 15 overall:")
    for i, (r, s, t, cap, ref) in enumerate(flat[:15], 1):
        print(f"  {i:>2}. {cap:<16} {ref:<8} {names.get(ref, '')}  rules {r}, sole {s}, tech {t}")
    b = B.load()
    print("\nCloses that flag until onboarding verifies seed data (taint propagates through gates):")
    for _, d in B.flows(b):
        t = B.tainted_closes(b, d["flow"])
        if t:
            total_closes = len(B.close_paths(b, d["flow"]))
            print(f"  {d['id']}: {len(t)} of {total_closes} closes, via step(s) {sorted({s for _, _, bad in t for s in bad})}")
    if no_close:
        print("\nRule-level detections with no close outside Q0:", ", ".join(no_close))


if __name__ == "__main__":
    main()
