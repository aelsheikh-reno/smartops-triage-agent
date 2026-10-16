#!/usr/bin/env python3
"""Load the YAML bank into a SQLite database (schema is Postgres-compatible).

Usage: tools/load_sql.py [output.sqlite]   (default: build/bank.sqlite)
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

J = lambda o: json.dumps(o, sort_keys=True)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(B.ROOT, "build", "bank.sqlite")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out):
        os.remove(out)
    b = B.load()
    db = sqlite3.connect(out)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")) as f:
        db.executescript(f.read())
    for c in b["capabilities"]["capabilities"]:
        db.execute("INSERT INTO capabilities VALUES (?,?,?,?,?,?)",
                   (c["name"], c["kind"], int(c["escalate_only"]), c["yes_means"], c["no_means"], c.get("flow_use")))
    for f in b["facts"].values():
        db.execute("INSERT INTO context_facts VALUES (?,?,?,?,?,?,?,?)",
                   (f["id"], f["name"], f["description"], f["collected_by"], f.get("match_rule"), J(f["fields"]),
                    int(B.has_unverified_seed(f)), f["version"]))
    for e in b["explanations"].values():
        db.execute("INSERT INTO explanations VALUES (?,?,?)", (e["id"], e["name"], e["description"]))
    for r in b["reason_codes"].values():
        db.execute("INSERT INTO reason_codes VALUES (?,?,?)", (r["code"], r["disposition"], r["description"]))
    for q in b["questions"].values():
        cap = q["capability"]
        db.execute("INSERT INTO questions VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (q["id"], q["text"], q["tests"], cap["name"], J(cap.get("inputs", {})), J(cap.get("params", {})),
                    J(q["source"]), J(q["license"]), q["status"], q["version"]))
        needs = {("context", x) for x in B.list_refs(q)}
        needs |= {("alert_field", f) for _, f in B.walk_refs(cap.get("inputs", {}))}
        needs |= {("param", p["param"]) for p in (cap.get("params") or {}).values() if isinstance(p, dict)}
        db.executemany("INSERT INTO question_needs VALUES (?,?,?)", [(q["id"], t, r) for t, r in sorted(needs)])
    n_steps = 0
    for level, d in B.flows(b):
        db.execute("INSERT INTO detections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (d["id"], level, d["name"], J(d.get("techniques", [d["id"]])), J(d.get("data_source", [])), J(d.get("sigma_logsource", [])), J(d.get("sigma_refs", [])),
                    J(d.get("required_alert_fields") or d.get("assumed_alert_fields")), d.get("intent"), d.get("fp_quality"),
                    J(d["fingerprint"]), d["precedent_validity"], d.get("max_mode"), d["status"], d["version"]))
        for st in d["flow"]:
            db.execute("INSERT INTO flow_steps VALUES (?,?,?,?,?,?,?)",
                       (d["id"], st["step"], st["question"], st["on_yes"], st["on_no"], st["on_unknown"], J(st.get("bind") or {})))
            n_steps += 1
    db.commit()
    counts = {t: db.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
              for t in ("detections", "questions", "flow_steps", "question_needs", "context_facts", "capabilities")}
    print(f"wrote {os.path.relpath(out, B.ROOT)}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))


if __name__ == "__main__":
    main()
