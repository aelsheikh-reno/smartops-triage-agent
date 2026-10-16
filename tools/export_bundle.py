#!/usr/bin/env python3
"""Export the runtime bundle: what the triage agent and MCP server receive.

Offline metadata stays out: data_source, sigma_logsource, sigma_refs, source, license,
text_origin, legal_review and source identifiers. Seed data (bank/seeds/), the use-case
catalog and the pilot list are not part of the bundle.

Usage: tools/export_bundle.py [out.json]   (default: build/runtime_bundle.json)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

OFFLINE_KEYS = {"data_source", "sigma_logsource", "sigma_refs", "source", "license", "text_origin", "legal_review",
                "escu_uuid", "_file", "seed", "explanations"}


def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in OFFLINE_KEYS}
    if isinstance(o, list):
        return [strip(v) for v in o]
    return o


def build(b=None):
    b = b or B.load()
    caps = b["capabilities"]
    return strip({
        "bundle_version": 1,
        "answer_contract": caps["answer_contract"],
        "unknown_semantics": caps["unknown_semantics"],
        "unverified_seed": caps["unverified_seed"],
        "guard_semantics": caps["guard_semantics"],
        "attacker_influence_scale": caps["attacker_influence_scale"],
        "source_profiles": caps["source_profiles"],
        "scope": caps["scope"],
        "capabilities": caps["capabilities"],
        "parameters": b["parameters"],
        "reason_codes": list(b["reason_codes"].values()),
        "explanations": [{k: e[k] for k in ("id", "name", "description")} for e in b["explanations"].values()],
        "facts": list(b["facts"].values()),
        "questions": list(b["questions"].values()),
        "detections": list(b["detections"].values()),
        "technique_fallbacks": list(b["techniques"].values()),
    })


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(B.ROOT, "build", "runtime_bundle.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    bundle = build()
    with open(out, "w") as f:
        json.dump(bundle, f, indent=1, sort_keys=True)
    print(f"wrote {os.path.relpath(out, B.ROOT)}: {len(bundle['detections'])} detections, {len(bundle['technique_fallbacks'])} fallbacks, "
          f"{len(bundle['questions'])} questions, {len(bundle['capabilities'])} capabilities")


if __name__ == "__main__":
    main()
