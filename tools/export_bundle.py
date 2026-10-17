#!/usr/bin/env python3
"""Export the runtime bundles: what the Triage agent receives and what the Tool Broker receives.

The triage bundle holds the contract and the triage layer only (contract/ and triage/, read from disk): question IDs and
answer types, status, trust and the envelope; detections and flows, questions with their role inputs, context questions,
parameters, guards, reason codes. It never holds anything from broker/ or intake/.
The broker bundle holds the contract and the broker's capabilities, sources, scope profiles, question map, broker
parameters and context-list definitions. Translations ship with the broker's recipes, not in either bundle; seed data,
the rule map, the use-case catalog and the pilot list are never in a bundle.
Offline metadata stays out of both: derived_from, data_source, sigma_logsource, sigma_refs, source, license,
text_origin, legal_review and source identifiers.

Usage: tools/export_bundle.py [out_dir]   (default: build/; writes triage_bundle.json and broker_bundle.json)
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

OFFLINE_KEYS = {"data_source", "sigma_logsource", "sigma_refs", "source", "license", "text_origin", "legal_review",
                "escu_uuid", "_file", "seed", "explanations", "derived_from"}


def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in OFFLINE_KEYS}
    if isinstance(o, list):
        return [strip(v) for v in o]
    return o


def _files(pattern):
    return [B._load(p) for p in sorted(glob.glob(os.path.join(B.BANK, pattern), recursive=True))]


def build(b=None):
    b = b or B.load()
    caps = b["capabilities"]
    contract = {"questions": list(b["contract"]["questions"].values()),
                "answer": b["contract"]["answer"], "envelope": b["contract"]["envelope"]}
    triage_params = (B._load(os.path.join(B.TRIAGE, "parameters.yaml")) or {})
    triage = strip({
        "bundle_version": 2,
        "contract": contract,
        "semantics": B._load(os.path.join(B.TRIAGE, "semantics.yaml")),
        "parameters": triage_params.get("parameters"),
        "parameter_precedence": triage_params.get("precedence"),
        "context_questions": _files("triage/context/C-*.yaml"),
        "context_rules": B._load(os.path.join(B.TRIAGE, "context_rules.yaml")),
        "reason_codes": B._load(os.path.join(B.TRIAGE, "reason_codes.yaml"))["reason_codes"],
        "explanations": [{k: e[k] for k in ("id", "name", "description")} for e in _files("triage/explanations/BE-*.yaml")],
        "questions": _files("triage/questions/Q-*.yaml"),
        "detections": _files("triage/detections/*/*.yaml"),
        "technique_fallbacks": _files("triage/techniques/T*.yaml"),
    })
    broker = strip({
        "bundle_version": 2,
        "contract": contract,
        "capabilities": caps["capabilities"],
        "alert_classes": caps["alert_classes"],
        "scope": caps["scope"],
        "source_authority": caps.get("source_authority"),
        "unverified_seed": caps.get("unverified_seed"),
        "question_map": b["question_map"],
        "parameters": (B._load(os.path.join(B.BROKER, "parameters.yaml")) or {}).get("parameters"),
        "facts": [{k: v for k, v in f.items() if k not in ("seed", "default_entries", "example")} for f in b["facts"].values()],
    })
    return {"triage": triage, "broker": broker}


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(B.ROOT, "build")
    os.makedirs(out, exist_ok=True)
    bundles = build()
    for name, bundle in bundles.items():
        with open(os.path.join(out, f"{name}_bundle.json"), "w") as f:
            json.dump(bundle, f, indent=1, sort_keys=True)
    t, br = bundles["triage"], bundles["broker"]
    print(f"wrote {os.path.relpath(out, B.ROOT)}/triage_bundle.json: {len(t['detections'])} detections, {len(t['technique_fallbacks'])} fallbacks, "
          f"{len(t['questions'])} questions; broker_bundle.json: {len(br['capabilities'])} capabilities, {len(br['question_map'])} mapped questions")


if __name__ == "__main__":
    main()
