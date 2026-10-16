"""Shared loader for the YAML question bank."""
import glob
import os
import re

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BANK = os.path.join(ROOT, "bank")
REF = re.compile(r"\b(process|module|file|value):([A-Za-z_][A-Za-z0-9_]*)")
OUTCOME = re.compile(r"^(next|escalate|flag|close:(\w+):(\w+))$")


def _load(path):
    with open(path) as f:
        return yaml.safe_load(f)


def _by_id(pattern):
    out = {}
    for path in sorted(glob.glob(os.path.join(BANK, pattern))):
        doc = _load(path)
        doc["_file"] = os.path.relpath(path, ROOT)
        out[doc["id"]] = doc
    return out


def load():
    caps = _load(os.path.join(BANK, "capabilities.yaml"))
    return {
        "capabilities": caps,
        "capability_by_name": {c["name"]: c for c in caps["capabilities"]},
        "parameters": _load(os.path.join(BANK, "parameters.yaml"))["parameters"],
        "reason_codes": {r["code"]: r for r in _load(os.path.join(BANK, "reason_codes.yaml"))["reason_codes"]},
        "questions": _by_id("questions/Q-*.yaml"),
        "explanations": _by_id("explanations/BE-*.yaml"),
        "facts": _by_id("facts/CF-*.yaml"),
        "detections": _by_id("detections/*/*.yaml"),
        "techniques": _by_id("techniques/T*.yaml"),
        "pilot": _load(os.path.join(BANK, "pilot.yaml")),
    }


def flows(b):
    """All flows: rule-level detections first, then technique fallbacks."""
    for d in b["detections"].values():
        yield "rule", d
    for t in b["techniques"].values():
        yield "technique", t


def walk_refs(obj):
    """Yield (kind, field) for every entity reference in a capability input value."""
    if isinstance(obj, str):
        yield from REF.findall(obj)
    elif isinstance(obj, list):
        for x in obj:
            yield from walk_refs(x)
    elif isinstance(obj, dict):
        for x in obj.values():
            yield from walk_refs(x)


def step_inputs(question, step):
    """Capability inputs for a question after the step's bind overrides."""
    inputs = dict(question["capability"].get("inputs", {}))
    inputs.update(step.get("bind") or {})
    return inputs


def list_refs(question):
    """Context list ids (CF-xxxx) the question's capability reads."""
    ids = []
    for v in question["capability"].get("inputs", {}).values():
        for x in v if isinstance(v, list) else [v]:
            if isinstance(x, str) and x.startswith("CF-"):
                ids.append(x.split(".")[0])
    for x in (question.get("needs") or {}).get("context", []):
        if x not in ids:
            ids.append(x)
    return ids


def close_paths(b, flow):
    """For each non-precedent close: (step, edge, steps whose answer it rests on).

    A close at step k rests on step k and on every earlier gate step (yes goes on;
    no and unknown both stop the flow), since only a yes gets past a gate.
    """
    paths, gates = [], []
    for st in flow[1:]:
        for edge in ("on_yes", "on_no"):
            if st[edge].startswith("close"):
                paths.append((st["step"], edge, gates + [st["step"]]))
        if st["on_yes"] == "next" and st["on_no"] != "next" and st["on_unknown"] != "next":
            gates.append(st["step"])
    return paths


def tainted_closes(b, flow):
    """Closes that flag until onboarding: reached through a yes that reads unverified seed data."""
    unverified = {fid for fid, f in b["facts"].items() if has_unverified_seed(f)}
    by_step = {st["step"]: st for st in flow}
    out = []
    for step, edge, rests_on in close_paths(b, flow):
        bad = [s for s in rests_on
               if (s != step or edge == "on_yes")
               and set(list_refs(b["questions"][by_step[s]["question"]])) & unverified]
        if bad:
            out.append((step, edge, bad))
    return out


def has_unverified_seed(fact):
    def scan(o):
        if isinstance(o, dict):
            if o.get("verified") is False:
                return True
            return any(scan(v) for v in o.values())
        if isinstance(o, list):
            return any(scan(v) for v in o)
        return False
    return scan(fact.get("seed"))
