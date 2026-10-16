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
    facts = _by_id("facts/CF-*.yaml")
    seeds = {}
    for path in sorted(glob.glob(os.path.join(BANK, "seeds", "*.yaml"))):
        doc = _load(path)
        doc["_file"] = os.path.relpath(path, ROOT)
        seeds[doc["fact"]] = doc
        if doc["fact"] in facts:
            facts[doc["fact"]]["seed"] = doc.get("entries", doc.get("data"))
    return {
        "seeds": seeds,
        "capabilities": caps,
        "capability_by_name": {c["name"]: c for c in caps["capabilities"]},
        "parameters": _load(os.path.join(BANK, "parameters.yaml"))["parameters"],
        "reason_codes": {r["code"]: r for r in _load(os.path.join(BANK, "reason_codes.yaml"))["reason_codes"]},
        "questions": _by_id("questions/Q-*.yaml"),
        "explanations": _by_id("explanations/BE-*.yaml"),
        "facts": facts,
        "detections": _by_id("detections/*/*.yaml"),
        "techniques": _by_id("techniques/T*.yaml"),
        "pilot": _load(os.path.join(BANK, "pilot.yaml")),
        "use_cases": (_load(os.path.join(BANK, "use_cases.yaml")) or {}).get("use_cases", []) if os.path.exists(os.path.join(BANK, "use_cases.yaml")) else [],
    }


def source_ids(b):
    """Map each rule-level detection's source-library id (e.g. escu:<file stem>) to its bank id."""
    out = {}
    for did, d in b["detections"].items():
        if did.startswith("vendor:"):
            out[did] = did
            continue
        src = d.get("source")
        if isinstance(src, dict) and src.get("path"):
            stem = os.path.splitext(os.path.basename(src["path"]))[0]
            out[did.split(":", 1)[0] + ":" + stem] = did
    return out


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
    """Closes that flag until onboarding: reached through a yes (a step's, or a guard's that needs one)
    that reads unverified seed data. Returns (step, edge, [steps or 'step:guard Q-xxxx'])."""
    unverified = {fid for fid, f in b["facts"].items() if has_unverified_seed(f)}
    reads = lambda qid: set(list_refs(b["questions"][qid])) & unverified
    out = {}
    for path, outcome, guards in enumerate_paths(flow):
        last, ans = path[-1]
        if not outcome.startswith("close") or last["step"] == 1:
            continue
        bad = [st["step"] for st, a in path if a == "yes" and reads(st["question"])]
        bad += [f"{last['step']}:guard {g['question']}" for g in guards if guard_requires_yes(g) and reads(g["question"])]
        if bad:
            key = (last["step"], "on_" + ans)
            out[key] = sorted(set(out.get(key, [])) | set(bad), key=str)
    return [(s, e, bad) for (s, e), bad in sorted(out.items())]


def close_edges(flow):
    """Distinct (step, edge) pairs that close, outside Q0."""
    return sorted({(st["step"], e) for st in flow[1:] for e in ("on_yes", "on_no") if st[e].startswith("close")})


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


# ---------- flow execution model shared by the gates ----------
ANS = (("yes", "on_yes"), ("no", "on_no"), ("unknown", "on_unknown"))
RATING_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}
LOCAL_KINDS = {"local"}


def is_local(b, qid):
    cap = b["capability_by_name"].get(b["questions"][qid]["capability"]["name"], {})
    return cap.get("kind") in LOCAL_KINDS


def guard_requires_yes(g):
    """A guard that fires on 'no' (and always on unknown) means the close needs a yes from it."""
    return "no" in g.get("when", ["yes"])


def enumerate_paths(flow):
    """Yield (path, outcome, guards). path = [(step, answer)]; guards apply only when outcome is a close."""
    def walk(i, path):
        if i >= len(flow):
            return
        st = flow[i]
        for ans, edge in ANS:
            out = st[edge]
            here = path + [(st, ans)]
            if out == "next":
                yield from walk(i + 1, here)
            else:
                yield here, out, (st.get("guards") or []) if out.startswith("close") else []
    yield from walk(0, [])


def path_calls(b, path, outcome, guards):
    n = sum(1 for st, _ in path if not is_local(b, st["question"]))
    if outcome.startswith("close"):
        n += sum(1 for g in guards if not is_local(b, g["question"]))
    return n


def rating(b, item, profile=None):
    """Attacker influence for a step or guard: a step-level override wins over the question's own."""
    ai = item.get("attacker_influence") or b["questions"][item["question"]]["attacker_influence"]
    if profile and profile in (ai.get("by_source") or {}):
        return ai["by_source"][profile]
    return ai["rating"]


def yes_ratings(b, path, outcome, guards, profile=None):
    """Ratings of every yes a close rests on: yes answers on the path, plus guards that need a yes."""
    out = [(st["question"], rating(b, st, profile)) for st, a in path if a == "yes"]
    if outcome.startswith("close"):
        out += [(g["question"], rating(b, g, profile)) for g in guards if guard_requires_yes(g)]
    return out


def q0_rating(d):
    """Q0's influence follows the detection's fingerprint: if any fingerprint field is none/low, an
    attacker cannot freely reproduce it; if every field is attacker-chosen, Q0 is high."""
    fi = d.get("fingerprint_influence") or {}
    ranks = [RATING_ORDER[fi[f]["rating"]] for f in d.get("fingerprint", []) if f in fi]
    if not ranks:
        return None
    best = min(ranks)
    return {0: "low", 1: "low", 2: "medium", 3: "high"}[best]
