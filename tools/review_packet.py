#!/usr/bin/env python3
"""Write a review packet for an external reviewer: each detection's name, intent, flow table,
question texts, capability and attacker influence, plus the gate results.

Usage: tools/review_packet.py <batch-name> <id-prefix> [<id-prefix> ...]
   e.g. tools/review_packet.py batch-1-vendor-alerts vendor:
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bank as B  # noqa: E402

OUT = {"next": "next step", "escalate": "**escalate**", "flag": "flag to analyst"}


def outcome(v):
    if v.startswith("close:"):
        _, disp, code = v.split(":")
        return f"close ({disp.replace('_', ' ')}: {code})"
    return OUT.get(v, v)


def gate(cmd):
    r = subprocess.run([sys.executable] + cmd, cwd=B.ROOT, capture_output=True, text=True)
    lines = [l for l in r.stdout.strip().splitlines() if l.strip()]
    return ("PASS" if r.returncode == 0 else "FAIL"), (lines[-1] if lines else "")


def main():
    name, prefixes = sys.argv[1], sys.argv[2:]
    b = B.load()
    dets = [d for did, d in sorted(b["detections"].items()) if any(did.startswith(p) for p in prefixes)]
    used = []
    for d in dets:
        for st in d["flow"]:
            if st["question"] not in used:
                used.append(st["question"])
    caps_used = sorted({b["questions"][q]["capability"]["name"] for q in used})
    L = [f"# Review packet: {name}", "",
         f"{len(dets)} detections, {len(used)} distinct questions, {len(caps_used)} capabilities. Everything is `status: draft`.", "",
         "How to read a flow: steps run top to bottom; each answer leads to the next step, a close (with disposition and reason code), "
         "an escalation, or a flag to an analyst with no verdict. An unknown answer never closes. Q-0000 (precedent) runs first everywhere.", "",
         "Attacker influence rates how easily the activity under triage could produce a yes: **none** (records the attacker cannot touch, such as change tickets), "
         "**low** (OS-verified or control-recorded facts), **high** (attacker-chosen strings such as process names or command lines). "
         "Every path to a close must rest on at least one yes rated none or low.", "", "## Gate results", ""]
    for label, cmd in (("validate", ["tools/validate.py"]), ("attacker influence", ["tools/redteam_paths.py"]), ("replay", ["tools/replay.py"] + prefixes)):
        status, line = gate(cmd)
        L.append(f"- {label}: {status} ({line})")
    L += ["", "## Detections", ""]
    for d in dets:
        L += [f"### {d['name']} (`{d['id']}`)", "", d["intent"], ""]
        if d.get("notes"):
            L += [f"Note: {d['notes']}", ""]
        L += [f"Alert fields: {', '.join(d.get('required_alert_fields', []))}. Fingerprint: {', '.join(d['fingerprint'])}. Precedent valid for {d['precedent_validity']}.", "",
              "| Step | Question | Capability | Influence | Yes | No | Unknown |", "|---|---|---|---|---|---|---|"]
        for st in d["flow"]:
            q = b["questions"][st["question"]]
            L.append(f"| {st['step']} | {q['id']}: {q['text']} | `{q['capability']['name']}` | {q['attacker_influence']['rating']} | "
                     f"{outcome(st['on_yes'])} | {outcome(st['on_no'])} | {outcome(st['on_unknown'])} |")
        L.append("")
    L += ["## Questions used", "", "| Question | Text | Capability | Influence | Why |", "|---|---|---|---|---|"]
    for qid in sorted(used):
        q = b["questions"][qid]
        L.append(f"| {qid} | {q['text']} | `{q['capability']['name']}` | {q['attacker_influence']['rating']} | {q['attacker_influence']['reason']} |")
    L += ["", "## Capabilities used", "", "| Capability | Yes means | Escalate only |", "|---|---|---|"]
    for c in caps_used:
        cap = b["capability_by_name"][c]
        L.append(f"| `{c}` | {cap['yes_means']} | {'yes' if cap['escalate_only'] else 'no'} |")
    os.makedirs(os.path.join(B.ROOT, "review"), exist_ok=True)
    path = os.path.join(B.ROOT, "review", f"{name}.md")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"wrote {os.path.relpath(path, B.ROOT)}")


if __name__ == "__main__":
    main()
