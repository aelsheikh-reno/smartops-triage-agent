#!/usr/bin/env python3
"""Write a review packet for an external reviewer: each detection's name, intent, flow table,
question texts, capability and attacker influence, guards, plus the gate results. If
review/changes/<batch-name>.md exists, it is included as "Changes since review".

Usage: tools/review_packet.py <packet-name> [family ...]   families: endpoint, identity, endpoint_malware, network, email, data_protection, technique_fallback; none means all
   e.g. tools/review_packet.py batch-1-vendor-alerts endpoint_malware network email data_protection
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


def influence(b, item):
    ai = item.get("attacker_influence") or b["questions"][item["question"]]["attacker_influence"]
    extra = "".join(f", {k} {v}" for k, v in (ai.get("by_source") or {}).items())
    return ai["rating"] + extra


def rule_text(item):
    r = item.get("rule")
    if not r:
        return ""
    fmt = lambda v: f"{v['param']}" if isinstance(v, dict) else "/".join(map(str, v)) if isinstance(v, list) else str(v)
    return " [" + "; ".join(f"{k} {fmt(v)}" for k, v in r.items()) + "]"


def guard_text(b, st):
    out = []
    for g in st.get("guards") or []:
        extra = []
        if g.get("applies_to", ["close"]) != ["close"]:
            extra.append("on " + "/".join(g["applies_to"]))
        if g.get("if_entry_type"):
            extra.append("if " + "/".join(g["if_entry_type"]))
        out.append(f"{g['question']}{rule_text(g)} {'/'.join(g.get('when', ['yes']))} → {g['then']}" + (f" ({', '.join(extra)})" if extra else ""))
    return "; ".join(out) or "–"


def gate(cmd):
    r = subprocess.run([sys.executable] + cmd, cwd=B.ROOT, capture_output=True, text=True)
    lines = [l for l in r.stdout.strip().splitlines() if l.strip()]
    return ("PASS" if r.returncode == 0 else "FAIL"), (lines[-1] if lines else "")


def main():
    name, batches = sys.argv[1], B.select_batches(sys.argv[2:])
    b = B.load()
    dets = [d for did, d in sorted(b["detections"].items()) if B.batch_of("rule", d) in batches]
    B.require_loaded(f"review packet ({', '.join(sorted(batches))})", detections=len(dets))
    used = []
    for d in dets:
        for st in d["flow"]:
            for qid in [st["question"]] + [g["question"] for g in st.get("guards") or []]:
                if qid not in used:
                    used.append(qid)
    caps_used = sorted({b["questions"][q]["capability"]["name"] for q in used})
    L = [f"# Review packet: {name}", "",
         f"{len(dets)} detections, {len(used)} distinct questions, {len(caps_used)} capabilities. Everything is `status: draft`.", "",
         "How to read a flow: steps run top to bottom; each answer leads to the next step, a close (with disposition and reason code), "
         "an escalation, or a flag to an analyst with no verdict. An unknown answer never closes. Q-0000 (precedent) runs first everywhere.", "",
         "Guards run when a step reaches a close (or, where marked, a flag): each names a question and the answers that raise the outcome; guards only raise, and the strongest result wins "
         "(an unknown guard answer always flags, so the table lists only the triggering answers). A guard that fires on no means the close needs a yes from it.", "",
         "Each question asks the Tool Broker for a typed answer (bool, count, number, enum); where it is not bool, the step's rule [in brackets] turns it "
         "into yes or no on the Triage side, against a parameter with bounds. Questions refer to roles of the normalized alert, never to fields.", "",
         "Attacker influence rates how easily the activity under triage could produce a yes: **none** (records the attacker cannot touch, such as change tickets), "
         "**low** (OS-verified or control-recorded facts), **medium** (control-recorded facts that can be forged in transit, such as alerts forwarded over syslog), "
         "**high** (attacker-chosen strings such as process names, sender addresses or command lines). "
         "Every path to a close must rest on at least one yes rated none or low. Q-0000's rating is set per detection from its fingerprint fields.", ""]
    changes = os.path.join(B.ROOT, "review", "changes", f"{name}.md")
    if os.path.exists(changes):
        with open(changes) as fh:
            L += ["## Changes since review", "", fh.read().strip(), ""]
    L += ["## Gate results", ""]
    for label, cmd in (("validate", ["tools/validate.py"]), ("attacker influence", ["tools/redteam_paths.py"]), ("replay", ["tools/replay.py"] + [x for x in sorted(batches) if x != "technique"] if batches != set(B.BATCHES) else ["tools/replay.py"])):
        status, line = gate(cmd)
        L.append(f"- {label}: {status} ({line})")
    L += ["", "## Detections", ""]
    for d in dets:
        L += [f"### {d['name']} (`{d['id']}`)", "", d["intent"], ""]
        if d.get("notes"):
            L += [f"Note: {d['notes']}", ""]
        fi = d.get("fingerprint_influence") or {}
        fps = ", ".join(f"{f} ({fi[f]['rating']})" if f in fi else f for f in d["fingerprint"])
        validity = (d.get("parameters") or {}).get("precedent_validity_hours", b["parameters"]["precedent_validity_hours"]["default"])
        extra = ", ".join(f"{k} {v}" for k, v in (d.get("parameters") or {}).items() if k != "precedent_validity_hours")
        L += [f"Required roles: {', '.join(d.get('required_roles', []))}. Fingerprint: {fps}. Precedent entity: {d.get('precedent_entity')}. "
              f"Precedent valid for {validity}h." + (f" Detection parameters: {extra}." if extra else ""), "",
              "| Step | Question | Capability | Influence | Yes | No | Unknown | Guards (on close) |", "|---|---|---|---|---|---|---|---|"]
        for st in d["flow"]:
            q = b["questions"][st["question"]]
            L.append(f"| {st['step']} | {q['id']}: {q['text']}{rule_text(st)} | `{q['capability']['name']}` | {influence(b, st)} | "
                     f"{outcome(st['on_yes'])} | {outcome(st['on_no'])} | {outcome(st['on_unknown'])} | {guard_text(b, st)} |")
        L.append("")
    L += ["## Questions used", "", "| Question | Text | Capability | Influence | Why |", "|---|---|---|---|---|"]
    for qid in sorted(used):
        q = b["questions"][qid]
        L.append(f"| {qid} | {q['text']} | `{q['capability']['name']}` | {influence(b, {'question': qid})} | {q['attacker_influence']['reason']} |")
    facts_used = sorted({l for qid in used for l in B.list_refs(b["questions"][qid])})
    L += ["", "## Context facts used", "",
          "Supply effort is how hard a low-maturity customer finds it to provide the fact. These ratings are a draft judgement by the bank author, "
          "not measured; first onboardings should correct them.", "",
          "| Fact | Name | Supply effort (draft) | Why |", "|---|---|---|---|"]
    for fid in facts_used:
        f = b["facts"][fid]
        L.append(f"| {fid} | {f['name']} | {f.get('supply_effort', '?')} | {f.get('supply_effort_reason', '')} |")
    L += ["", "## Capabilities used", "", "| Capability | Answer | Meaning | Escalate only |", "|---|---|---|---|"]
    for c in caps_used:
        cap = b["capability_by_name"][c]
        L.append(f"| `{c}` | {cap['answer']['type']} | {cap.get('yes_means') or cap.get('measures')} | {'yes' if cap['escalate_only'] else 'no'} |")
    os.makedirs(os.path.join(B.ROOT, "review"), exist_ok=True)
    path = os.path.join(B.ROOT, "review", f"{name}.md")
    with open(path, "w") as fh:
        fh.write("\n".join(L) + "\n")
    print(f"wrote {os.path.relpath(path, B.ROOT)}")


if __name__ == "__main__":
    main()
