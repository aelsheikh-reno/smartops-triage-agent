#!/usr/bin/env python3
"""Render docs/testing/attack-corpus-plan.md from tests/corpus/plan.yaml (the plan is the source; the page is generated)."""
import os
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "docs", "testing", "attack-corpus-plan.md")


def main():
    plan = yaml.safe_load(open(os.path.join(HERE, "plan.yaml")))
    lab, dets, dn = plan["lab"], plan["detections"], plan["data_needed_values"]
    by = {}
    for d in dets:
        by.setdefault(d["lab"], []).append(d)
    ids = lambda *keys: ", ".join(d["id"] for k in keys for d in by.get(k, [])) or "none"
    L = ["# Attack-corpus plan for the lab", "",
         "Generated from `tests/corpus/plan.yaml` by `tests/corpus/render_plan.py`; edit the YAML, not this page.", "",
         "The replay gate proves a detection against public true-positive data; the lab adds real alerts from the customer's stack shape "
         "(Splunk ES, Sysmon, Windows event logs, FortiGate). This plan lists, for every detection, the ATT&CK techniques, the Atomic Red Team "
         "tests that should fire it, public datasets that cover it, the data it needs, and whether the lab can produce it today.", "",
         "## Summary", "",
         f"- **Lab can cover now ({len(by.get('now', [])) + len(by.get('now_custom', []))}):** {ids('now', 'now_custom')}"
         + (" (D-0014 with a lab script: no Atomic Red Team test fits)" if by.get("now_custom") else ""),
         f"- **Lab can cover after a lab addition:** {ids('now_if_domain')} (a domain controller); {ids('now_if_office')} (Office with macros)",
         f"- **Blocked by the missing EDR:** {ids('blocked_no_edr')}; partly {ids('partial_no_edr')} (Windows Defender Antivirus events reach Splunk, as a fallback source; the EDR alert and API do not)",
         f"- **Blocked by the missing email gateway:** {ids('blocked_no_email_gateway')}",
         f"- **Need Cribl-synthesised vendor alerts:** {ids('blocked_no_edr', 'blocked_no_email_gateway', 'cribl_synth')} (until the product is in the lab; {ids('cribl_synth')} have no product planned)", "",
         "## The lab", "", "Has: " + "; ".join(lab["has"]) + ".", "", "Lacks: " + "; ".join(lab["lacks"]) + ".", "",
         "| Status | Meaning |", "|---|---|"] + [f"| `{k}` | {v} |" for k, v in lab["status_values"].items()] + [
         "", "## Sources", "", "| Source | Licence | Note |", "|---|---|---|"] + [
         f"| {k} | {v.get('license')} | {v.get('note') or v.get('commit') or v.get('pinned_in') or ''} |" for k, v in plan["sources"].items()] + [
         "", "## Per detection", "", "| D-ID | Detection | Techniques | Atomic Red Team tests | Public datasets | Data needed | Lab |", "|---|---|---|---|---|---|---|"]
    for d in dets:
        tests = "<br>".join(f"{t['test']} {t['name']} (`{t['guid'][:8]}`)" for t in d["atomic_tests"]) or "none fits"
        ds = "<br>".join(f"{x['source']}: {x.get('path', '')} ({x['license']})" for x in d["datasets"]) or "none"
        note = f"<br>{d['note']}" if d.get("note") else ""
        L.append(f"| {d['id']} | {d['name']} | {', '.join(d['techniques'])} | {tests} | {ds} | {', '.join(dn[x] for x in d['data_needed'])} | `{d['lab']}`{note} |")
    f = plan["lab_case_format"]
    L += ["", "## Lab case format", "", f"Where: {f['where']}.", "", "Required: " + ", ".join(f"`{x}`" for x in f["required"]) + ".", "",
          "| Field | Meaning |", "|---|---|"] + [f"| `{k}` | {v} |" for k, v in f["fields"].items()] + ["", f"Never committed: {f['never_committed']}.", ""]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    open(OUT, "w").write("\n".join(L))
    print(f"wrote {os.path.relpath(OUT, ROOT)}")


if __name__ == "__main__":
    main()
