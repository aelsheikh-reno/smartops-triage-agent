#!/usr/bin/env bash
# Change-scope rule: a bank PR may add test cases and raise expected outcomes, but never lower them or change the engine,
# the contract or the gates; those change in their own PR. bank/contract/ is gate-side, not bank content: a PR that
# changes the contract with engine/, tools/ or tests/ passes as long as it changes nothing else under bank/.
# Compares the working tree (committed or not) with its merge base on origin/main (BASE overrides it). Fails if the change
# touches bank content (bank/ outside bank/contract/: triage/, broker/, intake/) and also:
#   - changes anything in bank/contract/ (added, modified or deleted), or
#   - modifies or deletes anything in engine/ or the gate code in tools/, or
#   - lowers an existing expected outcome in tests/cases/ (escalate > flag > close; a deleted case counts as lowered).
# A change with no bank content is not a bank PR and passes (a contract, engine, tools or tests PR).
# One-time exemptions live in tools/scope_exemptions.yaml; they apply only while that file is new in the change (see there).
set -u
cd "$(dirname "$0")/.."
base="${BASE:-$(git merge-base HEAD origin/main 2>/dev/null)}"
if [ -z "$base" ]; then echo "check_scope: no merge base with origin/main (fetch origin first)"; exit 2; fi
changed=$(git diff --name-status "$base" -- . ; git ls-files --others --exclude-standard | sed 's/^/A\t/')
if ! printf '%s\n' "$changed" | awk -F'\t' '{print $NF}' | grep '^bank/' | grep -vq '^bank/contract/'; then
  echo "check_scope: no bank content changed (bank/contract/ is gate-side; not a bank PR): pass"
  exit 0
fi
BASE_COMMIT="$base" CHANGED="$changed" python3 - <<'EOF'
import os, subprocess, sys
import yaml

base = os.environ["BASE_COMMIT"]
rows = [l.split("\t") for l in os.environ["CHANGED"].splitlines() if l.strip()]
bad = []
EXEMPTIONS = "tools/scope_exemptions.yaml"
exempt, bank_ok = set(), set()
at_base_exempt = subprocess.run(["git", "cat-file", "-e", f"{base}:{EXEMPTIONS}"], capture_output=True).returncode == 0
if os.path.exists(EXEMPTIONS) and not at_base_exempt:
    for e in (yaml.safe_load(open(EXEMPTIONS)) or {}).get("exemptions") or []:
        exempt |= set(e.get("protected_paths") or [])
        bank_ok |= set(e.get("bank_files") or [])
        print(f"check_scope: one-time exemption for PR #{e.get('pr')}: {e.get('why', '').strip()[:120]}")
elif at_base_exempt:
    print(f"check_scope: {EXEMPTIONS} already exists on the base: its exemptions no longer apply")
bank_changed = {paths[-1] for status, *paths in rows if paths[-1].startswith("bank/") and not paths[-1].startswith("bank/contract/")}
if exempt and bank_changed - bank_ok:
    print(f"check_scope: bank files outside the exemption changed ({sorted(bank_changed - bank_ok)}): the exemption does not apply")
    exempt = set()
for status, *paths in rows:
    path = paths[-1]
    old = paths[0]
    for p in {old, path}:
        protected = p.startswith(("engine/", "bank/contract/")) or (p.startswith("tools/") and not p.startswith("tools/__pycache__"))
        if protected and (status[0] in "MDR" or p.startswith("bank/contract/")):
            if p in exempt:
                print(f"check_scope: exempt {p} ({status})")
                continue
            bad.append(f"{p}: a bank PR may not change the engine, the contract or the gates ({status})")

RANK = {"close": 0, "flag": 1, "escalate": 2}

def rank(exp):
    """The lowest outcome a case's expectation allows, as close/flag/escalate (None for 'must not be' expectations)."""
    if not exp:
        return None
    want = exp.get("outcome") or exp.get("every_alert")
    return RANK.get(str(want).split(":")[0]) if want else None

def at_base(p):
    r = subprocess.run(["git", "show", f"{base}:{p}"], capture_output=True, text=True)
    return yaml.safe_load(r.stdout) if r.returncode == 0 else None

for status, *paths in rows:
    p = paths[0]
    if not (p.startswith("tests/cases/") and p.endswith(".yaml")) or status[0] == "A":
        continue
    before = at_base(p)
    if before is None:
        continue
    if status[0] == "D":
        bad.append(f"{p}: an existing test case was deleted (lowering)")
        continue
    after = yaml.safe_load(open(paths[-1]))
    rb, ra = rank(before.get("expect")), rank((after or {}).get("expect"))
    if before.get("expect", {}).get("not") and (after or {}).get("expect", {}).get("not") != before["expect"]["not"]:
        bad.append(f"{p}: a 'must not be {before['expect']['not']}' expectation was changed")
    elif rb is not None and (ra is None or ra < rb):
        bad.append(f"{p}: expected outcome lowered from {before['expect']} to {(after or {}).get('expect')}")
for b in bad:
    print("FAIL check_scope:", b)
print(f"check_scope: bank PR, {len(rows)} changed files, {len(bad)} violations -> {'FAIL' if bad else 'PASS'}")
sys.exit(1 if bad else 0)
EOF
