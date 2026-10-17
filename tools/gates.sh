#!/usr/bin/env bash
# Run every quality gate. Usage: tools/gates.sh [batch ...]
#   No argument runs every batch (escu, vendor, technique). A batch argument narrows the batch-scoped gates
#   (attacker influence, replay, review packet). An unknown batch, or a gate that loads nothing, fails.
#   The review packet is written to review/$PACKET.md (default bank-migration).
set -u
cd "$(dirname "$0")/.."
packet="${PACKET:-bank-migration}"
rc=0
python3 -c 'import sys; sys.path.insert(0, "tools"); import bank as B; B.select_batches(sys.argv[1:])' "$@" || exit 2
# Replay covers the rule-level batches only; technique fallbacks have no source rule or dataset.
replay_batches=()
for a in "$@"; do [ "$a" != technique ] && replay_batches+=("$a"); done
echo "== 1. validate (incl. vendor-leak gate)"; python3 tools/validate.py | grep -v '^INFO'; [ "${PIPESTATUS[0]}" = 0 ] || rc=1
echo "== 2. attacker influence";  python3 tools/redteam_paths.py --quiet "$@" || rc=1; python3 tools/redteam_paths.py "$@" | tail -1
if [ $# -gt 0 ] && [ ${#replay_batches[@]} -eq 0 ]; then
  echo "== 3. replay: skipped (technique fallbacks are not replayable)"
else
  echo "== 3. replay (strict)";   python3 tools/replay.py --strict "${replay_batches[@]}" > build/replay.txt 2>&1 || rc=1; tail -16 build/replay.txt
fi
echo "== 4. gate self-test";      python3 tools/selftest.py > build/selftest.txt 2>&1 || rc=1; tail -1 build/selftest.txt
echo "== 5. org.prevalence";      python3 tools/test_prevalence.py || rc=1
echo "== 6. review packet";       python3 tools/review_packet.py "$packet" "$@" || rc=1
python3 tools/load_sql.py >/dev/null && python3 tools/export_bundle.py >/dev/null && python3 tools/rank_facts.py > build/rank_facts.txt || rc=1
echo "gates: $([ $rc = 0 ] && echo PASS || echo FAIL)"
exit $rc
