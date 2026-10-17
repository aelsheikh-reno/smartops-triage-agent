#!/usr/bin/env bash
# Run every quality gate a batch must pass before its PR. Usage: tools/gates.sh <batch-name> <id-prefix>...
set -u
cd "$(dirname "$0")/.."
batch="${1:?batch name}"; shift
rc=0
echo "== 1. validate (incl. vendor-leak gate)";         python3 tools/validate.py | grep -v '^INFO' || true; python3 tools/validate.py >/dev/null || rc=1
echo "== 2. attacker influence"; python3 tools/redteam_paths.py --quiet && python3 tools/redteam_paths.py | tail -1 || rc=1
echo "== 3. replay (strict)";    python3 tools/replay.py --strict "$@" | tail -14; python3 tools/replay.py --strict "$@" >/dev/null || rc=1
echo "== 4. gate self-test";    python3 tools/selftest.py | tail -1; python3 tools/selftest.py >/dev/null || rc=1
echo "== 5. org.prevalence";     python3 tools/test_prevalence.py || rc=1
echo "== 6. review packet";      python3 tools/review_packet.py "$batch" "$@" || rc=1
python3 tools/load_sql.py >/dev/null && python3 tools/export_bundle.py >/dev/null && python3 tools/rank_facts.py > build/rank_facts.txt
exit $rc
