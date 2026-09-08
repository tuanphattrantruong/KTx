#!/bin/bash
# run_offline.sh — the untimed analyses (static, exhaustive, corpus).
# Kept out of run_v2.sh so their CPU use cannot perturb any measurement.
set -euo pipefail
cd "$(dirname "$0")/.."
RES=experiments/results/v2
mkdir -p "$RES"
CORPUS=${CORPUS:-}

echo ">>> e4 elision merge"
python3 - "$RES" <<'PYEOF'
import glob, json, sys, time
res = sys.argv[1]
runs = [json.load(open(p)) for p in sorted(glob.glob('workloads/*.elide.json'))]
json.dump({"experiment": "e4_elision",
           "meta": {"date_iso": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                    "note": "static analysis output of src/elide/elide.py, "
                            "merged verbatim from workloads/*.elide.json",
                    "seed": 42, "cmdline": "run_offline.sh e4_merge"},
           "runs": runs}, open(res + '/e4_elision.json', 'w'), indent=2)
print(f"e4_elision.json: merged {len(runs)} programs")
PYEOF

echo ">>> e8 serializability check"
python3 tools/ser_check.py "$RES"/e8_tx_*.json > "$RES/e8_check_tx.txt" 2>&1 \
    && echo "  tx histories: SERIALIZABLE" \
    || echo "  tx histories: VIOLATION FOUND (see e8_check_tx.txt)"
python3 tools/ser_check.py "$RES"/e8_direct_*.json \
    > "$RES/e8_check_direct.txt" 2>&1 \
    && echo "  direct control: serializable (UNEXPECTED - check is vacuous)" \
    || echo "  direct control: NOT serializable, as required for the check to have power"

echo ">>> e11 protocol model check"
python3 tools/model_check.py "$RES/e11_model_check.json" \
    > "$RES/e11_model_check.txt" 2>&1 || true
tail -2 "$RES/e11_model_check.txt"

if [ -n "$CORPUS" ]; then
    echo ">>> e10 corpus survey"
    python3 tools/corpus_survey.py "$CORPUS" "$RES/e10_corpus.json" \
        > "$RES/e10_corpus.txt" 2>&1
    tail -12 "$RES/e10_corpus.txt"
fi
echo "run_offline.sh: complete"
