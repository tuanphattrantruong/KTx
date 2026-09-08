#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
REPS=${REPS:-3}
WRITES=${WRITES:-250000}
OUT=experiments/results/v4
mkdir -p "$OUT"
make bin/ktxobserver
for r in $(seq 1 "$REPS"); do
  bin/ktxobserver --writes "$WRITES" --out "$OUT/e16_ordinary_r${r}.json"
  bin/ktxobserver --published --writes "$WRITES" \
    --out "$OUT/e16_published_r${r}.json"
done
python3 experiments/analyze_e16.py "$OUT"/e16_*_r*.json \
  > "$OUT/e16_summary.json"
