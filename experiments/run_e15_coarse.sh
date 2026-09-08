#!/bin/bash
# E15: abort-safe coarse serialization versus KTx OCC under identical guards.
set -euo pipefail
cd "$(dirname "$0")/.."
RES=experiments/results/v3
mkdir -p "$RES"
REPS=${REPS:-3}
ITERS=${ITERS:-250000}
WARMUP=${WARMUP:-25000}
NKEYS=${NKEYS:-1024}

make all
python3 tools/asm.py workloads/ctnat.S -o workloads/ctnat.kbin
# l4lb.kbin is produced from workloads/c/l4lb.c by run_cprogs.sh and retained
# as the exact compiled-C program used by the paper.
test -f workloads/l4lb.kbin

for r in $(seq 1 "$REPS"); do
  for p in ctnat l4lb; do
    for t in 1 2 4 8 16 32; do
      for m in tx coarse; do
        bin/ktxbench --prog "workloads/$p.kbin" --mode "$m" --jit \
          --measure throughput --threads "$t" --iters "$ITERS" \
          --warmup "$WARMUP" --seed $((100 + r)) --nkeys "$NKEYS" --zipf 0.0 \
          --pktlen-min 64 --pktlen-max 256 --fuel 65536 --exp e15_coarse \
          --out "$RES/e15_${p}_${m}_${t}t_r${r}.json"
      done
    done
  done
done

python3 experiments/analyze_e15.py --results "$RES" \
  --out "$RES/e15_coarse_summary.json"
