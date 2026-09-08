#!/bin/bash
# run_cprogs.sh — the same E1 matrix over the workloads compiled from C by
# clang's BPF backend, so the cost model is measured on compiler output and
# not only on our assembler's.
set -euo pipefail
cd "$(dirname "$0")/.."
RES=experiments/results/v2
mkdir -p "$RES"
REPS=${REPS:-3}
CPROGS="flowstats_c policy l4lb"
CONFIGS="vanilla:vanilla: sfi:sfi: tx:tx: tx-elide:tx-elide:E 2pl:2pl: \
txnd:tx:--no-shadow-diff tx-elidend:tx-elide:E,--no-shadow-diff \
jvanilla:vanilla:--jit jsfi:sfi:--jit jtx:tx:--jit \
jtx-elide:tx-elide:E,--jit j2pl:2pl:--jit"
flags_for() {
    local spec="$1" w="$2" out=""; local IFS=','
    for f in $spec; do case "$f" in
        E) out="$out --elide workloads/$w.elide";; "") ;; *) out="$out $f";;
    esac; done
    echo "$out"
}
echo ">>> e1 over clang-compiled workloads (${REPS} reps x 12 configs)"
for r in $(seq 1 "$REPS"); do
  for p in $CPROGS; do
    for c in $CONFIGS; do
      tag="${c%%:*}"; rest="${c#*:}"; mode="${rest%%:*}"; xf="${rest#*:}"
      FL=$(flags_for "$xf" "$p")
      # shellcheck disable=SC2086
      bin/ktxbench --prog "workloads/$p.kbin" $FL --mode "$mode" \
          --measure latency --threads 1 --iters 500000 --warmup 50000 \
          --seed $((42 + r)) --nkeys 1024 --zipf 0.0 --pktlen-min 64 \
          --pktlen-max 256 --fuel 65536 --batch 32 --exp e1_latency \
          --out "$RES/e1_lat_${p}_${tag}_r${r}.json"
      # shellcheck disable=SC2086
      bin/ktxbench --prog "workloads/$p.kbin" $FL --mode "$mode" \
          --measure throughput --threads 8 --iters 400000 --warmup 40000 \
          --seed $((42 + r)) --nkeys 1024 --zipf 0.0 --pktlen-min 64 \
          --pktlen-max 256 --fuel 65536 --exp e1_throughput \
          --out "$RES/e1_thr_${p}_${tag}_r${r}.json"
    done
  done
done
echo ">>> e14 elision audit (all workloads, guards retained on certified accesses)"
for p in pktcount flowstats tokenbucket maglev ctnat pktrewrite loopy \
         atomic_demo firewall flowstats_c policy l4lb; do
    bin/ktxbench --prog "workloads/$p.kbin" --elide "workloads/$p.elide" \
        --mode tx-audit --measure latency --threads 1 --iters 1000000 \
        --warmup 100000 --seed 42 --nkeys 1024 --zipf 0.0 --pktlen-min 64 \
        --pktlen-max 256 --fuel 65536 --batch 32 --exp e14_elision_audit \
        --out "$RES/e14_audit_${p}.json"
done
echo ">>> e13 engine calibration"
bin/ktxengine --iters 400000 --warmup 40000 --out "$RES/e13_engine.json"
echo "run_cprogs.sh: complete"
