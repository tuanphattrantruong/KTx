#!/bin/bash
# run_jit.sh — the JIT arm of the evaluation.
#
# Every cell here is the *same* configuration as its interpreter twin in
# run_v2.sh, with --jit added, so the pair isolates one variable: whether
# the extension body executes as interpreted bytecode or as native code.
# The transactional layer, the helper ABI, the commit protocol and the
# packet generator are byte-identical between the two arms.
set -euo pipefail
cd "$(dirname "$0")/.."
RES=experiments/results/v2
mkdir -p "$RES"
REPS=${REPS:-3}
log_block() { { echo ""; echo "=== $1 ==="; date; } >> "$RES/run_log.txt";
              echo ">>> $1"; }

W9="pktcount flowstats tokenbucket maglev ctnat pktrewrite loopy atomic_demo firewall"
MODES="vanilla sfi tx tx-elide 2pl"

log_block "e12_jit_lat (${REPS} reps)"
for r in $(seq 1 "$REPS"); do
  for p in $W9; do
    for m in $MODES; do
      EL=""; [ "$m" = "tx-elide" ] && EL="--elide workloads/$p.elide"
      # shellcheck disable=SC2086
      bin/ktxbench --prog "workloads/$p.kbin" $EL --mode "$m" --jit \
          --measure latency --threads 1 --iters 1000000 --warmup 100000 \
          --seed $((42 + r)) --nkeys 1024 --zipf 0.0 --pktlen-min 64 \
          --pktlen-max 256 --fuel 65536 --batch 32 --exp e12_jit_latency \
          --out "$RES/e12_lat_${p}_${m}_r${r}.json"
    done
  done
done

log_block "e12_jit_thr (${REPS} reps)"
for r in $(seq 1 "$REPS"); do
  for p in $W9; do
    for m in $MODES; do
      EL=""; [ "$m" = "tx-elide" ] && EL="--elide workloads/$p.elide"
      # shellcheck disable=SC2086
      bin/ktxbench --prog "workloads/$p.kbin" $EL --mode "$m" --jit \
          --measure throughput --threads 8 --iters 2000000 --warmup 10000 \
          --seed $((42 + r)) --nkeys 1024 --zipf 0.0 --pktlen-min 64 \
          --pktlen-max 256 --fuel 65536 --exp e12_jit_throughput \
          --out "$RES/e12_thr_${p}_${m}_r${r}.json"
    done
  done
done

log_block "e12_jit_e5 (${REPS} reps)"
for r in $(seq 1 "$REPS"); do
  for t in 1 2 4 8; do
    for z in 0.0 0.9 1.2; do
      for m in tx-elide vanilla 2pl; do
        EL=""; [ "$m" = "tx-elide" ] && EL="--elide workloads/flowstats.elide"
        # shellcheck disable=SC2086
        bin/ktxbench --prog workloads/flowstats.kbin $EL --mode "$m" --jit \
            --measure throughput --threads "$t" --iters 1000000 \
            --warmup 10000 --seed $((42 + r)) --nkeys 1024 --zipf "$z" \
            --pktlen-min 64 --pktlen-max 256 --fuel 65536 \
            --exp e12_jit_contention \
            --out "$RES/e12_e5_${t}t_z${z}_${m}_r${r}.json"
      done
    done
  done
done

log_block "e12_jit_e3"
for pair in ctnat atomic; do
  for m in vanilla tx 2pl; do
    bin/ktxtorn --pair "$pair" --mode "$m" --jit --writers 4 --readers 2 \
        --ops-per-writer 1000000 --seed 42 --nkeys 512 \
        --workloads-dir workloads --out "$RES/e12_e3a_${pair}_${m}.json"
  done
done
declare -A LO=( [ctnat]=16 [atomic]=8 )
declare -A HI=( [ctnat]=96 [atomic]=56 )
for pair in ctnat atomic; do
  for m in sfi tx 2pl; do
    bin/ktxtorn --pair "$pair" --mode "$m" --jit --writers 4 --readers 0 \
        --ops-per-writer 500000 --seed 42 --nkeys 512 \
        --fuel-lo "${LO[$pair]}" --fuel-hi "${HI[$pair]}" \
        --workloads-dir workloads --out "$RES/e12_e3b_${pair}_${m}.json"
  done
done

log_block "e12_jit_policy"
for vec in conflict fuel; do
  FUELARG=""; [ "$vec" = "fuel" ] && FUELARG="--fuel 900"
  for m in sfi tx tx-elide 2pl; do
    for d in pass drop; do
      for rr in 0 4; do
        [ "$rr" != "0" ] && [ "$m" = "sfi" ] && continue
        [ "$rr" != "0" ] && [ "$m" = "2pl" ] && continue
        # shellcheck disable=SC2086
        bin/ktxpolicy --prog workloads/firewall.kbin \
            --elide workloads/firewall.elide --mode "$m" --vector "$vec" \
            --jit $FUELARG --attackers 4 --legit 4 --ops 200000 \
            --default "$d" --retries "$rr" --seed 42 \
            --out "$RES/e12_e9_${vec}_${m}_${d}_r${rr}.json"
      done
    done
  done
done

log_block "done"
echo "run_jit.sh: complete; results in $RES"
