#!/bin/bash
# run_v2.sh — the KTx experiment matrix.
#
# Two things this script does that the first version did not, both about
# measurement validity rather than about KTx:
#
#  1. *Every* configuration of a cell — five execution modes, the
#     shadow-diffing ablation, and the interpreter/JIT arms — is run
#     back-to-back inside the innermost loop, so slow drift in machine
#     state (thermal, scheduler, background indexing) cannot line up with
#     the comparisons we draw.  Repeats are the outermost loop.
#  2. Each cell is repeated REPS times with a different seed, and the
#     analyzer reports median [min, max] rather than a single number.
#
# Honesty: this script never writes a metric itself; every number comes
# from the harness binaries and analyzers it invokes.
set -euo pipefail
cd "$(dirname "$0")/.."
RES=experiments/results/v2
mkdir -p "$RES"
REPS=${REPS:-3}

log_block() { { echo ""; echo "=== $1 ==="; date; } >> "$RES/run_log.txt";
              echo ">>> $1"; }

W9="pktcount flowstats tokenbucket maglev ctnat pktrewrite loopy atomic_demo firewall"
ALL="pktcount flowstats tokenbucket maglev ctnat ctnat_reader pktrewrite loopy atomic_demo atomic_reader firewall"

# tag:mode:extra-flags   (tag is what appears in the result file name)
CONFIGS="\
vanilla:vanilla: \
sfi:sfi: \
tx:tx: \
tx-elide:tx-elide:E \
2pl:2pl: \
txnd:tx:--no-shadow-diff \
tx-elidend:tx-elide:E,--no-shadow-diff \
jvanilla:vanilla:--jit \
jsfi:sfi:--jit \
jtx:tx:--jit \
jtx-elide:tx-elide:E,--jit \
j2pl:2pl:--jit"

flags_for() {  # $1 = spec field 3, $2 = workload -> echoes the flags
    local spec="$1" w="$2" out=""
    local IFS=','
    for f in $spec; do
        case "$f" in
            E)  out="$out --elide workloads/$w.elide" ;;
            "") ;;
            *)  out="$out $f" ;;
        esac
    done
    echo "$out"
}

log_block "build"
make all

log_block "assemble+elide"
for p in $ALL; do
    python3 tools/asm.py "workloads/$p.S" -o "workloads/$p.kbin"
    python3 src/elide/elide.py "workloads/$p.kbin" \
        -o "workloads/$p.elide" --json "workloads/$p.elide.json"
done

# ---- E1 latency + throughput, all configs adjacent in time --------------
log_block "e1 (${REPS} reps x 12 configs)"
for r in $(seq 1 "$REPS"); do
  for p in $W9; do
    for c in $CONFIGS; do
      tag="${c%%:*}"; rest="${c#*:}"; mode="${rest%%:*}"; xf="${rest#*:}"
      FL=$(flags_for "$xf" "$p")
      # shellcheck disable=SC2086
      bin/ktxbench --prog "workloads/$p.kbin" $FL --mode "$mode" \
          --measure latency --threads 1 --iters 1000000 --warmup 100000 \
          --seed $((42 + r)) --nkeys 1024 --zipf 0.0 --pktlen-min 64 \
          --pktlen-max 256 --fuel 65536 --batch 32 --exp e1_latency \
          --out "$RES/e1_lat_${p}_${tag}_r${r}.json"
      # shellcheck disable=SC2086
      bin/ktxbench --prog "workloads/$p.kbin" $FL --mode "$mode" \
          --measure throughput --threads 8 --iters 2000000 \
          --warmup 200000 --seed $((42 + r)) --nkeys 1024 --zipf 0.0 \
          --pktlen-min 64 --pktlen-max 256 --fuel 65536 \
          --exp e1_throughput --out "$RES/e1_thr_${p}_${tag}_r${r}.json"
    done
  done
done

# ---- E2 commit/abort/append microbench ----------------------------------
log_block "e2_micro"
bin/ktxmicro --out "$RES/e2_micro.json"

# ---- E3a torn updates under concurrent readers --------------------------
log_block "e3a"
for r in 1 2; do
  for pair in ctnat atomic; do
    for m in vanilla tx 2pl; do
      for arm in "" "--jit"; do
        tag="$m"; [ -n "$arm" ] && tag="j$m"
        # shellcheck disable=SC2086
        bin/ktxtorn --pair "$pair" --mode "$m" $arm --writers 4 --readers 2 \
            --ops-per-writer 1000000 --seed $((42 + r)) --nkeys 512 \
            --workloads-dir workloads \
            --out "$RES/e3a_${pair}_${tag}_r${r}.json"
      done
    done
  done
done

# ---- E3b abort injection ------------------------------------------------
log_block "e3b"
for pair in ctnat atomic; do
    case "$pair" in
        ctnat)  LO=16; HI=96 ;;
        atomic) LO=8;  HI=56 ;;
    esac
    for m in sfi tx 2pl; do
      for arm in "" "--jit"; do
        tag="$m"; [ -n "$arm" ] && tag="j$m"
        # shellcheck disable=SC2086
        bin/ktxtorn --pair "$pair" --mode "$m" $arm --writers 4 --readers 0 \
            --ops-per-writer 500000 --seed 42 --nkeys 512 \
            --fuel-lo "$LO" --fuel-hi "$HI" --workloads-dir workloads \
            --out "$RES/e3b_${pair}_${tag}.json"
      done
    done
done

# ---- E5 OCC contention --------------------------------------------------
log_block "e5 (${REPS} reps)"
for r in $(seq 1 "$REPS"); do
  for t in 1 2 4 8; do
    for z in 0.0 0.9 1.2; do
      for m in tx-elide vanilla 2pl; do
        for arm in "" "--jit"; do
          tag="$m"; [ -n "$arm" ] && tag="j$m"
          EL=""; [ "$m" = "tx-elide" ] && EL="--elide workloads/flowstats.elide"
          # shellcheck disable=SC2086
          bin/ktxbench --prog workloads/flowstats.kbin $EL --mode "$m" $arm \
              --measure throughput --threads "$t" --iters 1000000 \
              --warmup 100000 --seed $((42 + r)) --nkeys 1024 --zipf "$z" \
              --pktlen-min 64 --pktlen-max 256 --fuel 65536 \
              --exp e5_contention \
              --out "$RES/e5_${t}t_z${z}_${tag}_r${r}.json"
        done
      done
    done
  done
done

# ---- E8 serializability check -------------------------------------------
log_block "e8_serializability"
for cfg in "8 32 0.0" "8 32 1.2" "4 8 0.0" "2 64 0.0"; do
    set -- $cfg
    bin/ktxser --threads "$1" --keys "$2" --zipf "$3" \
        --tx-per-thread 250000 --mode tx --seed 42 \
        --out "$RES/e8_tx_${1}t_${2}k_z${3}.json"
done
bin/ktxser --threads 8 --keys 32 --zipf 0.0 --tx-per-thread 250000 \
    --mode direct --seed 42 --out "$RES/e8_direct_8t_32k_z0.0.json"

# ---- E9 abort-induced policy bypass -------------------------------------
log_block "e9_policy"
for vec in conflict fuel; do
  FUELARG=""; [ "$vec" = "fuel" ] && FUELARG="--fuel 900"
  for m in sfi tx tx-elide 2pl; do
    for d in pass drop; do
      for rr in 0 1 2 4 8; do
        if [ "$rr" != "0" ]; then
          [ "$m" = "sfi" ] && continue
          [ "$m" = "2pl" ] && continue
        fi
        for arm in "" "--jit"; do
          tag="$m"; [ -n "$arm" ] && tag="j$m"
          # shellcheck disable=SC2086
          bin/ktxpolicy --prog workloads/firewall.kbin \
              --elide workloads/firewall.elide --mode "$m" --vector "$vec" \
              $arm $FUELARG --attackers 4 --legit 4 --ops 200000 \
              --default "$d" --retries "$rr" --seed 42 \
              --out "$RES/e9_${vec}_${tag}_${d}_r${rr}.json"
        done
      done
    done
  done
done

log_block "done-timed"
echo "run_v2.sh: timed matrix complete; results in $RES"
