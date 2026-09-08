#!/bin/bash
# run_all.sh - execute the full KTx experiment matrix (DESIGN.md section 9).
# Runs from the project root regardless of invocation directory.
# Every experiment block appends `date` + its name to results/run_log.txt.
# Honesty: this script never writes a metric itself; all numbers come from
# the harness binaries / analyzers it invokes.
set -euo pipefail

cd "$(dirname "$0")/.."
RES=experiments/results
mkdir -p "$RES"

log_block() {
    { echo ""; echo "=== $1 ==="; date; } >> "$RES/run_log.txt"
    echo ">>> $1"
}

W8="pktcount flowstats tokenbucket maglev ctnat pktrewrite loopy atomic_demo"
ALL10="pktcount flowstats tokenbucket maglev ctnat ctnat_reader pktrewrite loopy atomic_demo atomic_reader"
MODES="vanilla sfi tx tx-elide"

log_block "build"
make all

log_block "assemble+elide"
for p in $ALL10; do
    python3 tools/asm.py "workloads/$p.S" -o "workloads/$p.kbin"
    python3 src/elide/elide.py "workloads/$p.kbin" \
        -o "workloads/$p.elide" --json "workloads/$p.elide.json"
done

# ---- E1 latency: W8 x M4, 1 thread, 1M iters + 100k warmup ---------------
log_block "e1_lat"
for p in $W8; do
    for m in $MODES; do
        EL=""
        [ "$m" = "tx-elide" ] && EL="--elide workloads/$p.elide"
        # shellcheck disable=SC2086
        bin/ktxbench --prog "workloads/$p.kbin" $EL --mode "$m" \
            --measure latency --threads 1 --iters 1000000 --warmup 100000 \
            --seed 42 --nkeys 1024 --zipf 0.0 --pktlen-min 64 \
            --pktlen-max 256 --fuel 65536 --batch 32 --exp e1_latency \
            --out "$RES/e1_lat_${p}_${m}.json"
    done
done

# ---- E1 throughput: W8 x M4, 8 threads x 2M -------------------------------
log_block "e1_thr"
for p in $W8; do
    for m in $MODES; do
        EL=""
        [ "$m" = "tx-elide" ] && EL="--elide workloads/$p.elide"
        # shellcheck disable=SC2086
        bin/ktxbench --prog "workloads/$p.kbin" $EL --mode "$m" \
            --measure throughput --threads 8 --iters 2000000 \
            --warmup 10000 --seed 42 --nkeys 1024 --zipf 0.0 \
            --pktlen-min 64 --pktlen-max 256 --fuel 65536 \
            --exp e1_throughput --out "$RES/e1_thr_${p}_${m}.json"
    done
done

# ---- E2 commit/abort/append microbench (package-1 binary) -----------------
log_block "e2_micro"
bin/ktxmicro --out "$RES/e2_micro.json"

# ---- E3a torn updates under concurrent readers ----------------------------
log_block "e3a"
for pair in ctnat atomic; do
    for m in vanilla tx; do
        bin/ktxtorn --pair "$pair" --mode "$m" --writers 4 --readers 2 \
            --ops-per-writer 1000000 --seed 42 --nkeys 512 \
            --workloads-dir workloads --out "$RES/e3a_${pair}_${m}.json"
    done
done

# ---- E3b abort injection: calibrate fuel window, then full runs -----------
log_block "e3b"
CAL_LO=0
CAL_HI=0
calibrate() {
    # sweep <=5 short runs until abort fraction in [0.2, 0.8]
    local pair=$1
    local lo=16
    local hi=96
    local ok=""
    for i in 1 2 3 4 5; do
        local out="$RES/e3b_cal_${pair}_try${i}.json"
        bin/ktxtorn --pair "$pair" --mode sfi --writers 4 --readers 0 \
            --ops-per-writer 12500 --seed 42 --nkeys 512 \
            --fuel-lo "$lo" --fuel-hi "$hi" --workloads-dir workloads \
            --out "$out"
        local frac verdict
        frac=$(python3 -c "import json;print(json.load(open('$out'))['runs'][0]['metrics']['abort_fraction'])")
        verdict=$(python3 -c "f=$frac;print('ok' if 0.2<=f<=0.8 else ('low' if f<0.2 else 'high'))")
        echo "e3b calibration $pair try $i: window [$lo,$hi] abort_fraction=$frac -> $verdict" >> "$RES/run_log.txt"
        if [ "$verdict" = "ok" ]; then ok=1; break; fi
        if [ "$verdict" = "low" ]; then
            # too few fuel aborts -> window too generous -> shift down
            hi=$(( (lo + hi) / 2 ))
            lo=$(( lo / 2 ))
            [ $lo -lt 2 ] && lo=2
            [ $hi -lt $((lo + 8)) ] && hi=$((lo + 8))
        else
            # too many aborts -> window too small -> shift up
            lo=$(( (lo + hi) / 2 ))
            hi=$(( hi * 2 ))
        fi
    done
    if [ -z "$ok" ]; then
        echo "e3b calibration $pair: target range NOT reached in 5 runs; using last window [$lo,$hi]" >> "$RES/run_log.txt"
    else
        echo "e3b calibration $pair: chosen fuel window [$lo,$hi]" >> "$RES/run_log.txt"
    fi
    CAL_LO=$lo
    CAL_HI=$hi
}
for pair in ctnat atomic; do
    calibrate "$pair"
    for m in sfi tx; do
        bin/ktxtorn --pair "$pair" --mode "$m" --writers 4 --readers 0 \
            --ops-per-writer 500000 --seed 42 --nkeys 512 \
            --fuel-lo "$CAL_LO" --fuel-hi "$CAL_HI" \
            --workloads-dir workloads --out "$RES/e3b_${pair}_${m}.json"
    done
done

# ---- E5 OCC contention: flowstats, threads x zipf x {tx-elide, vanilla} ---
log_block "e5"
for t in 1 2 4 8; do
    for z in 0.0 0.9 1.2; do
        for m in tx-elide vanilla; do
            EL=""
            [ "$m" = "tx-elide" ] && EL="--elide workloads/flowstats.elide"
            # shellcheck disable=SC2086
            bin/ktxbench --prog workloads/flowstats.kbin $EL --mode "$m" \
                --measure throughput --threads "$t" --iters 1000000 \
                --warmup 10000 --seed 42 --nkeys 1024 --zipf "$z" \
                --pktlen-min 64 --pktlen-max 256 --fuel 65536 \
                --exp e5_contention \
                --out "$RES/e5_${t}t_z${z}_${m}.json"
        done
    done
done

# ---- E4: merge per-workload elision stats into one results file -----------
log_block "e4_merge"
python3 - "$RES" <<'PYEOF'
import glob, json, sys, time
res = sys.argv[1]
runs = []
for p in sorted(glob.glob('workloads/*.elide.json')):
    with open(p) as f:
        runs.append(json.load(f))
out = {
    "experiment": "e4_elision",
    "meta": {
        "date_iso": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        "note": ("static analysis output of src/elide/elide.py on this "
                 "machine; merged verbatim from workloads/*.elide.json by "
                 "run_all.sh; no runtime timing involved"),
        "seed": 42,
        "cmdline": "run_all.sh e4_merge",
    },
    "runs": runs,
}
with open(res + '/e4_elision.json', 'w') as f:
    json.dump(out, f, indent=2)
    f.write('\n')
print(f"e4_elision.json: merged {len(runs)} programs")
PYEOF

# ---- analyze --------------------------------------------------------------
log_block "analyze"
python3 experiments/analyze.py

log_block "done"
echo "run_all.sh: complete; results in $RES"
