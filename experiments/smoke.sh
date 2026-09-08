#!/bin/bash
# smoke.sh - fast sanity pass (<30 s): build, assemble + elide every
# workload, then a 1000-iteration ktxbench latency run of every workload x
# every mode. Asserts exit 0 everywhere and, for tx modes, zero guard/helper
# aborts (all ten workloads are dynamically correct programs).
set -euo pipefail

cd "$(dirname "$0")/.."
SMK=experiments/results/smoke
mkdir -p "$SMK"

ALL10="pktcount flowstats tokenbucket maglev ctnat ctnat_reader pktrewrite loopy atomic_demo atomic_reader"
MODES="vanilla sfi tx tx-elide"

echo ">>> smoke: build"
make all

echo ">>> smoke: assemble + elide"
for p in $ALL10; do
    python3 tools/asm.py "workloads/$p.S" -o "workloads/$p.kbin"
    python3 src/elide/elide.py "workloads/$p.kbin" \
        -o "workloads/$p.elide" --json "workloads/$p.elide.json"
done

echo ">>> smoke: assembler self-test"
python3 tools/asm.py --selftest > /dev/null

echo ">>> smoke: 1000-iteration run of every workload x mode"
fail=0
for p in $ALL10; do
    for m in $MODES; do
        EL=""
        [ "$m" = "tx-elide" ] && EL="--elide workloads/$p.elide"
        out="$SMK/smoke_${p}_${m}.json"
        # shellcheck disable=SC2086
        if ! bin/ktxbench --prog "workloads/$p.kbin" $EL --mode "$m" \
                --measure latency --threads 1 --iters 1000 --warmup 100 \
                --seed 42 --nkeys 64 --batch 32 --exp smoke --out "$out"; then
            echo "SMOKE FAIL: ktxbench exited nonzero for $p/$m"
            fail=1
            continue
        fi
        verdict=$(python3 - "$out" "$m" <<'PYEOF'
import json, sys
run = json.load(open(sys.argv[1]))["runs"][0]
mode = sys.argv[2]
if "error" in run:
    print("error:", run["error"]); sys.exit(0)
mt = run["metrics"]
problems = []
if mode in ("tx", "tx-elide"):
    if mt.get("commits", 0) == 0:
        problems.append("no commits")
    for k in ("aborts_guard", "aborts_helper", "aborts_fuel",
              "aborts_conflict", "aborts_capacity"):
        if mt.get(k, 0) != 0:
            problems.append(f"{k}={mt[k]}")
print("; ".join(problems) if problems else "ok")
PYEOF
)
        if [ "$verdict" != "ok" ]; then
            echo "SMOKE FAIL: $p/$m: $verdict"
            fail=1
        else
            echo "  ok: $p/$m"
        fi
    done
done

if [ "$fail" -ne 0 ]; then
    echo "SMOKE: FAILURES (see above)"
    exit 1
fi
echo "SMOKE: ALL PASS"
