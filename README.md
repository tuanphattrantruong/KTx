# KTx: abort-safe, serializable transactions across eBPF maps

KTx is a userspace prototype that makes one invocation of an eBPF-subset
program an all-or-nothing, conflict-serializable transaction over the maps it
touches. Effectful helpers no longer mutate shared state when they are called:
they append to a per-invocation effect log with read-your-writes, and a
commit-time optimistic-concurrency protocol validates the read set under
striped per-map versions and applies the log, or aborts leaving no trace.
Because every guard, fuel check and log indirection is enforced at run time, an
offline analyzer can *remove* them where it can prove them unnecessary, rather
than deciding whether the program is admitted at all.

The artifact contains the two execution engines (a C11 interpreter and an
AArch64 template JIT), the transactional layer, three comparison baselines, the
elision analyzer and its certificate checkers, the workload programs, and every
experiment harness and analysis script.

## Requirements

- A C11 compiler (`clang` or `gcc`) with pthreads.
- Python 3. No third-party packages are used.
- AArch64 for the JIT arm. The interpreter arm is portable, and the JIT
  degrades to it automatically elsewhere.
- macOS or Linux. No kernel modules, no root, no network at run time.
- An 8-thread machine is enough; the scaling harnesses go to 32 threads.
- ~100 MB of disk, plus ~1 GB if the corpus survey is re-run against freshly
  fetched sources.
- `clang` with a BPF backend only to rebuild the three C workloads. Their
  compiled bytecode ships, so this is not needed to reproduce anything.

## Build and test

    make all && make test      # 55 + 154 + 336 checks

`make test` runs three suites: `test_vm` (decoder, interpreter, loader),
`test_ktx` (effect log, read-your-writes, clean-shadow detection, commit and
abort protocol, retry policy), and `test_jit`, a differential harness that
replays identical packet streams through matched interpreting and JIT
environments and compares, per invocation, status, verdict, fuel charged and
log-record count, and at stream end the byte contents of every map. It covers
14 programs across 7 modes, abort-inducing fuel budgets, and 24 generated
programs exercising every ALU64, ALU32, jump and memory opcode in the subset
over random registers and immediates.

An optional external comparison adds a ubpf arm to the engine calibration:

    make UBPF_DIR=/path/to/ubpf UBPF_LIB=/path/to/libubpf.a bin/ktxengine

## Layout

- `src/vm/` — decoder, loader and the eBPF-subset interpreter
  (`vm_core.inc` is compiled twice, with and without the fuel check).
- `src/ktx/` — the transactional layer: effect log and arena (`log.c`),
  maps (`map.c`), helper ABI (`helpers.c`), the commit protocol (`commit.c`),
  and `twopl.c`, the cross-map-locking strawman. The `coarse` mode keeps redo
  and abort semantics while holding one environment lock across the invocation;
  `p2pl` is the deadlock-free predeclared-map two-phase-locking baseline.
- `src/jit/` — the AArch64 template JIT. It consumes the same decoded streams,
  calls the same helper ABI and ends at the same commit protocol, so a matched
  pair of measurements differs in exactly one variable.
- `src/elide/elide.py` — the offline range-analysis guard-elision pass that
  emits the `.elide` sidecars.
- `src/bench/` — the measurement binaries.
- `src/tests/`, `tests/progs/` — unit and differential tests, plus negative
  programs that must be rejected or must trap.

- `tools/asm.py` — assembler for the `.S` workloads; emits eBPF encodings
  byte for byte.
- `tools/elf2kbin.py` — reads a BPF ELF object from clang's BPF backend and
  relocates it into the container format.
- `tools/model_check.py` — exhaustive state-space check of the commit protocol
  against a model mirroring `commit.c`, for both KTx and the 2PL strawman.
- `tools/ser_check.py` — offline conflict-serializability checker over recorded
  runtime histories.
- `tools/semantic_check.py` — digest-bound certificate checker: it re-derives
  typed transfer and loop-bound facts from the exact bytecode named by a
  certificate and admits it only when every submitted fact is entailed.
- `tools/profile_screen.py`, `tools/corpus_survey.py`,
  `tools/corpus_validate.py` — the source survey and its screening pass.

- `workloads/` — 9 hand-written programs plus 3 compiled from C by clang's BPF
  backend (sources in `workloads/c/`, up to 145 instructions and 5 maps), 2
  invariant-checking reader programs, and 3 helper-free kernels used for engine
  calibration. Each ships as `.kbin` bytecode with its `.elide` sidecar.
- `experiments/` — the harnesses, the analysis scripts, and
  `experiments/results/` with reference output from a previous run.
- `CERTIFICATE.md` — the sidecar and certificate format, and what each checker
  does and does not establish.

## Binaries

| Binary | Purpose |
|---|---|
| `ktxbench` | latency and throughput across workloads, modes and both arms |
| `ktxtorn` | cross-map invariant violations and torn keys under concurrency and injected aborts |
| `ktxpolicy` | abort-induced policy bypass, retry budgets and verdict defaults |
| `ktxengine` | engine calibration against ubpf and compiled C |
| `ktxobserver` | mixed-observer publication litmus |
| `ktxmicro` | the transaction API in isolation, with no bytecode |
| `ktxser` | runtime serializability histories for `ser_check.py` |

## Reproduce

    REPS=3 experiments/run_v2.sh              # timed matrix
    REPS=3 experiments/run_cprogs.sh          # compiled workloads, audit, calibration
    experiments/run_offline.sh                # static, exhaustive, corpus
    REPS=3 experiments/run_e15_coarse.sh      # 1-32 thread abort-safe baseline
    REPS=3 experiments/run_e16_observer.sh    # mixed userspace observer
    python3 experiments/run_e17_adaptive.py   # adaptive contention, fairness
    python3 experiments/run_e18_p2pl.py       # predeclared-map 2PL baseline
    python3 experiments/run_e19_micro_repeats.py
    python3 experiments/run_e21_principal_budgets.py
    make semantic-check                       # certificate checker
    python3 experiments/analyze_v2.py

The full matrix takes roughly 60 minutes at `REPS=3`.

The corpus survey needs a directory of checked-out repositories:

    CORPUS=<dir-of-checkouts> experiments/run_offline.sh

## Results

Every binary writes a JSON envelope carrying machine, compiler, timer
calibration, seed and command line alongside its metrics. `analyze_v2.py`
recomputes every derived quantity from those stored raw values, names the
source file for each, and writes `experiments/results/v2/summary_v2.json` and
`experiments/derived/v2_*.csv`. `experiments/RESULTS_SUMMARY_V2.md` summarises
the reference run.

The reference `experiments/results/` shipped here omits the raw
serializability histories (`results/v2/e8_*.json`, about 600 MB). They are
intermediate outputs of `ktxser` and are regenerated by `run_offline.sh`.

## Metrics and expected variation

The harnesses report per-invocation latency, throughput and committed goodput,
abort rates by cause, cross-map invariant violations, torn keys, elision rates
and audit faults, policy-bypass and false-drop rates, and memory footprint.

Absolute nanosecond figures are machine-specific and will not match the
reference run. The contrasts are not: zero versus non-zero invariant violations
and torn keys, the sign and rough magnitude of every mode ordering, the
serializability verdicts, and the audit's zero fault count reproduce on every
run. Multi-threaded cells vary by several percent between runs; the analyzer
reports a median and range for each and labels any comparison inside that range
as parity.

Timed cells are run three times with different seeds, and all configurations of
a cell run back-to-back in the innermost loop, so drift cannot align with the
comparisons being drawn.

## Scope

This is a userspace prototype. There is no Linux verifier, JIT or
attachment-point integration, and no Mpps, NIC or in-kernel claim. Bounds
guards and fuel enforce two properties for this custom VM; every other
obligation — initialized state, reference lifetime, context rules, locking, and
each feature outside the supported profile — remains with a separate static
checker. Per-CPU maps are applied thread-locally and lie outside the
serializability guarantee. Tail calls, kfuncs, timers, dynptrs, references,
spin locks, sleepable programs, callbacks and direct mutable pointers are
unsupported.
