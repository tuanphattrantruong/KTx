# KTx Prototype — Audited Results Summary (ground truth for paper writers)

Audit date: 2026-08-29. Auditor: independent adversarial results audit (this
file supersedes any earlier prose about the numbers; cite from here or from
the raw JSON files it names).

- Machine: Apple M1 (4P+4E, 8 logical CPUs, no pinning), macOS Darwin 25,
  clang 12.0.5, timer `mach_absolute_time` (tick 41.67 ns; all latency
  numbers use batch-of-32 timing).
- Every number below was read out of a results JSON in
  `experiments/results/` produced by binaries run on this machine
  (2026-08-29, seed 42; per-file `meta` blocks carry date/host/cmdline).
- Audit actions: (a) full internal-consistency sweep over all 100 result
  files (units, counter balances, derived-value recomputation) — all pass
  after the E3b fix below; (b) independent re-runs of E3a (all 4 configs),
  E3b (all 4), 8 E1-latency configs, 5 E1-throughput configs, E5 hot cell,
  and all of E2 — see "Reproducibility" below; (c) both unit-test binaries
  pass (test_vm 55/55, test_ktx 111/111).

## Corrections made during the audit (2026-08-29, logged in run_log.txt)

1. **E3b accounting fix (torn.c).** In the original E3b tx runs, writer OCC
   conflict aborts were counted in `attempts`/`abort_fraction` but appeared
   in no per-cause counter, so `attempts != commits + aborts_fuel +
   aborts_other` (gap 16,871 ctnat / 6,841 atomic). `src/bench/torn.c` now
   counts non-fuel aborts into `aborts_other`; all four
   `e3b_*_{sfi,tx}.json` files were regenerated with identical parameters.
   Qualitative results unchanged (SFI tears state, TX never does); the
   ctnat-SFI torn-key count moved 48 → 45 (run-to-run variance of a race).
2. **E2 characterization fix (analyze.py).** The raw E2 curves include
   `tx_begin` + k log appends per rep (stated in `e2_micro.json` "notes").
   The old summary fit a straight line to the *raw* commit curve (slope
   143 ns/rec, intercept −1362 ns) — a misleading fit to a superlinear
   curve, and it made abort look linear in k. `analyze.py` now derives
   commit-only and abort-only as (op − append), fits the workload-realistic
   range k ≤ 16 with R², and records a linearity caveat. `summary.json`
   regenerated.
3. (Pre-audit, by the evaluator, verified here: `analyze.py` E2 extraction
   accepts the `log_k` field `ktxmicro` writes — one-line fix, benign.)

## Claims-to-evidence table (DESIGN.md §10) — final verified numbers

| # | Paper claim | Verdict | Verified evidence (source files) |
|---|---|---|---|
| C1 | Cross-map torn updates occur under per-map-atomic concurrency; KTx eliminates them | **SUPPORTED** | E3a, 4 writers + 2 readers, 4M writer ops: vanilla ctnat **4,241** violations / 3.29M reader commits; vanilla atomic **1,864,257** / 2.28M. tx: **0** violations in both (2.38M / 2.08M reader commits; 45,359 / 34,672 reader conflict-aborts = prevented torn reads). Re-run reproduced: 3,962 / 1,844,054 / 0 / 0. (`e3a_{ctnat,atomic}_{vanilla,tx}.json`) |
| C2 | SFI/cancellation without rollback leaves torn state on abort; KTx aborts leave state untouched | **SUPPORTED** | E3b, 2M attempts, calibrated fuel windows (ctnat [16,96] → 25.9% aborts; atomic [8,56] → 44.0%): SFI leaves **45/512** (ctnat) and **256/256** (atomic) torn keys; TX leaves **0** in both at matched abort fractions (26.8% / 44.5%). (`e3b_{ctnat,atomic}_{sfi,tx}.json`, regenerated post-fix) |
| C3 | KTx overhead vs verified-native baseline is modest and quantified honestly | **SUPPORTED, with framing care** | E1 latency p50 (1 thread, ktx_run only): sfi +9.5–30.8%, tx **+13.1–134%**, tx-elide **+5.1–112%** vs vanilla, workload-dependent (absolute vanilla p50 32.6–1410 ns). 8-thread throughput loss: tx 7.8–49.8%, tx-elide 0–47.6%. "Modest" is defensible for guard cost and for read-mostly / intent-based workloads (pktrewrite +5.1% lat, maglev-elide +40% lat / ~0% thr); write-through workloads pay ~2× latency in tx modes. Cite per-workload, not one blended number. (`e1_lat_*.json`, `e1_thr_*.json`, `summary.json`) |
| C4 | Guard elision recovers most of the guard+fuel cost; unverifiable programs still run | **SUPPORTED** | Measured guard+fuel cost = sfi − vanilla; elision recovery = tx − tx-elide (both on lat p50). pktcount 9.1/10.4 ns (88%), flowstats 11.7/11.7 (100%), tokenbucket 11.7/13.0 (90%), ctnat 15.6/15.6 (100%), pktrewrite 44.3/44.3 (100%), atomic_demo 14.3/18.2 (79%), maglev 28.6 ns recovered vs 7.8 ns guard cost (>100%: RO-map validate-only elision also removes shadow-copy cost). loopy (unverifiable TLV walker): analyzer proves nothing hot (85% of guards elided are cold; fuel kept), tx-elide == tx (0% recovery, by design), still loads and runs at +13.1% lat vs vanilla. E4: 9/10 programs 100% tx-guard elision + fuel proven; RO maps proven: maglev `table`, both reader pairs. (`e4_elision.json` + E1 files) |
| C5 | Commit cost scales linearly in log size; abort is O(1) and cheap | **PARTLY SUPPORTED — scope it** | E2 (200k reps/point, k = 1..256): abort-only (abort − append) is **flat 0–8 ns for all k** — genuinely O(1). Commit-only (commit − append) is **near-linear only for k ≤ 16**: ~43.8 ns/record (fit, R² = 0.990); per-record cost then grows ~23 → 112 ns/rec across k = 1 → 256 (cache/stripe-set effects). All bytecode workloads log ≤ ~8 records, so the small-k regime is the relevant one — but the paper must not claim linearity across the full range. Raw curves include the k appends; cite the (op − append) derivation in `summary.json` `e2_fit`. (`e2_micro.json`) |
| C6 | OCC sustains goodput with characterized abort rates under contention/skew | **SUPPORTED** | E5 (flowstats): tx-elide abort rate rises smoothly with threads × skew: 0% (1t) → 1.7% (8t, θ=0) → 3.4% (8t, θ=0.9) → **9.2%** (8t, θ=1.2); goodput 9.66M commits/s at the hottest cell vs 11.2M at 8t/θ=0. Lock-based vanilla reference: 16.2–17.2M ops/s at 8t (tx-elide reaches 56–65% of it at 8t, 83–84% at ≤4t). (`e5_*t_z*_*.json`) |
| C7 | Multi-map atomic sections are a usable programmer primitive | **SUPPORTED** | atomic pair rows of C1/C2: invariant A[k]+B[k]=1000 violated 1.86M times under vanilla concurrent readers and torn in 256/256 keys under SFI aborts; **zero** violations and zero torn keys under tx. `atomic_demo.S` is the programming-model exhibit. (`e3a_atomic_*.json`, `e3b_atomic_*.json`) |
| C8 | Per-CPU maps commit lock-free (no scalability penalty for the counter pattern) | **SUPPORTED** | E1-thr pktcount, 8t × 2M: vanilla 16.65 Mops/s, tx 15.36 (−7.8%), tx-elide 15.60 (−6.3%), **zero** conflict aborts in any mode. (`e1_thr_pktcount_*.json`) |

## Per-experiment summaries

### E1 — Latency and throughput, 8 workloads × 4 modes

Latency (1 thread, 1M timed + 100k warmup, batch-of-32, packet generation
outside the timed region, `timed_region: ktx_run_only`): vanilla p50 ranges
32.6 ns (maglev) to 1410 ns (loopy). SFI guards+fuel add 9.5–30.8%. Full
transactions (tx) add 13.1–134%; the cost concentrates in write-through
workloads (atomic_demo +134%, maglev +128% — the latter because *every*
lookup shadow-copies and writes back without dirty tracking). tx-elide
removes ~80–100% of the measured guard+fuel cost on all 7 verifiable
workloads (see C4) and additionally removes shadow-copy cost on proven
read-only maps (maglev tx +128% → tx-elide +40%). Residual tx-elide
overhead is the effect-log + OCC-commit cost itself. Throughput (8 threads
× 2M): losses are smaller than the latency deltas (tx-elide 0–47.6%)
because ~240 ns/op of trace synthesis sits inside the throughput pipeline
(see Limitations 2) and because commit work overlaps across cores.
Latency-mode numbers are the ones to cite for per-invocation overhead.

### E2 — Commit/abort/append microbenchmark

`ktxmicro`, hash map 4096 (8 B key / 16 B value), 256 keys pre-populated
(steady state), 200k reps/point, k ∈ {1..256}. Each timed rep = begin + k
appends + op; commit-only and abort-only derive as (op − append). Verified
findings: append ≈ 12 ns/record at small k; commit-only ≈ 27 ns at k=1,
~43.8 ns/record fit over k ≤ 16 (R² 0.990), rising to ~112 ns/record at
k=256 (superlinear tail); abort-only is flat 0–8 ns independent of k. The
headline shape "abort ≪ commit, commit grows with log size" is real; the
precise claim should be "near-linear in the workload range k ≤ 16, with
per-record cost growing at large k". Re-run reproduced every point within
one timer tick except commit k=1 (39.1 vs 48.2 ns — sub-tick regime).

### E3a — Torn updates under concurrent readers

4 writers × 1M successful ops + 2 invariant-checker readers, pairs
{ctnat, atomic}. Vanilla (per-bucket-locked direct writes, the eBPF
analogue): readers committed observations of broken cross-map invariants —
4,241 (ctnat) and 1,864,257 (atomic; ~82% of reader commits). TX: **zero**
violations over 2.4M / 2.1M reader commits; the OCC machinery instead
surfaced 45k / 35k reader conflict-aborts (prevented torn reads) and 113k /
83k writer retries. Both vanilla counts and both zeros reproduced on
re-run (3,962 / 1,844,054 / 0 / 0).

### E3b — Abort injection (torn state after cancellation)

4 writers, no readers, per-invocation fuel drawn uniform from a calibrated
window so a fraction of invocations dies between the two map updates;
post-run quiesced scan counts invariant-violating keys. SFI (cancellation
without rollback): 45/512 keys torn (ctnat, abort fraction 0.259) and
256/256 (atomic, 0.440). TX at matched abort fractions (0.268 / 0.445):
**0 torn keys** in both. This is the KFlex-differentiator result. Files
were regenerated after the accounting fix (correction 1); TX writer OCC
conflicts are now visible as `aborts_other` (17,089 ctnat / 7,032 atomic)
and all counters balance.

### E4 — Guard elision (static analysis)

`elide.py` on all 10 programs: 9/10 get 100% tx-mode guard elision and a
proven fuel bound (16–162 instructions); read-only maps proven for maglev
(`table`) and both reader programs (both maps each). loopy — the
deliberately unverifiable TLV walker — gets 85% of guards elided (the cold
ones), fuel *not* elidable, `analysis_complete: true`. Analysis cost is
0.19–0.89 ms/program. Elision is physically real (pre-decoded handler
arrays, unguarded variants), and its effect is measured in E1, not assumed.

### E5 — OCC under contention and skew

flowstats, threads {1,2,4,8} × Zipf θ {0, 0.9, 1.2}, tx-elide vs a
lock-based vanilla reference. Abort rate grows monotonically with both
axes: ≤1% up to 2 threads, 3.1% at 4t/θ=1.2, 9.2% at 8t/θ=1.2. Goodput
scales 2.96M (1t) → 11.2M commits/s (8t, θ=0) and degrades only ~14% from
θ=0 to θ=1.2 at 8t. The vanilla reference never aborts by construction
(stripe locks); tx-elide delivers 83–84% of its goodput at ≤4 threads,
56–65% at 8 threads (where commit-time cache-line traffic bites; note the
4P+4E asymmetry). Single run per cell — see Limitations 1.

## Reproducibility spot-checks performed in this audit

- E1 latency: 8 configs re-run in full (1M + 100k warmup). p50 identical to
  the stored (tick-quantized) value in 7/8; ctnat-sfi differed 1.1%.
- E1 throughput / E5: 6 eight-thread configs re-run; values within 5–10%
  of stored (direction and ordering of all mode comparisons preserved).
- E2: full re-run; all 27 points within one 1.30 ns batch-tick except
  commit k=1 (39.1 → 48.2 ns).
- E3a/E3b: all 8 configs re-run; both zeros exact, violation/torn counts
  within run-to-run variance of a data race (±7%).

## Honest limitations (must accompany any use of these numbers)

1. **Single run per matrix cell; multi-thread noise 5–10%.** E1-throughput
   and E5 cells are one run each; audit re-runs on the asymmetric M1 (no
   pinning) moved 8-thread numbers by 5–10%. All claimed effects are far
   larger than this, but sub-10% differences (e.g. maglev tx-elide
   "−0.18% vs vanilla") must be reported as **parity within noise**, never
   as a speedup.
2. **Throughput mode times the whole pipeline.** Packet synthesis (per-byte
   PRNG payload fill, ~240 ns/op measured as the 1-thread gap between
   throughput mode at 287.6 ns/op and latency mode at 44.3 ns/op for
   vanilla flowstats) is inside the throughput timed region (documented in
   bench.c). Throughput "loss %" therefore *understates* VM-relative
   overhead; latency mode isolates `ktx_run` and is the per-invocation
   overhead number.
3. **Tail metrics are batch-level.** The 41.67 ns timer tick forces
   batch-of-32 timing; p50/p99/p999 are nearest-rank percentiles over
   *batch means*, which smooths per-op tails. Do not present p999 as a
   per-invocation tail.
4. **E2 linearity is a small-k statement** (see C5). Per-record commit cost
   grows ~4× from k=1 to k=256; the raw stored curves also include the k
   appends per rep.
5. **Userspace interpreter, not a kernel or JIT.** The vanilla baseline is
   the same interpreter with guards compiled out — the right ablation
   baseline, but all overhead percentages are interpreter-relative;
   absolute ns and relative cost under a JIT/kernel would differ. No Mpps
   or in-kernel claims.
6. **E5 "vanilla" is a lock-based reference, not a contention-equivalent
   baseline.** It never aborts by construction; it bounds what a
   no-isolation design achieves and should be labeled "reference".
7. **tx mode (no elision) penalizes read-only workloads structurally**:
   without dirty tracking every lookup shadow-copy is written back at
   commit, so 8-thread read-only maglev shows 224k spurious conflicts in
   tx mode. This is an honest cost of the design; RO-map elision (tx-elide)
   removes it (0 conflicts, vanilla-parity throughput).
8. **E3 counts are race outcomes**, deterministic only in expectation:
   violation/torn-key counts vary run to run (e.g. ctnat SFI torn keys 48
   vs 45); the invariant results (zero vs non-zero) are stable across all
   runs performed.
9. **Workload scale is modest**: 1024 flows, 64–256 B synthetic packets,
   maps ≤ 4096 entries, log sizes ≤ ~8 records in real workloads. Claims
   about larger states extrapolate and must be flagged as such.

## File inventory (all under `experiments/results/`)

`e1_lat_<prog>_<mode>.json` ×32, `e1_thr_<prog>_<mode>.json` ×32,
`e2_micro.json`, `e3a_<pair>_<mode>.json` ×4,
`e3b_<pair>_<mode>.json` ×4 (regenerated 2026-08-29 after accounting fix)
+ `e3b_cal_*` ×3, `e4_elision.json`, `e5_<t>t_z<θ>_<mode>.json` ×24,
`summary.json` (regenerated by the audited `analyze.py`), `run_log.txt`
(includes audit entries). Re-run artifacts used for the reproducibility
checks live outside the project tree and are not results.

## Erratum (2026-08-29, appended during paper revision; audit body above unchanged)

- **C6 / §E5 reference-goodput ratios.** The prose above quotes tx-elide at
  "83–84% of [the lock-based reference's] goodput at ≤4 threads, 56–65% at
  8 threads". Recomputing same-θ ratios strictly from
  `goodput_commits_per_s` in `e5_<t>t_z<θ>_{tx-elide,vanilla}.json` gives
  **80.3–86.5% at ≤4 threads** (per-cell: 85.2/86.5/85.5 at 1t,
  83.7/84.3/83.8 at 2t, 83.2/82.6/80.3 at 4t) and **59.5–67.0% at 8
  threads** (64.8/67.0/59.5). The original prose mixed ops-based and
  goodput-based ratios; the goodput-based figures are the correct ones for
  a "fraction of reference goodput" claim and are what the paper and
  `paper/NUMBERS.md` cite. No raw JSON or any other number above is
  affected.
