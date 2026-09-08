# KTx — results summary (v2 matrix, ground truth for the paper)

Everything below was read out of a JSON file in `experiments/results/v2/`
produced by a binary run on this machine. No number in the paper is
transcribed from prose; `experiments/analyze_v2.py` recomputes every
derived quantity from the stored raw values and names its source file.

- **Machine.** Apple M1 (4P+4E, 8 hardware threads), macOS, Apple clang
  `-O2`. No CPU affinity API exists; every harness thread requests the
  user-interactive QoS class. Timer `mach_absolute_time` (41.67 ns tick),
  batch-of-32 latency timing.
- **Design.** Every timed cell is 3 runs with different seeds; the
  analyzer reports median and range. All 12 configurations of a cell (5
  modes + shadow-diff ablation + both execution arms) run back-to-back
  inside the innermost loop. This replaced an earlier *blocked* matrix
  that produced a 50% systematic offset between blocks and none within
  them — the reason the interleaved design exists.
- **Tests.** `test_vm` 55/55, `test_ktx` 139/139, `test_jit` 198/198
  (12 workloads × 5 modes + abort-inducing fuel budgets + 24 generated
  opcode-coverage programs).

## Headline results

| # | Claim | Evidence |
|---|---|---|
| C1 | Multi-map effect is common in real eBPF | 5,551 programs, 9 projects: 281/823 effectful (34.1%) write ≥2 maps; production 143/231 (61.9%); Cilium 71%, Tracee 88%, Katran 50%. Strict lower bound without call-graph propagation: 13.2% / 27.1%. (`e10_corpus.json`, `e10_corpus_directonly.json`) |
| C2 | Cross-map violations occur; KTx eliminates them | E3a: vanilla ctnat 5,590 violations, accounts 1,971,448 **and 252/256 keys permanently torn**; tx 0 and 0. 2PL: 2 and 0 violations but 12,998 deadlock aborts. (`e3a_*`) |
| C3 | Cross-map locking does not fix cancellation | E3b at matched abort fractions: sfi 48/512 & 256/256 torn, **2pl 52/512 & 256/256**, tx **0 & 0**. (`e3b_*`) |
| C4 | The guarantee holds under checking | Model check 26,167 states, 0 atomicity/serializability violations, 0 deadlocks (2PL: 26 deadlocks, 113 non-serializable). Runtime: 11.6M committed txs over 5 shapes (rmw chain recovery 5.5M, delete 2.0M, capacity 249k with 1.75M capacity aborts, per-CPU 2.0M exact, RO-elide 1.88M), 0 violations. Controls: direct-effect rmw → 64,122 lost updates; split-writer RO → 9,048 torn reads. (`e11_*`, `e8_*`, `e8b_*`) |
| C5 | Cost, honestly, in both arms | Post-elision: 1.1–2.3× an interpreted body, **1.6–5.5× a compiled one**. Transactional add-on 10–153 ns interpreted, 13–152 ns JIT — a fixed cost. On compiled bodies the guard usually exceeds the transaction (firewall 411 vs 13 ns). (`e1_lat_*`) |
| C6 | Elision recovery | 79–117% of measured guard+fuel cost interpreted, 98–375% JIT; 1–9% on the two programs the analyzer cannot certify. 10/12 programs fully certified, including all three compiled from C. (`e1_lat_*`, `e4_elision.json`) |
| C7 | The analyzer's facts audited, not trusted | 157,484,600 certified accesses executed with guards retained: **0 facts falsified**, 0 writes to a map certified read-only. (`e14_audit_*`) |
| C8 | Aborts create a policy-bypass surface | Conflict vector, fail-open: tx 28.3% bypass (JIT 35.5%), tx-elide 26.3%, 2pl 16.3%, sfi 0%. 8 retries → 0.57%. Fail-closed → 0% at 1.01% false drops, 0.0024% with 8 retries. Fuel vector: **100% bypass in sfi as much as in tx** — inherent to runtime termination. (`e9_*`) |
| C9 | Engines are not strawmen | Our interpreter is 2.2–2.3× faster than ubpf's; our JIT within 1.04–1.56× of ubpf's arm64 JIT; 1.24× (ALU-bound) to 15× (vectorizable loops) slower than clang -O2. (`e13_engine.json`) |
| C10 | Memory | 84.6 KiB/thread provisioned; workloads use ≤132 B arena, ≤4 records, ≤2 read-set entries. JIT code 1.4–14.1 KB/program. (`e1_lat_*` `memory` block) |
| C11 | Contention | tx-elide abort rate ≤0.8% to 4 threads uniform, 2.1% at 8, 12.5% at 8t/θ=1.2; goodput 2.69→10.7 M commits/s; 46% of the lock reference at 8t (2PL 51%). At 16 threads (oversubscribed, θ=0.9) tx-elide plateaus at 11.83 M/s with 10.6% aborts. (`e5_*`, `e5x_*`) |

## Honest limitations that must accompany these numbers

1. **Userspace prototype.** No kernel integration; no Mpps/NIC claims.
2. **Our JIT is a template compiler**, 7.6–15× off clang on vectorizable
   loops — which *inflates* the body and therefore *understates* our
   relative overhead on `firewall`, `loopy`, `pktrewrite`.
3. **Throughput mode times a pipeline** including trace synthesis and
   understates VM-relative overhead; latency is the per-invocation number.
4. **Tail percentiles are batch-of-32 means**, forced by the timer tick.
5. **3 runs per cell**, reported as median + range; sub-range differences
   are parity, never a win.
6. **The corpus survey is syntactic**, over C not bytecode; see the
   direct-only lower bound and the stated biases.
7. **The model check is exhaustive only over 2–4 transactions / 2–3
   stripes**; the runtime checks can only falsify. Each exists because
   the other cannot do its job.
8. **8 cores, one asymmetric part.** The 4→8 knee is the machine, not the
   protocol; the 16-thread cell is oversubscription, not scaling.
