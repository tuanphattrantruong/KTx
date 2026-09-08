; atomic_demo.S - multi-map atomic section (DESIGN 7, C7).
; acct_a / acct_b: array 4->8 u64, 256 entries; harness initializes
; A[k]=1000, B[k]=0. Every invocation moves amt = 1 + (prandom & 7) units
; A[k] -> B[k], or back B[k] -> A[k] when A[k] < amt. Invariant:
; A[k] + B[k] == 1000 for all k. Both maps are touched in ONE invocation
; through lookup pointers - the atomic-section programming-model exhibit.
.min_pkt 64
.map acct_a array key=4 value=8 max=256
.map acct_b array key=4 value=8 max=256

  ldxdw r7, [r1+0]        ; pkt data
  ldxw r6, [r7+0]         ; flow id (src_ip)
  and r6, 255             ; k
  stxw [r10-4], r6
  call get_prandom_u32
  and r0, 7
  add r0, 1
  mov r9, r0              ; amt in [1, 8]
  mov r2, r10
  add r2, -4
  lddw r1, map:acct_a
  call map_lookup_elem
  jeq r0, 0, out          ; unreachable for k < 256; defensive
  mov r6, r0              ; A ptr
  mov r2, r10
  add r2, -4
  lddw r1, map:acct_b
  call map_lookup_elem
  jeq r0, 0, out
  mov r8, r0              ; B ptr
  ldxdw r3, [r6+0]        ; A[k]
  jlt r3, r9, back
  sub r3, r9              ; A -> B
  stxdw [r6+0], r3
  ldxdw r4, [r8+0]
  add r4, r9
  stxdw [r8+0], r4
  ja out
back:
  ldxdw r4, [r8+0]        ; B -> A (B >= 992 here, safe)
  sub r4, r9
  stxdw [r8+0], r4
  add r3, r9
  stxdw [r6+0], r3
out:
  mov r0, 2               ; PASS
  exit
