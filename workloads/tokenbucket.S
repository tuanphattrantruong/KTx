; tokenbucket.S - token-bucket rate limiter (DESIGN 7)
; bucket hash 8->16, value {u64 tokens, u64 last_ns}; cap = 64 tokens,
; refill 1 token per 2^20 ns. Spend 1 token or DROP.
.min_pkt 64
.map bucket hash key=8 value=16 max=4096

  ldxdw r7, [r1+0]        ; pkt data
  ldxdw r2, [r7+16]       ; flow_key
  stxdw [r10-8], r2
  mov r2, r10
  add r2, -8
  lddw r1, map:bucket
  call map_lookup_elem
  jeq r0, 0, init
  mov r6, r0              ; r6 = bucket value ptr (survives helper call)
  call ktime_get_ns       ; r0 = now
  ldxdw r2, [r6+8]        ; last_ns
  mov r3, r0
  sub r3, r2
  rsh r3, 20              ; elapsed >> 20 = refill
  ldxdw r4, [r6+0]        ; tokens
  add r4, r3
  jle r4, 64, nocap
  mov r4, 64
nocap:
  stxdw [r6+8], r0        ; last_ns = now
  jeq r4, 0, empty
  sub r4, 1
  stxdw [r6+0], r4
  mov r0, 2               ; PASS
  exit
empty:
  stxdw [r6+0], r4
  mov r0, 1               ; DROP
  exit
init:
  call ktime_get_ns
  mov r3, 63              ; start full (64) minus this packet's token
  stxdw [r10-24], r3      ; tokens
  stxdw [r10-16], r0      ; last_ns = now
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -24
  mov r4, 0
  lddw r1, map:bucket
  call map_update_elem
  mov r0, 2               ; PASS
  exit
