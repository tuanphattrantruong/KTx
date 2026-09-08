; pktcount.S - per-CPU packet/byte counter (DESIGN 7)
; cnt percpu_array[1], value {u64 pkts, u64 bytes}
; Straight-line; expected: full guard+fuel elision, lock-free per-CPU commit.
.min_pkt 64
.map cnt percpu_array key=4 value=16 max=1

  ldxw r6, [r1+16]        ; r6 = pkt len (ctx.len)
  stw [r10-4], 0          ; key = 0
  mov r2, r10
  add r2, -4              ; r2 = &key
  lddw r1, map:cnt
  call map_lookup_elem
  jeq r0, 0, out          ; cannot miss (array), but stay defensive
  ldxdw r3, [r0+0]        ; pkts
  add r3, 1
  stxdw [r0+0], r3
  ldxdw r3, [r0+8]        ; bytes
  add r3, r6
  stxdw [r0+8], r3
out:
  mov r0, 2               ; KTX_PASS
  exit
