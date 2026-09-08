; flowstats.S - per-flow stats (DESIGN 7); E5 contention driver.
; flows hash 8->16, value {u64 pkts, u64 bytes}
; lookup-or-init + increment through the lookup pointer.
.min_pkt 64
.map flows hash key=8 value=16 max=4096

  ldxw r6, [r1+16]        ; r6 = pkt len
  ldxdw r7, [r1+0]        ; r7 = pkt data
  ldxdw r2, [r7+16]       ; flow_key @16
  stxdw [r10-8], r2       ; key on stack
  mov r2, r10
  add r2, -8
  lddw r1, map:flows
  call map_lookup_elem
  jeq r0, 0, miss
  ldxdw r3, [r0+0]        ; pkts++
  add r3, 1
  stxdw [r0+0], r3
  ldxdw r3, [r0+8]        ; bytes += len
  add r3, r6
  stxdw [r0+8], r3
  ja out
miss:
  mov r3, 1
  stxdw [r10-24], r3      ; pkts = 1
  stxdw [r10-16], r6      ; bytes = len
  mov r2, r10
  add r2, -8              ; &key
  mov r3, r10
  add r3, -24             ; &value
  mov r4, 0               ; flags = 0
  lddw r1, map:flows
  call map_update_elem
out:
  mov r0, 2               ; KTX_PASS
  exit
