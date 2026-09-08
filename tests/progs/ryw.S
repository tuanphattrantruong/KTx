; ryw.S - read-your-writes probe, end to end through real bytecode.
; update rmap[9] = 5; lookup must see 5 (RYW, even if the key already
; existed with another value); delete; lookup must now see NULL.
; verdict: 5 on success, 0 on any RYW violation.
; Post-commit shared state: key 9 must be ABSENT (update then delete).
.min_pkt 0
.map rmap hash key=8 value=8 max=64
  mov r2, 9
  stxdw [r10-8], r2       ; key = 9
  mov r3, 5
  stxdw [r10-16], r3      ; val = 5
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -16
  mov r4, 0
  lddw r1, map:rmap
  call map_update_elem
  ; lookup: must return the in-tx value 5
  mov r2, r10
  add r2, -8
  lddw r1, map:rmap
  call map_lookup_elem
  jeq r0, 0, fail
  ldxdw r6, [r0+0]
  jne r6, 5, fail
  ; delete
  mov r2, r10
  add r2, -8
  lddw r1, map:rmap
  call map_delete_elem
  ; lookup again: must be NULL now
  mov r2, r10
  add r2, -8
  lddw r1, map:rmap
  call map_lookup_elem
  jne r0, 0, fail
  mov r0, r6              ; 5
  exit
fail:
  mov r0, 0
  exit
