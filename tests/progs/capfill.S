; capfill.S - inserts the packet's flow_key into a 4-entry hash map.
; Harness pre-fills the map with 4 other keys, then runs this in tx mode
; with a fresh key: commit must abort KTX_ABORT_CAPACITY and the map
; content must be exactly the 4 original entries afterwards.
.min_pkt 64
.map tiny hash key=8 value=8 max=4
  ldxdw r7, [r1+0]        ; pkt data
  ldxdw r2, [r7+16]       ; flow_key @16
  stxdw [r10-8], r2
  mov r3, 1
  stxdw [r10-16], r3
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -16
  mov r4, 0
  lddw r1, map:tiny
  call map_update_elem
  mov r0, 2
  exit
