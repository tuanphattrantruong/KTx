; regions13.S - boundary probe: exactly 13 distinct successful lookups.
; 13 is the documented live-mapval-region limit (slots 3..15), so this
; program must run to completion (verdict 2) in every mode.
.min_pkt 0
.map arr array key=4 value=8 max=16
  mov r6, 0
next:
  stxw [r10-4], r6
  mov r2, r10
  add r2, -4
  lddw r1, map:arr
  call map_lookup_elem
  add r6, 1
  jlt r6, 13, next
  mov r0, 2
  exit
