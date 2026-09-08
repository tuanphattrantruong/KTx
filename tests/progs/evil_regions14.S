; evil_regions14.S - adversarial: 14 distinct successful lookups.
; One more than the 13-live-mapval-region contract -> the 14th lookup
; must abort KTX_ABORT_HELPER in sfi/tx modes.
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
  jlt r6, 14, next
  mov r0, 2
  exit
