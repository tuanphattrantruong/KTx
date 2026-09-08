; evil_flags.S - adversarial: map_update_elem with flags != 0.
; Contract (DESIGN 3.5): flags must be 0 (ANY) -> KTX_ABORT_HELPER.
.min_pkt 0
.map flmap hash key=8 value=8 max=64
  stdw [r10-8], 1         ; key
  stdw [r10-16], 2        ; val
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -16
  mov r4, 1               ; ILLEGAL flags
  lddw r1, map:flmap
  call map_update_elem
  mov r0, 2
  exit
