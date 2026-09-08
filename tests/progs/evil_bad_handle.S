; evil_bad_handle.S - adversarial: calls map_lookup_elem with a forged
; 64-bit handle that does not carry the KTX map-handle tag.
; Helper contract: bad handle -> KTX_ABORT_HELPER.
.min_pkt 0
  stdw [r10-8], 0         ; key bytes on stack
  mov r2, r10
  add r2, -8
  lddw r1, 0x1234567800000000
  call map_lookup_elem
  mov r0, 2
  exit
