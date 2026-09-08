; evil_badkey.S - adversarial: key pointer argument outside every region.
; r10 itself is one past the stack region [fp-512, fp), so a key at
; [r10, r10+8) is not readable -> KTX_ABORT_HELPER in sfi/tx modes.
.min_pkt 0
.map bkmap hash key=8 value=8 max=64
  mov r2, r10             ; fp = one past the stack: NOT a valid key ptr
  lddw r1, map:bkmap
  call map_lookup_elem
  mov r0, 2
  exit
