; evil_ctx_oob.S - adversarial: reads 8 bytes at ctx+32 (ctx is 24 bytes).
; Guarded modes must trap -> KTX_ABORT_GUARD.  Never run in vanilla.
.min_pkt 0
  ldxdw r0, [r1+32]       ; past the 24-byte context
  exit
