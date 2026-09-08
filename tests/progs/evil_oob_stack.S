; evil_oob_stack.S - adversarial: store 8 bytes below the 512-byte stack.
; Guarded modes must trap -> KTX_ABORT_GUARD.  Never run in vanilla
; (it would corrupt harness memory - that is the point of the guard).
; Elision must keep this guard (below-stack offset is provably OOB).
.min_pkt 0
  mov r6, r10
  add r6, -520            ; 8 bytes below the stack region
  stdw [r6+0], 7
  mov r0, 2
  exit
