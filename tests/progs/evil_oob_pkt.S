; evil_oob_pkt.S - adversarial: reads pkt+300 with no data_end check.
; Run with a 64-byte packet: guarded modes must trap -> KTX_ABORT_GUARD.
; min_pkt is 64 so the analyzer cannot prove offset 300 in bounds; the
; guard must survive elision.  Never run in vanilla.
.min_pkt 64
  ldxdw r7, [r1+0]        ; pkt data
  ldxb r0, [r7+300]       ; out of bounds for a 64-byte packet
  mov r0, 2
  exit
