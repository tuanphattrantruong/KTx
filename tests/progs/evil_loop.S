; evil_loop.S - adversarial: performs a map update, then loops forever.
; Fueled modes must abort KTX_ABORT_FUEL with fuel_used == budget.
; KEY ATOMICITY PROBE (unit-scale C2):
;   sfi  : the direct update is already applied when fuel runs out ->
;          map contains key 77 after the abort (cancellation tears state).
;   tx   : abort discards the log -> map must NOT contain key 77.
; The analyzer must NOT set the fuel-elidable flag (uncounted loop),
; so tx-elide still aborts on fuel.
.min_pkt 0
.map evmap hash key=8 value=8 max=64
  mov r2, 77
  stxdw [r10-8], r2       ; key = 77
  mov r3, 55
  stxdw [r10-16], r3      ; val = 55
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -16
  mov r4, 0
  lddw r1, map:evmap
  call map_update_elem
loop:
  ja loop
