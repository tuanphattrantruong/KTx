; intents.S - deferred-intent atomicity probe (ringbuf + pktwrite + map).
; Does one ringbuf_output(8B msg), one packet_store_bytes(off 4, 4B), one
; map_update, then EITHER exits PASS (pkt[0] == 0) or loops forever
; (pkt[0] == 1, forcing a fuel abort past all three effects).
;   tx commit : pkt[4..7] = 0x2A2A2A2A at commit, ring_count 1, key present.
;   tx abort  : packet untouched, ring_count 0, map empty (all-or-nothing).
;   sfi abort : all three effects already applied (torn; the C2 contrast).
.min_pkt 64
.map imap hash key=8 value=8 max=64
  mov r9, r1              ; save ctx
  ldxdw r7, [r1+0]        ; pkt data
  ; ringbuf_output(0, &msg, 8, 0)
  mov r2, 4242
  stxdw [r10-8], r2       ; msg
  mov r1, 0
  mov r2, r10
  add r2, -8
  mov r3, 8
  mov r4, 0
  call ringbuf_output
  ; packet_store_bytes(ctx, 4, &fourbytes, 4)
  stw [r10-16], 0x2a2a2a2a
  mov r1, r9
  mov r2, 4
  mov r3, r10
  add r3, -16
  mov r4, 4
  call packet_store_bytes
  ; map_update(imap, key=88, val=99)
  mov r2, 88
  stxdw [r10-24], r2
  mov r3, 99
  stxdw [r10-32], r3
  mov r2, r10
  add r2, -24
  mov r3, r10
  add r3, -32
  mov r4, 0
  lddw r1, map:imap
  call map_update_elem
  ; pkt[0] == 1 ? loop forever (fuel abort) : exit PASS
  ldxb r8, [r7+0]
  jeq r8, 1, spin
  mov r0, 2
  exit
spin:
  ja spin
