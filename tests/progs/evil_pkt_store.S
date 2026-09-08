; evil_pkt_store.S - adversarial: stores DIRECTLY to the packet region.
; Direct modes (vanilla/sfi): packet is RW, store lands, pkt[0] = 65.
; Tx modes: packet region is RO (writes must use packet_store_bytes),
; so the store guard must trap -> KTX_ABORT_GUARD, packet untouched.
; The elision sidecar must NOT mark this store tx-elidable (PKT target),
; so tx-elide still aborts.
.min_pkt 64
  ldxdw r7, [r1+0]        ; pkt data
  stb [r7+0], 65          ; direct packet write ('A')
  mov r0, 2
  exit
