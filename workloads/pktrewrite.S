; pktrewrite.S - packet rewriter with deferred packet writes (DESIGN 7).
; No maps. Rewrites dst_ip via packet_store_bytes (a commit-time intent in tx
; modes), then a counted checksum loop over bytes 0..19 (constant bound ->
; fuel elidable; loop test at the head so interval refinement proves the
; ldxb in-bounds under min_pkt=64).
.min_pkt 64

  mov r6, r1              ; save ctx
  ldxdw r7, [r6+0]        ; pkt data
  ldxw r2, [r7+0]         ; src_ip
  xor r2, 0x5A5A5A5A      ; new dst_ip = src_ip ^ mask
  stxw [r10-4], r2
  mov r1, r6              ; packet_store_bytes(ctx, 4, &new_dst, 4)
  mov r2, 4
  mov r3, r10
  add r3, -4
  mov r4, 4
  call packet_store_bytes
  mov r8, 0               ; checksum accumulator
  mov r9, 0               ; i = 0
loop:
  jge r9, 20, done        ; while (i < 20)
  mov r2, r7
  add r2, r9
  ldxb r3, [r2+0]         ; pkt[i]
  add r8, r3
  add r9, 1
  ja loop
done:
  mov r0, 2               ; PASS
  exit
