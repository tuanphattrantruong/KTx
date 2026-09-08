; firewall.S - blocklist + per-flow counter + length-driven header scan.
;
; The security workload (E9).  Two properties make it the right exhibit
; for abort-induced policy bypass:
;   * the verdict is a *policy* decision (DROP for a blocklisted flow),
;     so an abort that returns the default verdict is a bypass;
;   * it both scans a packet-length-dependent number of header bytes
;     (a fuel-exhaustion vector) and does a write-through update of a
;     shared per-flow counter (an OCC-conflict vector).
.min_pkt 64
.map blocklist hash key=8 value=8 max=4096
.map fwstats   hash key=8 value=8 max=4096

  ldxdw r7, [r1+0]        ; r7 = packet data
  ldxw  r9, [r1+16]       ; r9 = packet length
  jle r9, 256, scan       ; clamp the scan window to 256 bytes
  mov r9, 256
scan:
  mov r3, 0               ; i
  mov r4, 0               ; running sum (header checksum stand-in)
loop:
  jge r3, r9, scanned
  mov r5, r7
  add r5, r3
  ldxb r2, [r5+0]
  add r4, r2
  add r3, 1
  ja loop
scanned:
  stxdw [r10-16], r4      ; keep the checksum live

  ldxdw r2, [r7+16]       ; flow key
  stxdw [r10-8], r2
  mov r2, r10
  add r2, -8
  lddw r1, map:blocklist
  call map_lookup_elem
  mov r8, 0
  jeq r0, 0, stats
  mov r8, 1               ; flow is blocklisted -> DROP
stats:
  mov r2, r10
  add r2, -8
  lddw r1, map:fwstats
  call map_lookup_elem
  jeq r0, 0, newflow
  ldxdw r3, [r0+0]
  add r3, 1
  stxdw [r0+0], r3        ; write-through: the OCC-conflict vector
  ja verdict
newflow:
  mov r3, 1
  stxdw [r10-24], r3
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -24
  mov r4, 0
  lddw r1, map:fwstats
  call map_update_elem
verdict:
  jeq r8, 0, pass
  mov r0, 1               ; DROP
  exit
pass:
  mov r0, 2               ; PASS
  exit
