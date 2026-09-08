; loopy.S - deliberately unverifiable TLV walker (DESIGN 7). The admission
; case study: a static verifier (and our elision analyzer) must FAIL on it,
; yet it is dynamically correct (every access is explicitly bounds-checked
; against data_end, so guards never actually fire; it just runs fully
; guarded + fueled).
;
; Nested data-dependent walk: outer loop steps p += 2 + len where len comes
; from the packet (defeats the counted-loop pattern); inner loop sums the
; value bytes (packet-driven bound). Accumulates {count, bytesum} and folds
; per-type info into the key: tlvstats[flow_key ^ typemask] += {count, sum}.
.min_pkt 64
.map tlvstats hash key=8 value=16 max=4096

  ldxdw r7, [r1+0]        ; data
  ldxdw r8, [r1+8]        ; data_end
  ldxdw r2, [r7+16]       ; flow_key
  stxdw [r10-8], r2
  stdw [r10-32], 0        ; typemask accumulator
  mov r9, r7
  add r9, 24              ; p = data + 24 (TLV area)
  mov r6, 0               ; count
  mov r5, 0               ; bytesum (moved to stack before helper calls)
outer:
  mov r2, r9
  add r2, 2
  jgt r2, r8, walk_done   ; need type+len header in bounds
  ldxb r3, [r9+0]         ; type
  jeq r3, 0, walk_done    ; type 0 terminates
  ldxdw r4, [r10-32]      ; typemask |= (1 << (type & 63))
  mov r2, 1
  lsh r2, r3
  or r4, r2
  stxdw [r10-32], r4
  ldxb r4, [r9+1]         ; len (data-dependent step!)
  mov r2, r9
  add r2, 2
  add r2, r4
  jgt r2, r8, walk_done   ; whole value must be in bounds
  add r6, 1               ; count++
  mov r3, 0               ; j = 0
inner:
  jge r3, r4, inner_done  ; while (j < len)  - packet-driven bound
  mov r2, r9
  add r2, 2
  add r2, r3
  ldxb r1, [r2+0]
  add r5, r1              ; bytesum += value[j]
  add r3, 1
  ja inner
inner_done:
  add r9, 2
  add r9, r4              ; p += 2 + len
  ja outer
walk_done:
  ldxdw r2, [r10-8]       ; key = flow_key ^ typemask
  ldxdw r3, [r10-32]
  xor r2, r3
  stxdw [r10-8], r2
  stxdw [r10-24], r6      ; value = {count, bytesum}
  stxdw [r10-16], r5
  mov r2, r10
  add r2, -8
  lddw r1, map:tlvstats
  call map_lookup_elem
  jeq r0, 0, fresh
  ldxdw r3, [r0+0]        ; hit: increment through the pointer
  add r3, r6
  stxdw [r0+0], r3
  ldxdw r3, [r0+8]
  ldxdw r4, [r10-16]
  add r3, r4
  stxdw [r0+8], r3
  ja out
fresh:
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -24
  mov r4, 0
  lddw r1, map:tlvstats
  call map_update_elem
out:
  mov r0, 2               ; PASS
  exit
