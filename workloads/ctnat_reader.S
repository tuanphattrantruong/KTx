; ctnat_reader.S - cross-map invariant checker for ctnat (DESIGN 7, E3a).
; DROP(1) iff exactly one of {conntrack, nat} has the key, or gens differ.
; PASS(2) otherwise (both absent is consistent).
.min_pkt 64
.map conntrack hash key=8 value=16 max=4096
.map nat hash key=8 value=16 max=4096

  ldxdw r7, [r1+0]        ; pkt data
  ldxdw r2, [r7+16]       ; flow_key
  stxdw [r10-8], r2
  mov r2, r10
  add r2, -8
  lddw r1, map:conntrack
  call map_lookup_elem
  mov r6, -1              ; sentinel: absent
  jeq r0, 0, ct_done
  ldxw r6, [r0+4]         ; conntrack gen (u32 < 2^32, never == sentinel)
ct_done:
  mov r2, r10
  add r2, -8
  lddw r1, map:nat
  call map_lookup_elem
  mov r8, -1
  jeq r0, 0, nat_done
  ldxw r8, [r0+4]         ; nat gen
nat_done:
  jne r6, r8, drop        ; equal (incl. both absent) -> consistent
  mov r0, 2               ; PASS
  exit
drop:
  mov r0, 1               ; DROP = observed violation
  exit
