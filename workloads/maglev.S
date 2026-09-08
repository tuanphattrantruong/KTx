; maglev.S - Maglev-style LB table lookup (DESIGN 7). Pure read.
; table array 4->4, 4093 entries. Expected: map proven read-only ->
; validate-only commit in tx-elide.
.min_pkt 64
.map table array key=4 value=4 max=4093

  ldxdw r7, [r1+0]        ; pkt data
  ldxdw r2, [r7+16]       ; flow_key
  lddw r3, 0x9E3779B97F4A7C15
  mul r2, r3              ; multiply-shift fold
  rsh r2, 33
  mod r2, 4093            ; idx in [0, 4092]
  stxw [r10-4], r2
  mov r2, r10
  add r2, -4
  lddw r1, map:table
  call map_lookup_elem
  jeq r0, 0, out
  ldxw r3, [r0+0]         ; backend id (consumed as verdict-neutral read)
out:
  mov r0, 2               ; PASS
  exit
