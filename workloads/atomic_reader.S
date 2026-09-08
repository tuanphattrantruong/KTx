; atomic_reader.S - invariant checker for atomic_demo (DESIGN 7, E3a).
; DROP(1) iff A[k] + B[k] != 1000, PASS(2) otherwise.
.min_pkt 64
.map acct_a array key=4 value=8 max=256
.map acct_b array key=4 value=8 max=256

  ldxdw r7, [r1+0]        ; pkt data
  ldxw r6, [r7+0]         ; flow id
  and r6, 255
  stxw [r10-4], r6
  mov r2, r10
  add r2, -4
  lddw r1, map:acct_a
  call map_lookup_elem
  jeq r0, 0, pass
  ldxdw r8, [r0+0]        ; A[k]
  mov r2, r10
  add r2, -4
  lddw r1, map:acct_b
  call map_lookup_elem
  jeq r0, 0, pass
  ldxdw r3, [r0+0]        ; B[k]
  add r8, r3
  jne r8, 1000, drop
pass:
  mov r0, 2               ; PASS
  exit
drop:
  mov r0, 1               ; DROP = observed violation
  exit
