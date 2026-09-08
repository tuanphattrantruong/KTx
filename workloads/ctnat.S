; ctnat.S - conntrack+NAT writer with a cross-map invariant (DESIGN 7, E3).
; conntrack hash 8->16 {u32 state, u32 gen, u64 pkts}
; nat       hash 8->16 {u32 rewrite_ip, u32 gen, u64 touched}
; Invariant: for every flow_key, either both maps have the key with EQUAL gen
; fields, or neither has it. gen' = 1 on miss, gen+1 on hit; both values are
; built on the stack with the SAME gen', then two map_update calls with a
; >=6-insn window between them (the E3b fuel-abort landing zone).
.min_pkt 64
.map conntrack hash key=8 value=16 max=4096
.map nat hash key=8 value=16 max=4096

  ldxdw r7, [r1+0]        ; pkt data
  ldxdw r2, [r7+16]       ; flow_key
  stxdw [r10-8], r2       ; key
  ldxw r8, [r7+4]         ; dst_ip -> NAT rewrite value
  mov r2, r10
  add r2, -8
  lddw r1, map:conntrack
  call map_lookup_elem
  mov r6, 1               ; gen' = 1 (miss default)
  mov r9, 0               ; pkts = 0 (miss default)
  jeq r0, 0, build
  ldxw r6, [r0+4]         ; gen
  add r6, 1               ; gen' = gen + 1
  ldxdw r9, [r0+8]        ; pkts
build:
  add r9, 1
  ; conntrack value @ [r10-24, r10-8): state, gen', pkts
  stw [r10-24], 1
  stxw [r10-20], r6
  stxdw [r10-16], r9
  ; nat value @ [r10-40, r10-24): rewrite_ip, SAME gen', touched
  stxw [r10-40], r8
  stxw [r10-36], r6
  stxdw [r10-32], r9
  mov r2, r10
  add r2, -8
  mov r3, r10
  add r3, -24
  mov r4, 0
  lddw r1, map:conntrack
  call map_update_elem    ; update #1
  mov r2, r10             ; --- >=6 insns between the two updates ---
  add r2, -8
  mov r3, r10
  add r3, -40
  mov r4, 0
  lddw r1, map:nat        ; (lddw = 2 slots -> 7-slot window)
  call map_update_elem    ; update #2
  mov r0, 2               ; PASS
  exit
