; k_hash.S - helper-free kernel: 64 splitmix64 rounds over a packet word.
.min_pkt 64

  ldxdw r7, [r1+0]
  ldxdw r6, [r7+16]       ; seed from the packet
  mov r3, 0
loop:
  jge r3, 64, done
  mov r4, r6
  rsh r4, 30
  xor r6, r4
  lddw r5, 0xBF58476D1CE4E5B9
  mul r6, r5
  mov r4, r6
  rsh r4, 27
  xor r6, r4
  lddw r5, 0x94D049BB133111EB
  mul r6, r5
  mov r4, r6
  rsh r4, 31
  xor r6, r4
  add r3, 1
  ja loop
done:
  mov r0, r6
  exit
