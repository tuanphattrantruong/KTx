; k_stride.S - helper-free kernel: xor 32 doublewords strided through the
; packet, so the cost is dominated by loads rather than ALU work.
.min_pkt 256

  ldxdw r7, [r1+0]
  mov r3, 0
  mov r4, 0
loop:
  jge r3, 256, done
  mov r5, r7
  add r5, r3
  ldxdw r2, [r5+0]
  xor r4, r2
  add r3, 8
  ja loop
done:
  mov r0, r4
  exit
