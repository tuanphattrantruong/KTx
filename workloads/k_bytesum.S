; k_bytesum.S - helper-free kernel: sum the first 256 packet bytes.
; Used only to calibrate the execution engines against a C compiler
; (E13); it makes no map or helper call, so the whole cost is body cost.
.min_pkt 256

  ldxdw r7, [r1+0]        ; data
  mov r3, 0               ; i
  mov r4, 0               ; sum
loop:
  jge r3, 256, done
  mov r5, r7
  add r5, r3
  ldxb r2, [r5+0]
  add r4, r2
  add r3, 1
  ja loop
done:
  mov r0, r4
  exit
