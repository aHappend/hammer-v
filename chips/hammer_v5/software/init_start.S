/* SPDX-License-Identifier: MIT */
    .section .text.start
    .option push
    .option norvc
    .globl _start
    .type _start, @function
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    andi sp, sp, -16
    call hammer_init_main
    li a7, 94
    li a0, 1
    ecall
1:  j 1b
    .size _start, .-_start
    .balign 4
    .globl hammer_try_vxctl_write
    .type hammer_try_vxctl_write, @function
hammer_try_vxctl_write:
    csrrw zero, 0x800, zero
    ret
    .size hammer_try_vxctl_write, .-hammer_try_vxctl_write
    .balign 4
    .globl hammer_try_misaligned_vload
    .type hammer_try_misaligned_vload, @function
hammer_try_misaligned_vload:
    .insn r 0x0b, 0, 0, x0, a0, x0
    ret
    .size hammer_try_misaligned_vload, .-hammer_try_misaligned_vload
    .option pop
    .section .note.GNU-stack, "", @progbits
