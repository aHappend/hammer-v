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
    .option pop
    .section .note.GNU-stack, "", @progbits
