    .option norvc
    .option norelax
    .section .text.entry, "ax"
    .balign 4
    .globl _start
_start:
    andi sp, sp, -16
    call init_main
    li a7, 93
    ecall
1:
    j 1b
