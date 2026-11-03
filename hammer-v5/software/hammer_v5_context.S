    .section .text
    .option push
    .option norvc
    .balign 4
    .globl hammer_vx_save
    .type hammer_vx_save, @function
hammer_vx_save:
    .insn r 0x0b, 4, 0, x0, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 4, 0, x0, a0, x1
    addi a0, a0, 8
    .insn r 0x0b, 4, 0, x0, a0, x2
    addi a0, a0, 8
    .insn r 0x0b, 4, 0, x0, a0, x3
    addi a0, a0, 8
    .insn r 0x0b, 4, 0, x0, a0, x4
    addi a0, a0, 8
    .insn r 0x0b, 4, 0, x0, a0, x5
    addi a0, a0, 8
    .insn r 0x0b, 4, 0, x0, a0, x6
    addi a0, a0, 8
    .insn r 0x0b, 4, 0, x0, a0, x7
    ret
    .size hammer_vx_save, .-hammer_vx_save

    .balign 4
    .globl hammer_vx_restore
    .type hammer_vx_restore, @function
hammer_vx_restore:
    .insn r 0x0b, 0, 0, x0, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 0, 0, x1, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 0, 0, x2, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 0, 0, x3, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 0, 0, x4, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 0, 0, x5, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 0, 0, x6, a0, x0
    addi a0, a0, 8
    .insn r 0x0b, 0, 0, x7, a0, x0
    ret
    .size hammer_vx_restore, .-hammer_vx_restore
    .option pop
    .section .note.GNU-stack, "", @progbits
