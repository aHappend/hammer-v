OUTPUT_ARCH(riscv)
ENTRY(_start)
MEMORY { firmware (rwx) : ORIGIN = 0x80000000, LENGTH = 2M }
SECTIONS
{
    . = ORIGIN(firmware);
    .text : { KEEP(*(.text.entry)) *(.text .text.*) } > firmware
    .rodata : ALIGN(16) { *(.rodata .rodata.*) } > firmware
    .data : ALIGN(16) { *(.sdata .sdata.* .data .data.*) } > firmware
    .bss (NOLOAD) : ALIGN(16) {
        __bss_start = .;
        *(.sbss .sbss.* .bss .bss.* COMMON)
        . = ALIGN(16);
        __bss_end = .;
    } > firmware
    .stacks (NOLOAD) : ALIGN(16) {
        . += 16384;
        __boot_stack_top = .;
        . += 16384;
        __trap_stack_top = .;
        __firmware_end = .;
    } > firmware
    /DISCARD/ : { *(.comment .note .eh_frame .eh_frame_hdr) }
}
ASSERT(_start == 0x80000000, "firmware entry mismatch")
ASSERT(__firmware_end <= 0x80200000, "firmware overlaps kernel")
