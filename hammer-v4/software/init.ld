OUTPUT_ARCH(riscv)
ENTRY(_start)
PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS
{
    . = 0x10000 + SIZEOF_HEADERS;
    .text : ALIGN(16) { KEEP(*(.text.entry)) *(.text .text.*) } :text
    .rodata : ALIGN(16) { *(.rodata .rodata.*) } :text
    . = ALIGN(4096);
    .data : { *(.data .data.* .sdata .sdata.*) } :data
    .bss (NOLOAD) : ALIGN(16) { *(.bss .bss.* .sbss .sbss.* COMMON) } :data
    /DISCARD/ : { *(.comment .note .eh_frame .eh_frame_hdr) }
}
ASSERT(_start >= 0x10000 && _start < 0x20000, "init entry outside user text")
