#include <stddef.h>
#include <stdint.h>

#define UART ((volatile uint8_t *)(uintptr_t)0x10010000)
#define MTIMECMP (*(volatile uint64_t *)(uintptr_t)0x02004000)
#define SBI_BASE 0x10UL
#define SBI_TIME 0x54494d45UL
#define STIP (1UL << 5)
#define MTIE (1UL << 7)

struct trap_frame {
    uint64_t x[32];
    uint64_t pc, status, cause, tval;
};

_Static_assert(offsetof(struct trap_frame, pc) == 256, "trap assembly ABI");
_Static_assert(sizeof(struct trap_frame) == 288, "trap stack alignment");

static void io_fence(void)
{
    __asm__ volatile ("fence iorw, iorw" ::: "memory");
}

static void putchar_uart(unsigned char c)
{
    while (!(UART[5] & 0x20))
        __asm__ volatile ("nop");
    UART[0] = c;
    io_fence();
}

static void puts_uart(const char *text)
{
    while (*text)
        putchar_uart((unsigned char)*text++);
}

static void puthex(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    for (unsigned int shift = 64; shift != 0; ) {
        shift -= 4;
        putchar_uart(digits[(value >> shift) & 15]);
    }
}

static __attribute__((noreturn)) void fatal(const char *message)
{
    puts_uart(message);
    for (;;)
        __asm__ volatile ("wfi");
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void set_timer(uint64_t deadline)
{
    __asm__ volatile ("csrc mie, %0" :: "r"(MTIE) : "memory");
    __asm__ volatile ("csrc mip, %0" :: "r"(STIP) : "memory");
    MTIMECMP = deadline;
    io_fence();
    __asm__ volatile ("csrs mie, %0" :: "r"(MTIE) : "memory");
}

static unsigned long probe_extension(unsigned long extension)
{
    return extension == SBI_BASE || extension == SBI_TIME ||
           extension == 0 || extension == 1 || extension == 2;
}

void fw_trap(struct trap_frame *frame)
{
    if (frame->cause == ((1UL << 63) | 7)) {
        __asm__ volatile ("csrc mie, %0" :: "r"(MTIE) : "memory");
        __asm__ volatile ("csrs mip, %0" :: "r"(STIP) : "memory");
        return;
    }
    if (frame->cause != 9) {
        puts_uart("HAMMER firmware fatal trap: cause=0x");
        puthex(frame->cause);
        puts_uart(" epc=0x");
        puthex(frame->pc);
        puts_uart(" tval=0x");
        puthex(frame->tval);
        fatal("\r\n");
    }

    unsigned long eid = frame->x[17], fid = frame->x[16];
    long error = -2;
    unsigned long value = 0;
    if (eid == SBI_BASE) {
        switch (fid) {
        case 0: error = 0; value = 2; break;
        case 1: error = 0; value = 0x48414d4d; break;
        case 2: error = 0; value = 0x00040000; break;
        case 3: error = 0; value = probe_extension(frame->x[10]); break;
        case 4: case 5: case 6: error = 0; value = 0; break;
        default: break;
        }
    } else if (eid == SBI_TIME && fid == 0) {
        set_timer(frame->x[10]);
        error = 0;
    } else if (eid == 0) {
        set_timer(frame->x[10]);
        frame->x[10] = 0;
        frame->pc += 4;
        return;
    } else if (eid == 1) {
        putchar_uart((unsigned char)frame->x[10]);
        frame->x[10] = 0;
        frame->pc += 4;
        return;
    } else if (eid == 2) {
        frame->x[10] = UART[5] & 1 ? UART[0] : (uint64_t)-1;
        frame->pc += 4;
        return;
    }
    frame->x[10] = (uint64_t)error;
    frame->x[11] = value;
    frame->pc += 4;
}

extern void fw_enter_supervisor(unsigned long hartid, uintptr_t dtb)
    __attribute__((noreturn));

void fw_main(unsigned long hartid, uintptr_t dtb)
{
    UART[1] = 0;
    UART[3] = 0x80;
    UART[0] = 1;
    UART[1] = 0;
    UART[3] = 3;
    UART[2] = 7;
    io_fence();
    puts_uart("HAMMER-V4 OpenSBI-compatible fw_jump (SBI v0.2)\r\n");
    if (hartid != 0 || dtb != 0x87e00000)
        fatal("HAMMER firmware error: invalid hart/DTB handoff\r\n");
    const uint8_t *fdt = (const uint8_t *)dtb;
    if (be32(fdt) != 0xd00dfeed)
        fatal("HAMMER firmware error: FDT magic\r\n");
    uint32_t size = be32(fdt + 4);
    uint32_t structure = be32(fdt + 8), strings = be32(fdt + 12);
    uint32_t reserve = be32(fdt + 16);
    uint32_t strings_size = be32(fdt + 32), structure_size = be32(fdt + 36);
    if (size < 40 || size > 0x200000 || structure < 40 ||
        structure > size || structure_size > size - structure ||
        strings < 40 || strings > size || strings_size > size - strings ||
        reserve < 40 || reserve > size - 16 || (reserve & 7) ||
        (structure & 3) || be32(fdt + 20) != 17 || be32(fdt + 24) > 17)
        fatal("HAMMER firmware error: FDT bounds/version\r\n");
    MTIMECMP = UINT64_MAX;
    io_fence();
    __asm__ volatile ("csrw mip, zero" ::: "memory");
    __asm__ volatile ("csrw mcounteren, %0" :: "r"(7UL) : "memory");
    __asm__ volatile ("csrw medeleg, %0" :: "r"(0xb1ffUL) : "memory");
    __asm__ volatile ("csrw mideleg, %0" :: "r"(0x222UL) : "memory");
    __asm__ volatile ("csrw mie, %0" :: "r"(MTIE) : "memory");
    puts_uart("HAMMER firmware: hart=0 dtb=0x87e00000 next=0x80200000 S-mode\r\n");
    __asm__ volatile ("fence.i" ::: "memory");
    fw_enter_supervisor(hartid, dtb);
}
