#include <stddef.h>
#include <stdint.h>

static long syscall6(long number, long p0, long p1, long p2,
                     long p3, long p4, long p5)
{
    register long a0 __asm__("a0") = p0;
    register long a1 __asm__("a1") = p1;
    register long a2 __asm__("a2") = p2;
    register long a3 __asm__("a3") = p3;
    register long a4 __asm__("a4") = p4;
    register long a5 __asm__("a5") = p5;
    register long a7 __asm__("a7") = number;
    __asm__ volatile ("ecall" : "+r"(a0), "+r"(a1) :
                      "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a7) : "memory");
    return a0;
}

static size_t length(const char *s)
{
    size_t n = 0;
    while (s[n])
        ++n;
    return n;
}

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

static __attribute__((noreturn)) void exit_status(long status)
{
    syscall6(93, status, 0, 0, 0, 0, 0);
    for (;;)
        __asm__ volatile ("nop");
}

static void output(const char *s)
{
    size_t count = length(s);
    while (count) {
        long n = syscall6(64, 1, (long)s, count, 0, 0, 0);
        if (n == -4)
            continue;
        if (n <= 0 || (unsigned long)n > count)
            exit_status(2);
        s += n;
        count -= (size_t)n;
    }
}

static __attribute__((noreturn)) void fail(const char *s)
{
    output("HAMMER /init: FAIL ");
    output(s);
    output("\n");
    exit_status(1);
}

struct utsname {
    char sysname[65], nodename[65], release[65];
    char version[65], machine[65], domainname[65];
};

struct timespec64 {
    int64_t seconds, nanoseconds;
};

long init_main(void)
{
    output("HAMMER /init: entered real Linux U-mode\n");
    static struct utsname name;
    if (syscall6(160, (long)&name, 0, 0, 0, 0, 0) != 0)
        fail("uname syscall");
    if (!equal(name.sysname, "Linux") ||
        !equal(name.release, "6.6.1-hammer-v4") ||
        !equal(name.machine, "riscv64"))
        fail("uname contents");
    output("HAMMER /init: uname Linux 6.6.1-hammer-v4 riscv64\n");
    if (syscall6(172, 0, 0, 0, 0, 0, 0) != 1)
        fail("getpid result");
    output("HAMMER /init: getpid=1\n");

    long address = syscall6(222, 0, 3 * 4096, 3, 0x22, -1, 0);
    if ((unsigned long)address >= (unsigned long)-4095)
        fail("anonymous mmap");
    volatile uint64_t *memory = (volatile uint64_t *)(uintptr_t)address;
    for (unsigned long i = 0; i < (3 * 4096 / 8); ++i)
        memory[i] = 0x48414d4d45525634UL ^ (i * 0x102030405UL);
    for (unsigned long i = 0; i < (3 * 4096 / 8); ++i)
        if (memory[i] != (0x48414d4d45525634UL ^ (i * 0x102030405UL)))
            fail("demand-page readback");
    output("HAMMER /init: demand-page write/read verified\n");
    if (syscall6(215, address, 3 * 4096, 0, 0, 0, 0) != 0)
        fail("munmap");

    struct timespec64 delay = { 0, 50000000 }, remaining;
    for (;;) {
        long result = syscall6(101, (long)&delay, (long)&remaining, 0, 0, 0, 0);
        if (result == 0)
            break;
        if (result != -4)
            fail("nanosleep");
        delay = remaining;
    }
    output("HAMMER /init: timer wait complete; waiting for UART v4 line\n");
    char input[3];
    size_t received = 0;
    while (received < sizeof(input)) {
        long n = syscall6(63, 0, (long)(input + received),
                          sizeof(input) - received, 0, 0, 0);
        if (n == -4)
            continue;
        if (n <= 0 || (unsigned long)n > sizeof(input) - received)
            fail("UART read");
        received += (size_t)n;
    }
    if (input[0] != 'v' || input[1] != '4' || input[2] != '\n')
        fail("UART input contents");
    output("HAMMER /init: UART input verified; exit(0)\n");
    exit_status(0);
}
