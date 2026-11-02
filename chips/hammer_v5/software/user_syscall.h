/* SPDX-License-Identifier: MIT */
#ifndef HAMMER_USER_SYSCALL_H
#define HAMMER_USER_SYSCALL_H
#include <stddef.h>
#include <stdint.h>

/* RV64 native Linux 6.6.1 asm-generic syscall ABI; no libc or emulated ISA. */
enum {
    HV_IOCTL=29, HV_MKDIRAT=34, HV_MOUNT=40, HV_OPENAT=56, HV_CLOSE=57,
    HV_WRITE=64, HV_EXIT_GROUP=94, HV_NANOSLEEP=101, HV_SCHED_YIELD=124,
    HV_KILL=129, HV_SIGALTSTACK=132, HV_RT_SIGACTION=134, HV_RT_SIGRETURN=139,
    HV_GETPID=172, HV_MUNMAP=215, HV_CLONE=220, HV_MMAP=222,
    HV_MPROTECT=226, HV_WAIT4=260
};

static inline long hammer_syscall(long number, long arg0, long arg1, long arg2,
                                 long arg3, long arg4, long arg5)
{
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a3 __asm__("a3") = arg3;
    register long a4 __asm__("a4") = arg4;
    register long a5 __asm__("a5") = arg5;
    register long a7 __asm__("a7") = number;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a3),
                     "r"(a4), "r"(a5), "r"(a7) : "memory");
    return a0;
}

static inline long hammer_call(long number, long a0, long a1, long a2)
{
    return hammer_syscall(number, a0, a1, a2, 0, 0, 0);
}

typedef struct {
    void (*handler)(int, void *, void *);
    unsigned long flags;
    uint64_t mask;
} hammer_sigaction;

typedef struct {
    void *sp;
    int flags;
    int padding;
    unsigned long size;
} hammer_stack;

typedef struct {
    unsigned long flags;
    void *link;
    hammer_stack stack;
    uint8_t mask_and_reserved[128];
    uint64_t gpr[32] __attribute__((aligned(16)));
} hammer_ucontext;

_Static_assert(offsetof(hammer_ucontext, gpr) == 176, "pinned RV64 ucontext ABI");
_Static_assert(sizeof(hammer_sigaction) == 24, "pinned RV64 rt_sigaction ABI");

#define HV_SIGUSR1 10
#define HV_SIGUSR2 12
#define HV_SIGILL 4
#define HV_SIGBUS 7
#define HV_SIGSEGV 11
#define HV_SA_SIGINFO 4UL
#define HV_SA_ONSTACK 0x08000000UL
#define HV_SA_NODEFER 0x40000000UL
#define HV_AT_FDCWD (-100)
#endif
