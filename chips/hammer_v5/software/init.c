/* SPDX-License-Identifier: MIT */
#include "hammer_v5_isa.h"
#include "hammer_ieee.h"
#include "user_syscall.h"

extern void hammer_vx_save(uint64_t *);
extern void hammer_vx_restore(const uint64_t *);

static char line[768];
static unsigned line_used;
static int control_fd;
static volatile uint64_t observed_sink;
static uint64_t task_state[8];
static volatile unsigned signal_count, nested_count, fault_count;
static volatile int expected_signal;
static volatile uintptr_t expected_address;
static uint8_t signal_stack[16384] __attribute__((aligned(16)));
static uint64_t int_a[32], int_b[32], bf_a[64], bf_b[64];
static uint64_t int_matrix_a[8][8], int_matrix_b[8][8];
static uint64_t bf_matrix_a[4][8], bf_matrix_b[4][8];

static unsigned length(const char *text)
{
    unsigned n = 0;
    while (text[n])
        ++n;
    return n;
}

static void append(const char *text)
{
    while (*text && line_used + 1 < sizeof(line))
        line[line_used++] = *text++;
}

static void hex(uint64_t value)
{
    static const char digits[] = "0123456789abcdef";
    append("0x");
    for (int shift = 60; shift >= 0; shift -= 4)
        line[line_used++] = digits[(value >> shift) & 15];
}

static void decimal(uint64_t value)
{
    char digits[24];
    unsigned n = 0;
    do {
        digits[n++] = (char)('0' + value % 10);
        value /= 10;
    } while (value);
    while (n)
        line[line_used++] = digits[--n];
}

static void emit(void)
{
    unsigned sent = 0;
    line[line_used++] = '\n';
    while (sent < line_used) {
        long done = hammer_call(HV_WRITE, 1, (long)(line + sent), line_used - sent);
        if (done == -4)
            continue;
        if (done <= 0) {
            hammer_call(HV_EXIT_GROUP, 1, 0, 0);
            for (;;) {}
        }
        sent += (unsigned)done;
    }
    line_used = 0;
}

static void begin(const char *kind)
{
    line_used = 0;
    append("HV5 ");
    append(kind);
}

static void fail(const char *message)
{
    begin("FAIL ");
    append(message);
    emit();
    hammer_call(HV_EXIT_GROUP, 1, 0, 0);
    for (;;) {}
}

static void require(int condition, const char *message)
{
    if (!condition)
        fail(message);
}

static uint32_t random_word(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

static uint64_t random_i8(uint32_t *state)
{
    uint64_t value = 0;
    for (unsigned lane = 0; lane < 8; ++lane)
        value |= (uint64_t)(random_word(state) & 255) << (8 * lane);
    return value;
}

static uint64_t random_bf16(uint32_t *state)
{
    uint64_t value = 0;
    for (unsigned lane = 0; lane < 4; ++lane) {
        uint32_t r = random_word(state);
        uint16_t bits = (uint16_t)((r & 0x8000) |
                                  ((122 + ((r >> 8) % 12)) << 7) |
                                  (r & 127));
        value |= (uint64_t)bits << (16 * lane);
    }
    return value;
}

static uint64_t hash_word(uint64_t hash, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        hash ^= (value >> (8 * i)) & 255;
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static void configure_counters(unsigned mode)
{
    require(hammer_call(HV_IOCTL, control_fd, mode ? 0x4801 : 0x4800, 0) == 0,
            "counter ioctl");
}

static void check_state(const uint64_t *expected, const char *message)
{
    uint64_t actual[8] __attribute__((aligned(8)));
    hammer_vx_save(actual);
    for (unsigned i = 0; i < 8; ++i)
        require(actual[i] == expected[i], message);
}

static void clobber_state(uint64_t tag, uint64_t *saved)
{
    for (unsigned i = 0; i < 8; ++i)
        saved[i] = tag ^ (UINT64_C(0x0102040810204080) * (i + 1));
    hammer_vx_restore(saved);
}

static void signal_handler(int signal, void *info, void *context)
{
    (void)info;
    (void)context;
    uint64_t clobbered[8] __attribute__((aligned(8)));
    if (signal == HV_SIGUSR2) {
        ++nested_count;
        clobber_state(UINT64_C(0x8877665544332211), clobbered);
        return;
    }
    ++signal_count;
    check_state(task_state, "signal entry vector state");
    clobber_state(UINT64_C(0x1122334455667788), clobbered);
    require(hammer_call(HV_KILL, hammer_call(HV_GETPID, 0, 0, 0),
                        HV_SIGUSR2, 0) == 0, "nested signal delivery");
    check_state(clobbered, "nested sigreturn vector state");
}

static void fault_handler(int signal, void *info, void *context)
{
    hammer_ucontext *uc = context;
    uintptr_t address = *(uintptr_t *)((uint8_t *)info + 16);
    require(signal == expected_signal, "unexpected fault signal");
    require(address == expected_address, "fault si_addr");
    check_state(task_state, "faulting custom changed vector state");
    ++fault_count;
    expected_signal = 0;
    /* All fault probes are explicitly emitted four-byte custom/CSR opcodes. */
    uc->gpr[0] += 4;
}

static void install_handlers(void)
{
    hammer_stack stack = {signal_stack, 0, 0, sizeof(signal_stack)};
    hammer_sigaction action = {signal_handler,
        HV_SA_SIGINFO | HV_SA_ONSTACK | HV_SA_NODEFER, 0, 0};
    require(hammer_call(HV_SIGALTSTACK, (long)&stack, 0, 0) == 0, "sigaltstack");
    require(hammer_syscall(HV_RT_SIGACTION, HV_SIGUSR1, (long)&action,
                          0, 8, 0, 0) == 0, "SIGUSR1 handler");
    require(hammer_syscall(HV_RT_SIGACTION, HV_SIGUSR2, (long)&action,
                          0, 8, 0, 0) == 0, "SIGUSR2 handler");
    action.handler = fault_handler;
    action.flags = HV_SA_SIGINFO | HV_SA_ONSTACK;
    require(hammer_syscall(HV_RT_SIGACTION, HV_SIGSEGV, (long)&action,
                          0, 8, 0, 0) == 0, "SIGSEGV handler");
    require(hammer_syscall(HV_RT_SIGACTION, HV_SIGBUS, (long)&action,
                          0, 8, 0, 0) == 0, "SIGBUS handler");
    require(hammer_syscall(HV_RT_SIGACTION, HV_SIGILL, (long)&action,
                          0, 8, 0, 0) == 0, "SIGILL handler");
}

static void faults(void)
{
    long mapped = hammer_syscall(HV_MMAP, 0, 8192, 3, 0x22, -1, 0);
    require(mapped > 0, "anonymous Sv39 mmap");
    uint64_t *memory = (uint64_t *)mapped;
    for (unsigned i = 0; i < 8; ++i)
        task_state[i] = UINT64_C(0x5aa50000deadbeef) ^ i;
    hammer_vx_restore(task_state);
    memory[0] = task_state[0];
    HAMMER_VLOAD(0, memory);
    check_state(task_state, "successful custom user load");

    require(hammer_call(HV_MPROTECT, mapped, 4096, 0) == 0, "PROT_NONE");
    expected_signal = HV_SIGSEGV;
    expected_address = (uintptr_t)memory;
    HAMMER_VLOAD(0, memory);
    require(!expected_signal, "missing protected vload fault");
    require(hammer_call(HV_MPROTECT, mapped, 4096, 1) == 0, "PROT_READ");
    expected_signal = HV_SIGSEGV;
    expected_address = (uintptr_t)memory;
    HAMMER_VSTORE(0, memory);
    require(!expected_signal, "missing protected vstore fault");
    require(memory[0] == task_state[0], "faulting store memory changed");
    require(hammer_call(HV_MPROTECT, mapped, 4096, 3) == 0, "PROT_READ_WRITE");
    expected_signal = HV_SIGBUS;
    expected_address = (uintptr_t)memory + 1;
    HAMMER_VLOAD(0, (uint8_t *)memory + 1);
    require(!expected_signal, "missing misaligned vload fault");
    require(hammer_call(HV_MUNMAP, mapped + 4096, 4096, 0) == 0, "unmap second page");
    expected_signal = HV_SIGSEGV;
    expected_address = (uintptr_t)memory + 4096;
    HAMMER_VLOAD(0, (uint8_t *)memory + 4096);
    require(!expected_signal, "missing unmapped vload fault");
    check_state(task_state, "fault sigreturn state");
    require(hammer_call(HV_MUNMAP, mapped, 4096, 0) == 0, "unmap first page");
    begin("FAULTS");
    append(" successful_vload=1 rejected=");
    decimal(fault_count);
    append(" Sv39_mmap_mprotect=1 state_preserved=1");
    emit();
}

static void context_task(unsigned identity)
{
    uint64_t pause[2] = {0, 1000000};
    unsigned delivered = signal_count, nested = nested_count;
    for (unsigned i = 0; i < 8; ++i)
        task_state[i] = UINT64_C(0xfedcba9800000000) ^ ((uint64_t)identity << 32) ^
                        (UINT64_C(0x0101010101010101) * (i + 1));
    hammer_vx_restore(task_state);
    for (unsigned iteration = 0; iteration < 64; ++iteration) {
        require(hammer_call(HV_SCHED_YIELD, 0, 0, 0) == 0, "sched_yield");
        check_state(task_state, "competing task context");
        require(hammer_call(HV_KILL, hammer_call(HV_GETPID, 0, 0, 0),
                            HV_SIGUSR1, 0) == 0, "signal delivery");
        check_state(task_state, "sigreturn restored all vectors");
        long result = hammer_call(HV_NANOSLEEP, (long)pause, 0, 0);
        require(result == 0 || result == -4, "nanosleep timer scheduling");
    }
    require(signal_count - delivered == 64 && nested_count - nested == 64,
            "task signal counts");
    begin("CONTEXT");
    append(" task="); decimal(identity);
    append(" switches=64 signals=64 nested=64 vr0_to_vr7=1");
    emit();
}

static void contexts(void)
{
    long children[2];
    for (unsigned task = 0; task < 2; ++task) {
        children[task] = hammer_syscall(HV_CLONE, 17, 0, 0, 0, 0, 0);
        require(children[task] >= 0, "fork two U tasks");
        if (!children[task]) {
            check_state(task_state, "fork inherited vector state");
            context_task(task + 1);
            hammer_call(HV_EXIT_GROUP, 0, 0, 0);
            for (;;) {}
        }
    }
    for (unsigned task = 0; task < 2; ++task) {
        int status = -1;
        long result;
        do {
            result = hammer_syscall(HV_WAIT4, children[task], (long)&status,
                                    0, 0, 0, 0);
        } while (result == -4);
        require(result == children[task] && !status, "context child failed");
    }
    check_state(task_state, "parent state after competing children");
}

__attribute__((noinline))
static uint64_t scalar_int(const uint64_t *a, const uint64_t *b, unsigned groups)
{
    uint64_t sum = 0;
    for (unsigned i = 0; i < groups; ++i)
        sum += (uint64_t)hammer_i8_dot(a[i], b[i]);
    return sum;
}

__attribute__((noinline))
static uint64_t vector_int(const uint64_t *a, const uint64_t *b, unsigned groups)
{
    uint64_t sum = 0, value;
    for (unsigned i = 0; i < groups; ++i) {
        HAMMER_VLOAD(0, a + i);
        HAMMER_VLOAD(7, b + i);
        HAMMER_VDOT_I8(value, 0, 7);
        sum += value;
    }
    return sum;
}

__attribute__((noinline))
static uint64_t scalar_bf(const uint64_t *a, const uint64_t *b, unsigned groups)
{
    uint32_t sum = 0;
    for (unsigned i = 0; i < groups; ++i)
        sum = hammer_fp32_add(sum, hammer_bf16_dot(a[i], b[i]));
    return sum;
}

__attribute__((noinline))
static uint64_t vector_bf(const uint64_t *a, const uint64_t *b, unsigned groups)
{
    uint32_t sum = 0;
    uint64_t value;
    for (unsigned i = 0; i < groups; ++i) {
        HAMMER_VLOAD(1, a + i);
        HAMMER_VLOAD(6, b + i);
        HAMMER_VDOT_BF16(value, 1, 6);
        sum = hammer_fp32_add(sum, (uint32_t)value);
    }
    return sum;
}

static uint64_t median(uint64_t *values)
{
    for (unsigned i = 1; i < 32; ++i) {
        uint64_t value = values[i];
        unsigned j = i;
        while (j && values[j - 1] > value) {
            values[j] = values[j - 1];
            --j;
        }
        values[j] = value;
    }
    return values[15] + ((values[16] - values[15]) >> 1);
}

static void benchmark(unsigned seed, unsigned bf)
{
    uint64_t scalar_cycles[32], vector_cycles[32];
    uint64_t *a = bf ? bf_a : int_a, *b = bf ? bf_b : int_b;
    unsigned groups = bf ? 64 : 32;
    uint64_t (*scalar)(const uint64_t *, const uint64_t *, unsigned) =
        bf ? scalar_bf : scalar_int;
    uint64_t (*vector)(const uint64_t *, const uint64_t *, unsigned) =
        bf ? vector_bf : vector_int;
    uint64_t expected = scalar(a, b, groups);
    require(vector(a, b, groups) == expected, "warm dot benchmark result");
    configure_counters(1);
    uint64_t mac_start = hammer_hpm6();
    for (unsigned repeat = 0; repeat < 32; ++repeat) {
        uint64_t begin_cycle, result;
        /* Alternate matched order; both include reduction and operand loads. */
        if (!(repeat & 1)) {
            begin_cycle = hammer_cycle();
            result = scalar(a, b, groups);
            scalar_cycles[repeat] = hammer_cycle() - begin_cycle;
            require(result == expected, "scalar timed dot mismatch");
        }
        begin_cycle = hammer_cycle();
        result = vector(a, b, groups);
        vector_cycles[repeat] = hammer_cycle() - begin_cycle;
        require(result == expected, "vector timed dot mismatch");
        if (repeat & 1) {
            begin_cycle = hammer_cycle();
            result = scalar(a, b, groups);
            scalar_cycles[repeat] = hammer_cycle() - begin_cycle;
            require(result == expected, "scalar timed dot mismatch");
        }
        observed_sink = result;
    }
    uint64_t mac_delta = hammer_hpm6() - mac_start;
    require(mac_delta == 32 * 256, "complete benchmark committed MAC delta");
    uint64_t sc = median(scalar_cycles), vc = median(vector_cycles);
    begin("BENCH");
    append(" seed="); decimal(seed);
    append(bf ? " kind=bf16" : " kind=int8");
    append(" reduction=256 repetitions=32 scalar_complete_cycles="); decimal(sc);
    append(" vector_complete_cycles="); decimal(vc);
    append(" result="); hex(expected);
    append(" macs="); decimal(mac_delta);
    append(" speedup_numerator="); decimal(sc);
    append(" speedup_denominator="); decimal(vc);
    emit();
    require(sc > vc && vc, "required warm complete-kernel speedup <=1");

    HAMMER_VLOAD(0, a);
    HAMMER_VLOAD(7, b);
    uint64_t start = hammer_cycle(), arithmetic = 0;
    for (unsigned repeat = 0; repeat < 32; ++repeat) {
        uint64_t value;
        if (bf)
            HAMMER_VDOT_BF16(value, 0, 7);
        else
            HAMMER_VDOT_I8(value, 0, 7);
        arithmetic ^= value;
    }
    uint64_t elapsed = hammer_cycle() - start;
    observed_sink = arithmetic;
    begin("ARITH");
    append(" seed="); decimal(seed);
    append(bf ? " kind=bf16" : " kind=int8");
    append(" repetitions=32 vector_arithmetic_cycles="); decimal(elapsed);
    append(" excludes_loads=1 not_speed_acceptance=1");
    emit();
}

static void directed(unsigned seed)
{
    static const uint64_t a[] = {
        UINT64_C(0x0000000000000000), UINT64_C(0x8000800080008000),
        UINT64_C(0x3f803f803f803f80), UINT64_C(0x7f807f807f807f80),
        UINT64_C(0x7fc17fc17fc17fc1), UINT64_C(0x0001000100010001),
        UINT64_C(0x0080008000800080), UINT64_C(0x3f803f80bf80bf80),
        UINT64_C(0x7f7f7f7f7f7f7f7f), UINT64_C(0x3f813f813f813f81),
        UINT64_C(0x3f800001bf800001), UINT64_C(0x8080008080800080)
    };
    static const uint64_t b[] = {
        UINT64_C(0x3f803f803f803f80), UINT64_C(0x3f803f803f803f80),
        UINT64_C(0x8000800080008000), UINT64_C(0x0000000000000000),
        UINT64_C(0x3f803f803f803f80), UINT64_C(0x3f803f803f803f80),
        UINT64_C(0x3f003f003f003f00), UINT64_C(0x3f803f803f803f80),
        UINT64_C(0x7f7f7f7f7f7f7f7f), UINT64_C(0x3f813f813f813f81),
        UINT64_C(0x3f803f803f803f80), UINT64_C(0x3f003f003f003f00)
    };
    uint64_t value;
    for (unsigned i = 0; i < sizeof(a) / sizeof(a[0]); ++i) {
        HAMMER_VLOAD(2, a + i);
        HAMMER_VLOAD(5, b + i);
        HAMMER_VDOT_BF16(value, 2, 5);
        uint32_t expected = hammer_bf16_dot(a[i], b[i]);
        require(value == expected, "BF16 directed IEEE mismatch");
        begin("CASE");
        append(" seed="); decimal(seed);
        append(" kind=bf16 id="); decimal(i);
        append(" a="); hex(a[i]); append(" b="); hex(b[i]);
        append(" result="); hex(value); append(" expected="); hex(expected);
        emit();
    }
    uint64_t packed = UINT64_C(0x8080808080808080);
    HAMMER_VLOAD(3, &packed);
    HAMMER_VDOT_I8(value, 3, 3);
    require(value == 131072, "INT8 -128 endpoint");
    HAMMER_VRMS_ACC(value, 3, UINT64_MAX);
    require(value == 131071, "RMS modulo endpoint");
}

static void tiles(unsigned seed, uint32_t *state)
{
    uint64_t digest_i = UINT64_C(14695981039346656037);
    uint64_t digest_b = digest_i;
    for (unsigned row = 0; row < 8; ++row)
        for (unsigned group = 0; group < 8; ++group) {
            int_matrix_a[row][group] = random_i8(state);
            /* Each row of B stores a column of the logical K-by-N matrix. */
            int_matrix_b[row][group] = random_i8(state);
        }
    for (unsigned row = 0; row < 4; ++row)
        for (unsigned group = 0; group < 8; ++group) {
            bf_matrix_a[row][group] = random_bf16(state);
            bf_matrix_b[row][group] = random_bf16(state);
        }
    configure_counters(1);
    uint64_t mac_start = hammer_hpm6(), start = hammer_cycle();
    for (unsigned row = 0; row < 8; ++row)
        for (unsigned column = 0; column < 8; ++column) {
            uint64_t scalar = scalar_int(int_matrix_a[row], int_matrix_b[column], 8);
            uint64_t vector = vector_int(int_matrix_a[row], int_matrix_b[column], 8);
            require(vector == scalar, "INT8 8x8x64 tensor tile");
            digest_i = hash_word(digest_i, vector);
        }
    for (unsigned row = 0; row < 4; ++row)
        for (unsigned column = 0; column < 4; ++column) {
            uint64_t scalar = scalar_bf(bf_matrix_a[row], bf_matrix_b[column], 8);
            uint64_t vector = vector_bf(bf_matrix_a[row], bf_matrix_b[column], 8);
            require(vector == scalar, "BF16 4x4x32 tensor tile");
            digest_b = hash_word(digest_b, vector);
        }
    uint64_t cycles = hammer_cycle() - start;
    uint64_t macs = hammer_hpm6() - mac_start;
    require(macs == 4096 + 512, "tensor MAC count");
    begin("TILE");
    append(" seed="); decimal(seed);
    append(" int8_shape=8x8x64 bf16_shape=4x4x32 int8_hash="); hex(digest_i);
    append(" bf16_hash="); hex(digest_b);
    append(" committed_macs="); decimal(macs);
    append(" comparison_complete_cycles="); decimal(cycles);
    emit();
}

static void seed_work(unsigned seed)
{
    uint32_t state = seed;
    uint64_t rms_seed = UINT64_C(0xffffffffffffff00), rms_expected = rms_seed;
    uint64_t rms_actual = rms_seed;
    for (unsigned i = 0; i < 32; ++i) {
        int_a[i] = random_i8(&state);
        int_b[i] = random_i8(&state);
    }
    for (unsigned i = 0; i < 64; ++i) {
        bf_a[i] = random_bf16(&state);
        bf_b[i] = random_bf16(&state);
    }
    directed(seed);
    configure_counters(1);
    uint64_t mac_start = hammer_hpm6();
    for (unsigned i = 0; i < 32; ++i) {
        HAMMER_VLOAD(4, int_a + i);
        HAMMER_VRMS_ACC(rms_actual, 4, rms_actual);
        rms_expected = hammer_i8_rms(int_a[i], rms_expected);
    }
    require(rms_actual == rms_expected, "RMS reduction");
    require(hammer_hpm6() - mac_start == 256, "RMS committed MAC count");
    begin("RMS");
    append(" seed="); decimal(seed);
    append(" lanes=256 scalar_seed="); hex(rms_seed);
    append(" result="); hex(rms_actual); emit();
    benchmark(seed, 0);
    benchmark(seed, 1);
    tiles(seed, &state);

    configure_counters(0);
    uint64_t lookup1 = hammer_hpm3(), hit1 = hammer_hpm4();
    uint64_t lookup2 = hammer_hpm5(), hit2 = hammer_hpm6();
    require(vector_int(int_a, int_b, 32) == scalar_int(int_a, int_b, 32),
            "cache measurement result");
    uint64_t dlookup1 = hammer_hpm3() - lookup1, dhit1 = hammer_hpm4() - hit1;
    uint64_t dlookup2 = hammer_hpm5() - lookup2, dhit2 = hammer_hpm6() - hit2;
    begin("CACHE");
    append(" seed="); decimal(seed);
    append(" selectors=1,2,3,4 l1_hits="); decimal(dhit1);
    append(" l1_lookups="); decimal(dlookup1);
    append(" l2_hits="); decimal(dhit2);
    append(" l2_lookups="); decimal(dlookup2);
    append(" zero_denominator=undefined rates_are_demand_not_retired=1");
    emit();
}

void hammer_init_main(void)
{
    static const unsigned seeds[] = {17, 43, 89};
    /* Linux opens the initramfs /dev/console before exec of PID 1. */
    begin("USER");
    append(" pid="); decimal((uint64_t)hammer_call(HV_GETPID, 0, 0, 0));
    append(" abi=rv64-lp64 scalar=RV64IM custom=0x0b");
    emit();
    require(hammer_call(HV_GETPID, 0, 0, 0) == 1, "genuine /init PID");
    require(hammer_syscall(HV_MOUNT, (long)"devtmpfs", (long)"/dev",
                          (long)"devtmpfs", 0, 0, 0) == 0, "mount devtmpfs");
    require(hammer_syscall(HV_MOUNT, (long)"proc", (long)"/proc",
                          (long)"proc", 0, 0, 0) == 0, "mount proc");
    control_fd = (int)hammer_call(HV_OPENAT, HV_AT_FDCWD,
                                   (long)"/dev/hammer-v5", 2);
    require(control_fd >= 0, "kernel vector/counter ABI device");
    install_handlers();
    faults();
    contexts();
    for (unsigned i = 0; i < sizeof(seeds) / sizeof(seeds[0]); ++i)
        seed_work(seeds[i]);
    begin("DONE");
    append(" seeds=17,43,89 numerical=1 context=1 faults=1 measured_speed=1");
    emit();
    for (;;) {
        uint64_t pause[2] = {1, 0};
        hammer_call(HV_NANOSLEEP, (long)pause, 0, 0);
    }
}
