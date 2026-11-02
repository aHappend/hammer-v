#ifndef HAMMER_V5_ISA_H
#define HAMMER_V5_ISA_H

#include <stdint.h>

#define HAMMER_STRINGIFY_INNER(value) #value
#define HAMMER_STRINGIFY(value) HAMMER_STRINGIFY_INNER(value)
#define HAMMER_VECTOR_FIELD(index) "x" HAMMER_STRINGIFY(index)
#define HAMMER_CHECK_VECTOR(index) \
    _Static_assert((index) >= 0 && (index) < 8, "vector index must be 0..7")

/* The assembly xN fields select vector registers, not scalar operands. */
#define HAMMER_VLOAD(index, address) do { \
    HAMMER_CHECK_VECTOR(index); \
    const void *hammer_address_ = (address); \
    __asm__ volatile (".insn r 0x0b, 0, 0, " HAMMER_VECTOR_FIELD(index) \
                      ", %0, x0" : : "r" (hammer_address_) : "memory"); \
} while (0)

#define HAMMER_VSTORE(index, address) do { \
    HAMMER_CHECK_VECTOR(index); \
    void *hammer_address_ = (address); \
    __asm__ volatile (".insn r 0x0b, 4, 0, x0, %0, " \
                      HAMMER_VECTOR_FIELD(index) \
                      : : "r" (hammer_address_) : "memory"); \
} while (0)

#define HAMMER_VDOT_I8(result, source_a, source_b) do { \
    HAMMER_CHECK_VECTOR(source_a); \
    HAMMER_CHECK_VECTOR(source_b); \
    uint64_t hammer_result_; \
    __asm__ volatile (".insn r 0x0b, 1, 0, %0, " \
                      HAMMER_VECTOR_FIELD(source_a) ", " \
                      HAMMER_VECTOR_FIELD(source_b) \
                      : "=r" (hammer_result_) : : "memory"); \
    (result) = hammer_result_; \
} while (0)

#define HAMMER_VDOT_BF16(result, source_a, source_b) do { \
    HAMMER_CHECK_VECTOR(source_a); \
    HAMMER_CHECK_VECTOR(source_b); \
    uint64_t hammer_result_; \
    __asm__ volatile (".insn r 0x0b, 2, 0, %0, " \
                      HAMMER_VECTOR_FIELD(source_a) ", " \
                      HAMMER_VECTOR_FIELD(source_b) \
                      : "=r" (hammer_result_) : : "memory"); \
    (result) = hammer_result_; \
} while (0)

#define HAMMER_VRMS_ACC(result, source, seed) do { \
    HAMMER_CHECK_VECTOR(source); \
    uint64_t hammer_seed_ = (seed), hammer_result_; \
    __asm__ volatile (".insn r 0x0b, 3, 0, %0, " \
                      HAMMER_VECTOR_FIELD(source) ", %1" \
                      : "=r" (hammer_result_) : "r" (hammer_seed_) : "memory"); \
    (result) = hammer_result_; \
} while (0)

static inline uint64_t hammer_cycle(void)
{
    uint64_t value;
    __asm__ volatile ("rdcycle %0" : "=r" (value) : : "memory");
    return value;
}

static inline uint64_t hammer_instret(void)
{
    uint64_t value;
    __asm__ volatile ("rdinstret %0" : "=r" (value) : : "memory");
    return value;
}

static inline uint64_t hammer_hpm3(void)
{
    uint64_t value;
    __asm__ volatile ("csrr %0, 0xc03" : "=r" (value) : : "memory");
    return value;
}

static inline uint64_t hammer_hpm4(void)
{
    uint64_t value;
    __asm__ volatile ("csrr %0, 0xc04" : "=r" (value) : : "memory");
    return value;
}

static inline uint64_t hammer_hpm5(void)
{
    uint64_t value;
    __asm__ volatile ("csrr %0, 0xc05" : "=r" (value) : : "memory");
    return value;
}

static inline uint64_t hammer_hpm6(void)
{
    uint64_t value;
    __asm__ volatile ("csrr %0, 0xc06" : "=r" (value) : : "memory");
    return value;
}

static inline void hammer_fence(void)
{
    __asm__ volatile ("fence rw, rw" : : : "memory");
}

#endif
