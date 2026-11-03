/* SPDX-License-Identifier: MIT */
#ifndef HAMMER_IEEE_H
#define HAMMER_IEEE_H

#include <stdint.h>

/* Software-only exact integer IEEE oracle. No host or scalar F arithmetic. */
#define HAMMER_QNAN UINT32_C(0x7fc00000)

static unsigned hammer_high64(uint64_t value)
{
    unsigned bit = 0;
    while (value >> 1) {
        value >>= 1;
        ++bit;
    }
    return bit;
}

static uint64_t hammer_round_shift(uint64_t value, unsigned shift)
{
    uint64_t kept, half, remainder;
    if (!shift)
        return value;
    if (shift > 64)
        return 0;
    if (shift == 64)
        return value > (UINT64_C(1) << 63);
    kept = value >> shift;
    half = UINT64_C(1) << (shift - 1);
    remainder = value & ((half << 1) - 1);
    return kept + (remainder > half || (remainder == half && (kept & 1)));
}

static uint32_t hammer_round_binary(uint64_t value, int exponent, uint32_t sign)
{
    unsigned high;
    int unbiased, shift;
    uint64_t rounded;
    if (!value)
        return sign;
    high = hammer_high64(value);
    unbiased = exponent + (int)high;
    if (unbiased < -126) {
        shift = -149 - exponent;
        rounded = shift >= 0 ? hammer_round_shift(value, (unsigned)shift) :
                              value << (unsigned)-shift;
        return sign | (uint32_t)rounded;
    }
    shift = (int)high - 23;
    rounded = shift >= 0 ? hammer_round_shift(value, (unsigned)shift) :
                          value << (unsigned)-shift;
    if (rounded == (UINT64_C(1) << 24)) {
        rounded >>= 1;
        ++unbiased;
    }
    if (unbiased > 127)
        return sign | UINT32_C(0x7f800000);
    return sign | ((uint32_t)(unbiased + 127) << 23) |
                  ((uint32_t)rounded & UINT32_C(0x7fffff));
}

static uint32_t hammer_bf16_product(uint16_t a, uint16_t b)
{
    unsigned ea = (a >> 7) & 255, eb = (b >> 7) & 255;
    unsigned ma = a & 127, mb = b & 127;
    uint32_t sign = (uint32_t)((a ^ b) & 0x8000) << 16;
    if ((ea == 255 && ma) || (eb == 255 && mb))
        return HAMMER_QNAN;
    if (ea == 255 || eb == 255) {
        if ((!ea && !ma) || (!eb && !mb))
            return HAMMER_QNAN;
        return sign | UINT32_C(0x7f800000);
    }
    if (ea)
        ma |= 128;
    if (eb)
        mb |= 128;
    return hammer_round_binary((uint64_t)ma * mb,
                               (ea ? (int)ea - 134 : -133) +
                               (eb ? (int)eb - 134 : -133), sign);
}

typedef struct {
    uint64_t limb[5];
} hammer_exact;

static hammer_exact hammer_expand32(uint32_t bits)
{
    hammer_exact result = {{0, 0, 0, 0, 0}};
    unsigned exponent = (bits >> 23) & 255;
    uint64_t significand = bits & UINT32_C(0x7fffff);
    unsigned shift = exponent ? exponent - 1 : 0;
    unsigned word = shift >> 6, offset = shift & 63;
    if (exponent)
        significand |= UINT32_C(0x800000);
    result.limb[word] = significand << offset;
    if (offset && word < 4)
        result.limb[word + 1] = significand >> (64 - offset);
    return result;
}

static int hammer_compare_exact(const hammer_exact *a, const hammer_exact *b)
{
    for (int i = 4; i >= 0; --i) {
        if (a->limb[i] != b->limb[i])
            return a->limb[i] > b->limb[i] ? 1 : -1;
    }
    return 0;
}

static unsigned hammer_exact_bit(const hammer_exact *a, unsigned bit)
{
    return (unsigned)((a->limb[bit >> 6] >> (bit & 63)) & 1);
}

static uint32_t hammer_pack_exact(const hammer_exact *a, uint32_t sign)
{
    int high = 319;
    unsigned shift;
    uint32_t kept = 0;
    unsigned sticky = 0;
    while (high >= 0 && !hammer_exact_bit(a, (unsigned)high))
        --high;
    if (high < 0)
        return sign;
    shift = high > 23 ? (unsigned)high - 23 : 0;
    for (unsigned i = 0; i < 24; ++i)
        kept |= hammer_exact_bit(a, shift + i) << i;
    if (shift) {
        for (unsigned i = 0; i + 1 < shift; ++i)
            sticky |= hammer_exact_bit(a, i);
        if (hammer_exact_bit(a, shift - 1) && (sticky || (kept & 1)))
            ++kept;
    }
    if (kept == UINT32_C(0x1000000)) {
        kept >>= 1;
        ++high;
    }
    if (high > 276)
        return sign | UINT32_C(0x7f800000);
    if (high < 23)
        return sign | kept;
    return sign | ((uint32_t)(high - 22) << 23) | (kept & UINT32_C(0x7fffff));
}

static uint32_t hammer_fp32_add(uint32_t a, uint32_t b)
{
    unsigned ea = (a >> 23) & 255, eb = (b >> 23) & 255;
    uint32_t sign_a = a & UINT32_C(0x80000000);
    uint32_t sign_b = b & UINT32_C(0x80000000);
    hammer_exact aa, bb, result;
    uint64_t carry = 0;
    if ((ea == 255 && (a & UINT32_C(0x7fffff))) ||
        (eb == 255 && (b & UINT32_C(0x7fffff))))
        return HAMMER_QNAN;
    if (ea == 255 || eb == 255) {
        if (ea == 255 && eb == 255 && sign_a != sign_b)
            return HAMMER_QNAN;
        return ea == 255 ? a : b;
    }
    aa = hammer_expand32(a);
    bb = hammer_expand32(b);
    if (sign_a == sign_b) {
        for (unsigned i = 0; i < 5; ++i) {
            __uint128_t sum = (__uint128_t)aa.limb[i] + bb.limb[i] + carry;
            result.limb[i] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }
        return hammer_pack_exact(&result, sign_a);
    }
    if (hammer_compare_exact(&aa, &bb) < 0) {
        hammer_exact temporary = aa;
        aa = bb;
        bb = temporary;
        sign_a = sign_b;
    }
    for (unsigned i = 0; i < 5; ++i) {
        uint64_t rhs = bb.limb[i] + carry;
        unsigned overflow = rhs < bb.limb[i];
        result.limb[i] = aa.limb[i] - rhs;
        carry = overflow || aa.limb[i] < rhs;
    }
    if (!hammer_compare_exact(&aa, &bb))
        return 0;
    return hammer_pack_exact(&result, sign_a);
}

static uint32_t hammer_bf16_dot(uint64_t a, uint64_t b)
{
    uint32_t product[4];
    for (unsigned i = 0; i < 4; ++i)
        product[i] = hammer_bf16_product((uint16_t)(a >> (16 * i)),
                                        (uint16_t)(b >> (16 * i)));
    return hammer_fp32_add(hammer_fp32_add(product[0], product[1]),
                          hammer_fp32_add(product[2], product[3]));
}

static int64_t hammer_i8_dot(uint64_t a, uint64_t b)
{
    int64_t sum = 0;
    for (unsigned i = 0; i < 8; ++i)
        sum += (int16_t)(int8_t)(a >> (8 * i)) *
               (int16_t)(int8_t)(b >> (8 * i));
    return sum;
}

static uint64_t hammer_i8_rms(uint64_t a, uint64_t seed)
{
    for (unsigned i = 0; i < 8; ++i) {
        int16_t lane = (int8_t)(a >> (8 * i));
        seed += (uint64_t)(lane * lane);
    }
    return seed;
}
#endif
