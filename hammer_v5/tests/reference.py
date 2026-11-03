"""Architectural numerical rules using exact rationals, never host floats."""
from fractions import Fraction

MASK64 = (1 << 64) - 1
NAN32 = 0x7FC00000


def lanes(value, width, count, signed=False):
    mask = (1 << width) - 1
    result = [(value >> (width * i)) & mask for i in range(count)]
    if signed:
        result = [v - (1 << width) if v >> (width - 1) else v for v in result]
    return result


def int8_dot(a, b):
    return sum(x * y for x, y in zip(lanes(a, 8, 8, True),
                                    lanes(b, 8, 8, True))) & MASK64


def rms(a, seed):
    return (seed + sum(x * x for x in lanes(a, 8, 8, True))) & MASK64


def power2(exponent):
    return Fraction(1 << exponent) if exponent >= 0 else Fraction(1, 1 << -exponent)


def unpack32(bits):
    sign, exponent, fraction = bits >> 31, (bits >> 23) & 255, bits & 0x7FFFFF
    if exponent == 255:
        return ("nan" if fraction else "inf"), sign, None
    magnitude = ((1 << 23) + fraction) if exponent else fraction
    value = magnitude * power2((exponent - 127 if exponent else -126) - 23)
    return "finite", sign, -value if sign else value


def nearest_even(value):
    integer, remainder = divmod(value.numerator, value.denominator)
    twice = 2 * remainder
    return integer + (twice > value.denominator or
                      (twice == value.denominator and integer & 1))


def round32(value, zero_sign=0):
    if not value:
        return zero_sign << 31
    sign = int(value < 0)
    value = abs(value)
    exponent = value.numerator.bit_length() - value.denominator.bit_length()
    if value < power2(exponent):
        exponent -= 1
    quantum = max(exponent - 23, -149)
    significand = nearest_even(value / power2(quantum))
    if not significand:
        return sign << 31
    if exponent < -126:
        # Rounding the largest subnormal upward naturally sets the normal exponent.
        return (sign << 31) | significand
    if significand == 1 << 24:
        significand >>= 1
        exponent += 1
    if exponent > 127:
        return (sign << 31) | 0x7F800000
    return (sign << 31) | ((exponent + 127) << 23) | (significand & 0x7FFFFF)


def multiply32(a, b):
    ka, sa, va = unpack32(a)
    kb, sb, vb = unpack32(b)
    if "nan" in (ka, kb):
        return NAN32
    if (ka == "inf" and kb == "finite" and not vb or
            kb == "inf" and ka == "finite" and not va):
        return NAN32
    if "inf" in (ka, kb):
        return ((sa ^ sb) << 31) | 0x7F800000
    return round32(va * vb, sa ^ sb)


def add32(a, b):
    ka, sa, va = unpack32(a)
    kb, sb, vb = unpack32(b)
    if "nan" in (ka, kb) or (ka == kb == "inf" and sa != sb):
        return NAN32
    if ka == "inf":
        return a
    if kb == "inf":
        return b
    return round32(va + vb, sa & sb)


def bf16_dot(a, b):
    products = [multiply32(x << 16, y << 16)
                for x, y in zip(lanes(a, 16, 4), lanes(b, 16, 4))]
    return add32(add32(products[0], products[1]),
                 add32(products[2], products[3]))


def self_check():
    assert multiply32(0x3F800000, 0x3F800000) == 0x3F800000
    assert multiply32(0x7F800000, 0) == NAN32
    assert add32(0x7F800000, 0xFF800000) == NAN32
    assert add32(0x80000000, 0x80000000) == 0x80000000
    assert add32(0x80000000, 0) == 0
    assert add32(1, 1) == 2
    assert round32(power2(-150)) == 0
    assert round32(3 * power2(-150)) == 2
    assert round32(1 + power2(-24)) == 0x3F800000
    assert round32(1 + 3 * power2(-24)) == 0x3F800002
    assert round32((1 << 24) * power2(-150)) == 0x00800000
    assert int8_dot(0x8080808080808080, 0x7F7F7F7F7F7F7F7F) == (-130048 & MASK64)
    assert rms(0x8080808080808080, MASK64) == 131071
