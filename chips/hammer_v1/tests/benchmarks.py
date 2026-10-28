"""Independent expected result buffers, including library CRC32 and SHA-256."""

import hashlib
import zlib

from compiler import compile_benchmark
from iss import MASK


NAMES = ("accumulation", "overlapping-move", "division", "matrix", "crc32", "sha256")


def expected(number):
    values = [j * 17 + 3 for j in range(128)]
    if number == 0:
        return [sum(values)]
    if number == 1:
        data = bytearray(v & 255 for v in values[:64])
        data[13:50] = bytes(data[4:41])
        data[2:31] = bytes(data[17:46])
        return list(data)
    if number == 2:
        output = []
        for j in range(16):
            a, b = values[j] * 1234567, values[j + 1]
            if j & 1:
                a = -a
            if j & 2:
                b = -b
            quotient = abs(a) // abs(b)
            if (a < 0) != (b < 0):
                quotient = -quotient
            output += [quotient & MASK, (a - quotient * b) & MASK,
                       (a & MASK) // (b & MASK), (a & MASK) % (b & MASK)]
        return output
    if number == 3:
        return [sum(values[4 * row + k] * values[16 + 4 * k + col] for k in range(4))
                for row in range(4) for col in range(4)]
    message = bytes((j * 17 + 3) & 255 for j in range(257))
    return [zlib.crc32(message)] if number == 4 else list(hashlib.sha256(message).digest())


def run_benchmarks(campaign, numbers=range(6)):
    for number in numbers:
        program, memory, symbols, elf = compile_benchmark(campaign.evidence, number)
        campaign.run("c-" + NAMES[number], program, (16384, 8192, 1, 16), data=memory,
                     expected_trap=(symbols["_halt"], 11), limit=5000000,
                     expected_buffer=(symbols["results"], expected(number)))
