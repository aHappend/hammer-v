"""Independent expected result buffers, including library CRC32 and SHA-256."""

import hashlib
import zlib

from compiler import compile_benchmark
from cycle import ComparisonFailure
from iss import MASK
from retention import ROOT, ToolFailure


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
    rows = [{"name": "c-" + NAMES[number], "number": number,
             "config": [16384, 8192, 1, 16], "status": "not_run",
             "stage": "not_reached", "required_result_words": len(expected(number)),
             "compared_result_words": None, "compared_retirements": None,
             "command_receipts": []} for number in numbers]
    campaign.benchmark_ledger.extend(rows)
    for row in rows:
        first_command = len(campaign.evidence.commands)
        try:
            row["stage"] = "compilation_and_elf_loading"
            program, memory, symbols, elf = compile_benchmark(campaign.evidence, row["number"])
            row["elf"] = str(elf.relative_to(ROOT))
            row["stage"] = "rtl_and_independent_comparisons"
            result = campaign.run(
                row["name"], program, tuple(row["config"]), data=memory,
                expected_trap=(symbols["_halt"], 11), limit=5000000,
                expected_buffer=(symbols["results"], expected(row["number"])))
            row.update(status="passed", stage="completed",
                       compared_result_words=row["required_result_words"],
                       compared_retirements=result["retired"])
        except (ComparisonFailure, ToolFailure, ValueError, OSError) as error:
            row.update(status="failed", error=str(error))
            raise
        finally:
            row["command_receipts"] = campaign.evidence.commands[first_command:]
