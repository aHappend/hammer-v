"""Analytical anchors for the independently authored instruction-set oracle."""

import sys
import struct
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from compiler import discover, load_elf
from cycle import equal
from encoding import i, r
from iss import MASK, arithmetic, decode
from retention import ToolFailure


def compiler_selection_checks():
    cases = (
        ({}, {"clang": "/fixture/clang", "clang-23": "/fixture/clang",
              "clang-18": "/fixture/clang-18"},
         ["/fixture/clang", "/fixture/clang-18"]),
        ({"RISCV_CC": "selected"}, {"selected": "/fixture/selected",
                                   "clang": "/fixture/clang"},
         ["/fixture/selected"]),
        ({"RISCV_CC": "missing"}, {"clang": "/fixture/clang"}, None),
        ({"RISCV_CC": ""}, {"clang": "/fixture/clang"}, None),
        ({}, {}, None),
    )
    for environment, available, expected in cases:
        with patch.dict("os.environ", environment, clear=True), \
                patch("compiler.shutil.which", side_effect=available.get):
            try:
                actual = discover()
            except ToolFailure as error:
                if expected is not None:
                    raise
                equal(str(error).startswith("PREREQUISITE_MISSING:"), True,
                      "compiler selection failure diagnostic")
            else:
                equal(actual, expected, "compiler selection policy")
    print(f"COMPILER_SELECTION_FIXTURES compared={len(cases)}; no compiler executed")


def compiler_elf_checks():
    image = bytearray(412)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", image, 0,
                     ident, 2, 243, 1, 0, 64, 128, 0, 64, 56, 1, 64, 3, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 408, 0, 0, 4, 4, 4)
    names = b"\0results\0_halt\0"
    image[320:320 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", image, 192,
                     0, 3, 0, 0, 320, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", image, 256,
                     0, 2, 0, 0, 336, 72, 1, 1, 8, 24)
    struct.pack_into("<IBBHQQ", image, 360, 1, 0x11, 0, 1, 0x10000000, 8)
    struct.pack_into("<IBBHQQ", image, 384, 9, 0x12, 0, 1, 0, 4)
    image[408:412] = b"\x13\x00\x00\x00"
    path = Path("synthetic-abi-fixture.elf")
    with patch.object(Path, "read_bytes", return_value=bytes(image)):
        code, memory, symbols, actual_path = load_elf(path)
    equal(code[0], 0x13, "ELF fixture instruction segment")
    equal(memory[0], 0, "ELF fixture initialized data")
    equal(symbols["results"], 0x10000000, "ELF fixture results symbol")
    equal(symbols["_halt"], 0, "ELF fixture halt symbol")
    equal(actual_path, path, "ELF fixture identity")
    for flags in (1, 2, 4, 8, 16, 0x80000000):
        struct.pack_into("<I", image, 48, flags)
        with patch.object(Path, "read_bytes", return_value=bytes(image)):
            try:
                load_elf(path)
            except ToolFailure as error:
                equal("compiled ELF requires" in str(error), True,
                      f"ELF ABI rejection diagnostic flags={flags:#x}")
            else:
                equal(True, False, f"ELF accepted unsupported ABI flags={flags:#x}")
    print("COMPILER_ELF_FIXTURES valid=1 rejected=6; no compiler or RTL executed")


def main():
    compiler_selection_checks()
    compiler_elf_checks()
    cases = (
        ("ADD", MASK, 1, 0), ("SUB", 0, 1, MASK),
        ("ADDW", 0x7fffffff, 1, 0xffffffff80000000),
        ("SRAW", 0x80000000, 31, MASK),
        ("SRLW", 0x80000000, 31, 1),
        ("MULH", 1 << 63, 1 << 63, 1 << 62),
        ("MULHSU", MASK, MASK, MASK),
        ("MULHU", MASK, MASK, MASK - 1),
        ("DIV", MASK - 6, 3, MASK - 1), ("REM", MASK - 6, 3, MASK),
        ("DIV", 7, MASK - 2, MASK - 1), ("REM", 7, MASK - 2, 1),
        ("DIV", 1 << 63, MASK, 1 << 63), ("REM", 1 << 63, MASK, 0),
        ("DIVU", 17, 0, MASK), ("DIV", MASK - 6, 0, MASK),
        ("REM", MASK - 6, 0, MASK - 6),
        ("DIVW", 0x80000000, MASK, 0xffffffff80000000),
        ("REMW", 0x80000000, MASK, 0),
        ("DIVUW", 1 << 32, 1, 0), ("REMUW", 0x80000000, 0, 0xffffffff80000000),
    )
    for name, a, b, expected in cases:
        equal(arithmetic(name, a, b, 0, 0), expected, f"analytical anchor {name}")
    for name in ("ADD", "SUB", "SLL", "SLT", "SLTU", "XOR", "SRL", "SRA",
                 "OR", "AND", "MUL", "MULH", "MULHSU", "MULHU", "DIV",
                 "DIVU", "REM", "REMU", "ADDW", "SUBW", "SLLW", "SRLW",
                 "SRAW", "MULW", "DIVW", "DIVUW", "REMW", "REMUW"):
        equal(decode(r(name, 3, 1, 2)).name, name, "assembler/decoder mnemonic")
    equal(decode(i("SLLI", 1, 2, 32)).name, "SLLI", "RV64 shift bit five is legal")
    equal(decode(0x04001013).name, "ILLEGAL", "reserved RV64 shift upper bits")
    print(f"ORACLE_ANCHORS compared={len(cases)}")


if __name__ == "__main__":
    main()
