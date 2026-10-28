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
    image = bytearray(528)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", image, 0,
                     ident, 2, 243, 1, 0, 64, 192, 0, 64, 56, 2, 64, 3, 0)
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 512, 0, 0, 4, 4, 4)
    struct.pack_into("<IIQQQQQQ", image, 120,
                     1, 6, 520, 0x10000000, 0x10000000, 8, 16, 8)
    names = b"\0results\0_halt\0"
    image[400:400 + len(names)] = names
    struct.pack_into("<IIQQQQIIQQ", image, 256,
                     0, 3, 0, 0, 400, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", image, 320,
                     0, 2, 0, 0, 432, 72, 1, 1, 8, 24)
    struct.pack_into("<IBBHQQ", image, 456, 1, 0x11, 0, 1, 0x10000000, 8)
    struct.pack_into("<IBBHQQ", image, 480, 9, 0x12, 0, 1, 0, 4)
    image[512:516] = b"\x13\x00\x00\x00"
    image[520:528] = (123).to_bytes(8, "little")
    path = Path("synthetic-abi-fixture.elf")
    with patch.object(Path, "read_bytes", return_value=bytes(image)):
        code, memory, symbols, actual_path = load_elf(path)
    equal(code[0], 0x13, "ELF fixture instruction segment")
    equal(memory[0], 123, "ELF fixture initialized data")
    equal(memory[1], 0, "ELF fixture zero-filled BSS")
    equal(symbols["results"], 0x10000000, "ELF fixture results symbol")
    equal(symbols["_halt"], 0, "ELF fixture halt symbol")
    equal(actual_path, path, "ELF fixture identity")
    invalid = []
    for label, offset, fmt, value in (
            ("missing executable segment", 64, "<I", 0),
            ("non-executable entry", 68, "<I", 4),
            ("relocatable image", 16, "<H", 1),
            ("bad ELF version", 20, "<I", 0),
            ("bad header size", 52, "<H", 0),
            ("bad program entry size", 54, "<H", 0),
            ("program table outside file", 32, "<Q", len(image)),
            ("bad section entry size", 58, "<H", 0),
            ("section table outside file", 40, "<Q", len(image)),
            ("segment payload outside file", 72, "<Q", len(image)),
            ("segment file larger than memory", 96, "<Q", 8),
            ("segment high-address alias", 80, "<Q", 1 << 32),
            ("invalid string-table index", 360, "<I", 3),
            ("bad symbol entry size", 376, "<Q", 0),
            ("string table outside file", 280, "<Q", len(image)),
            ("symbol table outside file", 344, "<Q", len(image)),
            ("symbol name outside strings", 456, "<I", len(names)),
            ("unaligned halt symbol", 488, "<Q", 2),
            ("unloaded results symbol", 464, "<Q", 0x10000010)):
        corrupted = bytearray(image)
        struct.pack_into(fmt, corrupted, offset, value)
        invalid.append((label, bytes(corrupted)))
    corrupted = bytearray(image)
    corrupted[400 + len(names) - 1] = ord("x")
    invalid += [("truncated header", bytes(image[:32])),
                ("unterminated symbol name", bytes(corrupted))]
    for flags in (1, 2, 4, 8, 16, 0x80000000):
        corrupted = bytearray(image)
        struct.pack_into("<I", corrupted, 48, flags)
        invalid.append((f"unsupported ABI flags={flags:#x}", bytes(corrupted)))
    for label, corrupted in invalid:
        with patch.object(Path, "read_bytes", return_value=corrupted):
            try:
                load_elf(path)
            except ToolFailure as error:
                equal(bool(str(error)), True, f"ELF rejection diagnostic: {label}")
            else:
                equal(True, False, f"ELF accepted {label}")
    print(f"COMPILER_ELF_FIXTURES valid=1 rejected={len(invalid)}; no compiler or RTL executed")


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
