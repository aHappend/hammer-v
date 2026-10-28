"""Analytical anchors for the independently authored instruction-set oracle."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from cycle import equal
from encoding import i, r
from iss import MASK, arithmetic, decode


def main():
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
