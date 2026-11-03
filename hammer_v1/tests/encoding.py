"""Program assembly helpers; the oracle independently decodes instruction words."""

from iss import M_NAMES


def r(name, rd, rs1, rs2):
    base = name[:-1] if name.endswith("W") else name
    table = {
        "ADD": (0, 0), "SUB": (0, 32), "SLL": (1, 0), "SLT": (2, 0),
        "SLTU": (3, 0), "XOR": (4, 0), "SRL": (5, 0), "SRA": (5, 32),
        "OR": (6, 0), "AND": (7, 0),
    }
    if name in M_NAMES:
        f3, f7 = ("MUL", "MULH", "MULHSU", "MULHU", "DIV", "DIVU", "REM", "REMU").index(base), 1
    else:
        f3, f7 = table[base]
    return f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | (0x3b if name.endswith("W") else 0x33)


def i(name, rd, rs1, immediate):
    table = {"ADDI": 0, "SLTI": 2, "SLTIU": 3, "XORI": 4, "ORI": 6, "ANDI": 7,
             "SLLI": 1, "SRLI": 5, "SRAI": 5}
    base = name[:-1] if name.endswith("W") else name
    if base == "SRAI":
        immediate |= 0x400
    return (immediate & 4095) << 20 | rs1 << 15 | table[base] << 12 | rd << 7 | (0x1b if name.endswith("W") else 0x13)


def load(name, rd, rs1, offset=0):
    f3 = ("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU").index(name)
    return (offset & 4095) << 20 | rs1 << 15 | f3 << 12 | rd << 7 | 3


def store(name, rs2, rs1, offset=0):
    f3 = ("SB", "SH", "SW", "SD").index(name)
    return ((offset & 4095) >> 5) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | (offset & 31) << 7 | 0x23


def branch(name, rs1, rs2, offset):
    f3 = {"BEQ": 0, "BNE": 1, "BLT": 4, "BGE": 5, "BLTU": 6, "BGEU": 7}[name]
    value = offset & 8191
    return ((value >> 12) & 1) << 31 | ((value >> 5) & 63) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | ((value >> 1) & 15) << 8 | ((value >> 11) & 1) << 7 | 0x63


def lui(rd, upper):
    return (upper & 0xfffff) << 12 | rd << 7 | 0x37


def auipc(rd, upper=0):
    return (upper & 0xfffff) << 12 | rd << 7 | 0x17


def jal(rd, offset):
    value = offset & ((1 << 21) - 1)
    return ((value >> 20) & 1) << 31 | ((value >> 1) & 1023) << 21 | ((value >> 11) & 1) << 20 | ((value >> 12) & 255) << 12 | rd << 7 | 0x6f


def jalr(rd, rs1, offset=0):
    return (offset & 4095) << 20 | rs1 << 15 | rd << 7 | 0x67


ECALL = 0x73
EBREAK = 0x100073
NOP = i("ADDI", 0, 0, 0)
