"""Directed and seeded workloads derived from the frozen ISA and edge contract."""

import random

from encoding import ECALL, EBREAK, NOP, auipc, branch, i, jal, jalr, load, lui, r, store
from iss import BRANCH_NAMES, DATA, MASK, M_NAMES

PATTERNS = (0, 1, 2, MASK, 1 << 63, (1 << 63) - 1, 0x80000000, 0xffffffff)
REGISTER_OPS = ("ADD", "SUB", "SLL", "SLT", "SLTU", "XOR", "SRL", "SRA", "OR", "AND",
                "ADDW", "SUBW", "SLLW", "SRLW", "SRAW")
IMMEDIATE_OPS = ("ADDI", "SLTI", "SLTIU", "XORI", "ORI", "ANDI", "SLLI", "SRLI", "SRAI",
                 "ADDIW", "SLLIW", "SRLIW", "SRAIW")


def functional_program():
    code = [lui(20, DATA >> 12), i("ADDI", 10, 0, 1), i("ADDI", 11, 0, 2),
            i("ADDI", 1, 0, -1), i("ADDI", 2, 0, 31)]
    for iteration in range(4):
        code += [lui(3, (0, 0x7ffff, 0x80000, 0xfffff)[iteration]), auipc(4)]
        for name in REGISTER_OPS:
            code += [r(name, 3, 1, 2)]
        for name in IMMEDIATE_OPS:
            if name.startswith(("SLL", "SRL", "SRA")):
                bits = 5 if name.endswith("W") else 6
                immediate = (0, 1, bits - 1, (1 << bits) - 1)[iteration]
            else:
                immediate = (-2048, -1, 0, 2047)[iteration]
            code += [i(name, 3, 1, immediate)]
        for name in M_NAMES:
            code += [r(name, 3, 1, 2)]
        for name in ("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU"):
            width = {"LB": 1, "LH": 2, "LW": 4, "LD": 8, "LBU": 1, "LHU": 2, "LWU": 4}[name]
            code += [load(name, 3, 20, lane) for lane in range(0, 8, width)]
        for name, width in (("SB", 1), ("SH", 2), ("SW", 4), ("SD", 8)):
            code += [store(name, 1, 20, 8 + lane) for lane in range(0, 8, width)]
        for name in BRANCH_NAMES:
            true_pair = (10, 10) if name in ("BEQ", "BGE", "BGEU") else (10, 11)
            false_pair = (10, 11) if name == "BEQ" else (10, 10) if name in ("BNE", "BLT", "BLTU") else (10, 11)
            code += [branch(name, *true_pair, 8), i("ADDI", 3, 0, 77),
                     branch(name, *false_pair, 8), NOP]
        code += [jal(5, 8), i("ADDI", 3, 0, 77), auipc(9),
                 i("ADDI", 9, 9, 16), jalr(5, 9), store("SD", 1, 20, 24),
                 0x0ff0000f, i("ADDI", 0, 0, -1)]
    # Independent youngest-older producer, rs1/rs2, store and WB-to-ID cases.
    code += [i("ADDI", 6, 0, 3), i("ADDI", 6, 0, 5), r("ADD", 7, 6, 6),
             store("SD", 7, 20, 32), load("LD", 8, 20, 32), r("ADD", 9, 8, 8),
             i("ADDI", 6, 0, 13), NOP, r("ADD", 7, 6, 6),
             i("ADDI", 6, 0, 7), NOP, store("SD", 6, 20, 40),
             i("ADDI", 6, 0, 3), NOP, NOP, r("ADD", 7, 6, 6),
             i("ADDI", 13, 0, 9), branch("BEQ", 13, 13, 8), i("ADDI", 14, 0, 101),
             load("LD", 0, 20), i("ADDI", 3, 0, 0),
             load("LD", 3, 20), i("ADDI", 4, 0, 3),
             load("LD", 3, 20), load("LD", 4, 20, 8),
             r("MUL", 5, 3, 4), r("DIVU", 6, 5, 4)]
    # Backward branch: explicitly includes both outcomes and a trained BTB hit.
    code += [i("ADDI", 12, 0, 4), i("ADDI", 12, 12, -1),
             branch("BNE", 12, 0, -4), EBREAK]
    return code


def m_cartesian():
    code = [lui(20, DATA >> 12)]
    for name in M_NAMES:
        for left in range(len(PATTERNS)):
            for right in range(len(PATTERNS)):
                code += [load("LD", 1, 20, left * 8), load("LD", 2, 20, right * 8),
                         r(name, 3, 1, 2)]
        rng = random.Random(1700 + M_NAMES.index(name))
        for _ in range(16):
            # Seeded words are held in a separately initialized operand table.
            left, right = rng.randrange(8, 40), rng.randrange(8, 40)
            code += [load("LD", 1, 20, left * 8), load("LD", 2, 20, right * 8), r(name, 3, 1, 2)]
    code += [ECALL]
    rng = random.Random(2027)
    return code, list(PATTERNS) + [rng.getrandbits(64) for _ in range(32)]


def random_program(seed, count):
    rng = seed if isinstance(seed, random.Random) else random.Random(seed)
    # A finite straight-line backbone with randomly selected branch diamonds and
    # JAL/JALR skips gives bounded valid control flow without removing instructions.
    code = [lui(20, DATA >> 12)]
    for reg in range(1, 20):
        code += [load("LD", reg, 20, (reg - 1) * 8)]
    for _ in range(count):
        rd, a, b = rng.randrange(20), rng.randrange(20), rng.randrange(20)
        choice = rng.randrange(10)
        if choice < 3:
            code.append(r(rng.choice(REGISTER_OPS), rd, a, b))
        elif choice < 5:
            name = rng.choice(IMMEDIATE_OPS)
            immediate = rng.randrange(32 if name.endswith("W") else 64) if name.startswith(("SLL", "SRL", "SRA")) else rng.randrange(-2048, 2048)
            code.append(i(name, rd, a, immediate))
        elif choice == 5:
            code.append(r(rng.choice(M_NAMES), rd, a, b))
        elif choice == 6:
            name = rng.choice(("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU"))
            width = 1 << (("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU").index(name) & 3)
            code.append(load(name, rd, 20, rng.randrange(128 // width) * width))
        elif choice == 7:
            index = rng.randrange(4)
            width = 1 << index
            code.append(store(("SB", "SH", "SW", "SD")[index], b, 20, rng.randrange(128 // width) * width))
        elif choice == 8:
            code += [branch(rng.choice(BRANCH_NAMES), a, b, 8), i("ADDI", rd, a, rng.randrange(-2048, 2048))]
        else:
            if rng.randrange(2):
                code += [jal(rd, 8), store("SD", b, 20, 256)]
            else:
                code += [auipc(21), i("ADDI", 21, 21, 16), jalr(rd, 21), store("SD", b, 20, 256)]
    code += [ECALL]
    return code, [rng.getrandbits(64) for _ in range(64)]


def precision_program(terminal):
    # Older register and memory changes must complete; all younger effects must die.
    return [lui(20, DATA >> 12), lui(21, 0x40000), i("ADDI", 1, 0, 91),
            store("SD", 1, 20, 8), i("ADDI", 2, 1, 17), terminal,
            i("ADDI", 3, 0, 99), store("SD", 3, 20, 16), store("SD", 3, 21), 0]


def trap_cases():
    yield "illegal", [NOP, 0, i("ADDI", 1, 0, 9)], (4, 2)
    for word in (0x0000100f, 0x00001073, 0x04001013, 0x0400101b,
                 0x0200003b | (1 << 12), 0x00007003, 0x00004023):
        yield "reserved-encoding", [NOP, word, store("SD", 0, 0)], (4, 2)
    for name, cause in (("LD", 4), ("SD", 6)):
        access = load(name, 2, 1, 1) if name == "LD" else store(name, 2, 1, 1)
        yield "data-alignment", [lui(1, DATA >> 12), access, ECALL], (4, cause)
    for base in (0, DATA + 257 * 8, 0x100000000 + DATA):
        # Build upper bits without relying on an assembler/compiler pseudo-op.
        prefix = [lui(1, DATA >> 12)] if base else [i("ADDI", 1, 0, 0)]
        if base == DATA + 257 * 8:
            prefix += [i("ADDI", 1, 1, 1024), i("ADDI", 1, 1, 1032)]
        elif base >> 32:
            prefix += [i("ADDI", 2, 0, 1), i("SLLI", 2, 2, 32), r("ADD", 1, 1, 2)]
        for store_access in (False, True):
            access = store("SD", 0, 1) if store_access else load("LD", 3, 1)
            yield "access-range", prefix + [access, ECALL], (len(prefix) * 4, 7 if store_access else 5)
    yield "jal-misalignment", [i("ADDI", 1, 0, 7), jal(2, 2), ECALL], (4, 0)
    yield "jalr-misalignment", [i("ADDI", 1, 0, 3), jalr(2, 1), ECALL], (4, 0)
    yield "branch-misalignment", [branch("BEQ", 0, 0, 2), ECALL], (0, 0)
    yield "unused-misalignment", [i("ADDI", 1, 0, 1), branch("BEQ", 0, 1, 2), ECALL], (8, 11)
    yield "fetch-range", [jal(0, 769 * 4), ECALL], (769 * 4, 1)
    yield "fetch-high-alias", [i("ADDI", 1, 0, 1), i("SLLI", 1, 1, 32), jalr(0, 1), ECALL], (1 << 32, 1)


def axi_program():
    code = [lui(20, 0x40000), i("ADDI", 1, 0, -1)]
    for name, width in (("SB", 1), ("SH", 2), ("SW", 4), ("SD", 8)):
        for lane in range(0, 8, width):
            code += [store(name, 1, 20, lane)]
    for name in ("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU"):
        width = 1 << (("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU").index(name) & 3)
        code += [load(name, 3, 20, lane) for lane in range(0, 8, width)]
    return code + [EBREAK]


def flush_program():
    code = [lui(20, DATA >> 12), lui(21, 0x40000), i("ADDI", 1, 0, 123)]
    for killed in (i("ADDI", 2, 0, 99), store("SD", 1, 20), store("SD", 1, 21), 0):
        code += [branch("BEQ", 0, 0, 8), killed]
    return code + [EBREAK]


def target_correction():
    # Revisit one JALR without another intervening control transfer, even at BTB=1.
    return [i("ADDI", 9, 0, -4), i("ADDI", 9, 9, 8), jalr(5, 9), ECALL]
