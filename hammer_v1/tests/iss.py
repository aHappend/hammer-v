"""Independent, integer-only RV64IM architectural oracle."""

from dataclasses import dataclass, field

MASK = (1 << 64) - 1
DATA = 0x10000000
MMIO = 0x40000000


def signed(value, bits=64):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def sext(value, bits):
    return signed(value, bits) & MASK


class Fault(Exception):
    def __init__(self, cause, pc):
        self.cause, self.pc = cause, pc
        super().__init__(f"trap cause={cause} pc={pc:#x}")


@dataclass(frozen=True)
class Instruction:
    word: int
    name: str
    rd: int = 0
    rs1: int = 0
    rs2: int = 0
    imm: int = 0
    uses: tuple = ()
    writes: bool = False
    width: int = 0
    unsigned: bool = False

    @property
    def load(self):
        return self.name in ("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU")

    @property
    def store(self):
        return self.name in ("SB", "SH", "SW", "SD")

    @property
    def branch(self):
        return self.name in ("BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU")

    @property
    def muldiv(self):
        return self.name in M_NAMES

    @property
    def control(self):
        return self.branch or self.name in ("JAL", "JALR")


M_NAMES = ("MUL", "MULH", "MULHSU", "MULHU", "DIV", "DIVU", "REM",
           "REMU", "MULW", "DIVW", "DIVUW", "REMW", "REMUW")
BRANCH_NAMES = ("BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU")
NORMAL_NAMES = (
    "LUI AUIPC JAL JALR BEQ BNE BLT BGE BLTU BGEU "
    "LB LH LW LD LBU LHU LWU SB SH SW SD "
    "ADDI SLTI SLTIU XORI ORI ANDI SLLI SRLI SRAI "
    "ADD SUB SLL SLT SLTU XOR SRL SRA OR AND "
    "ADDIW SLLIW SRLIW SRAIW ADDW SUBW SLLW SRLW SRAW FENCE"
).split() + list(M_NAMES)


def decode(word):
    op, f3, f7 = word & 127, (word >> 12) & 7, word >> 25
    rd, r1, r2 = (word >> 7) & 31, (word >> 15) & 31, (word >> 20) & 31
    name, imm, uses, writes, width, unsigned = "ILLEGAL", 0, (), False, 0, False
    if op in (0x37, 0x17):
        name, imm, writes = ("LUI" if op == 0x37 else "AUIPC"), signed(word & 0xfffff000, 32), True
    elif op == 0x6f:
        j = ((word >> 31) << 20 | ((word >> 12) & 255) << 12 |
             ((word >> 20) & 1) << 11 | ((word >> 21) & 1023) << 1)
        name, imm, writes = "JAL", signed(j, 21), True
    elif op == 0x67 and f3 == 0:
        name, imm, uses, writes = "JALR", signed(word >> 20, 12), (r1,), True
    elif op == 0x63 and f3 in (0, 1, 4, 5, 6, 7):
        b = ((word >> 31) << 12 | ((word >> 7) & 1) << 11 |
             ((word >> 25) & 63) << 5 | ((word >> 8) & 15) << 1)
        name = {0: "BEQ", 1: "BNE", 4: "BLT", 5: "BGE", 6: "BLTU", 7: "BGEU"}[f3]
        imm, uses = signed(b, 13), (r1, r2)
    elif op == 3 and f3 < 7:
        name = ("LB", "LH", "LW", "LD", "LBU", "LHU", "LWU")[f3]
        imm, uses, writes = signed(word >> 20, 12), (r1,), True
        width, unsigned = 1 << (f3 & 3), f3 >= 4
    elif op == 0x23 and f3 < 4:
        name, width = ("SB", "SH", "SW", "SD")[f3], 1 << f3
        imm, uses = signed(((word >> 25) << 5) | rd, 12), (r1, r2)
    elif op in (0x13, 0x1b):
        imm, uses, writes = signed(word >> 20, 12), (r1,), True
        if f3 == 0:
            name = "ADDIW" if op == 0x1b else "ADDI"
        elif op == 0x13 and f3 in (2, 3, 4, 6, 7):
            name = {2: "SLTI", 3: "SLTIU", 4: "XORI", 6: "ORI", 7: "ANDI"}[f3]
        elif f3 in (1, 5):
            shift_bits = 5 if op == 0x1b else 6
            upper = word >> (20 + shift_bits)
            if (f3 == 1 and upper == 0) or (f3 == 5 and upper in (0, 1 << (10 - shift_bits))):
                name = ("SLLI" if f3 == 1 else "SRAI" if upper else "SRLI")
                if op == 0x1b:
                    name += "W"
                imm = (word >> 20) & ((1 << shift_bits) - 1)
    elif op in (0x33, 0x3b):
        uses, writes = (r1, r2), True
        if f7 == 1 and (op == 0x33 or f3 in (0, 4, 5, 6, 7)):
            name = ("MUL", "MULH", "MULHSU", "MULHU", "DIV", "DIVU", "REM", "REMU")[f3]
            if op == 0x3b:
                name += "W"
        elif f7 == 0 and (op == 0x33 or f3 in (0, 1, 5)):
            name = ("ADD", "SLL", "SLT", "SLTU", "XOR", "SRL", "OR", "AND")[f3]
            if op == 0x3b:
                name += "W"
        elif f7 == 32 and f3 in (0, 5):
            name = ("SUB" if f3 == 0 else "SRA") + ("W" if op == 0x3b else "")
    elif op == 0x0f and f3 == 0 and rd == 0 and r1 == 0 and word >> 28 == 0:
        name = "FENCE"
    elif word in (0x73, 0x100073):
        name = "ECALL" if word == 0x73 else "EBREAK"
    if name == "ILLEGAL":
        uses, writes = (), False
    return Instruction(word, name, rd, r1, r2, imm, uses, writes, width, unsigned)


def arithmetic(name, a, b, pc, imm):
    """Unbounded Python products and integer quotient/remainder, not RTL iterations."""
    word = name.endswith("W")
    root = name[:-1] if word else name
    bits = 32 if word else 64
    mask = (1 << bits) - 1
    av, bv = a & mask, b & mask
    sa, sb = signed(a, bits), signed(b, bits)
    shift = (imm if root.endswith("I") else b) & (bits - 1)
    if root in ("ADD", "ADDI"):
        value = a + (imm if root == "ADDI" else b)
    elif root == "SUB":
        value = a - b
    elif root in ("SLL", "SLLI"):
        value = av << shift
    elif root in ("SRL", "SRLI"):
        value = av >> shift
    elif root in ("SRA", "SRAI"):
        value = sa >> shift
    elif root in ("SLT", "SLTI"):
        value = int(signed(a) < (imm if root == "SLTI" else signed(b)))
    elif root in ("SLTU", "SLTIU"):
        value = int(a < ((imm & MASK) if root == "SLTIU" else b))
    elif root in ("XOR", "XORI"):
        value = a ^ ((imm & MASK) if root == "XORI" else b)
    elif root in ("OR", "ORI"):
        value = a | ((imm & MASK) if root == "ORI" else b)
    elif root in ("AND", "ANDI"):
        value = a & ((imm & MASK) if root == "ANDI" else b)
    elif root == "LUI":
        value = imm
    elif root == "AUIPC":
        value = pc + imm
    elif root == "MUL":
        value = av * bv
    elif root in ("MULH", "MULHSU", "MULHU"):
        value = ((signed(a) if root != "MULHU" else a) *
                 (signed(b) if root == "MULH" else b)) >> 64
    elif root in ("DIV", "DIVU", "REM", "REMU"):
        dividend, divisor = (av, bv) if root.endswith("U") else (sa, sb)
        if divisor == 0:
            value = dividend if root.startswith("REM") else mask
        else:
            q = abs(dividend) // abs(divisor)
            if (dividend < 0) != (divisor < 0):
                q = -q
            value = dividend - q * divisor if root.startswith("REM") else q
    else:
        raise ValueError(f"not an arithmetic instruction: {name}")
    return sext(value, 32) if word else value & MASK


@dataclass
class Effect:
    pc: int
    insn: Instruction
    next_pc: int
    rd: int = 0
    value: int = 0
    address: int = 0
    mask: int = 0
    data: int = 0
    load_value: int = 0
    taken: bool = False
    cause: int | None = None

    def trace(self):
        mem = self.insn.load or self.insn.store
        return (self.pc, self.next_pc, self.insn.word, int(self.rd != 0),
                self.rd, self.value if self.rd else 0, int(mem),
                int(self.insn.store), self.address if mem else 0,
                self.mask if self.insn.store else 0,
                self.data if self.insn.store else 0,
                self.load_value if self.insn.load else 0)


def evaluate(insn, pc, registers, read, imem_words, dmem_words, response=0):
    e = Effect(pc, insn, (pc + 4) & MASK)
    a, b = registers[insn.rs1], registers[insn.rs2]
    if pc & 3:
        e.cause = 0
    elif pc >= imem_words * 4:
        e.cause = 1
    elif insn.name in ("ILLEGAL", "ECALL", "EBREAK"):
        e.cause = {"ILLEGAL": 2, "ECALL": 11, "EBREAK": 3}[insn.name]
    elif insn.branch or insn.name in ("JAL", "JALR"):
        condition = {
            "BEQ": a == b, "BNE": a != b,
            "BLT": signed(a) < signed(b), "BGE": signed(a) >= signed(b),
            "BLTU": a < b, "BGEU": a >= b,
        }
        e.taken = condition[insn.name] if insn.branch else True
        target = ((a + insn.imm) & ~1 if insn.name == "JALR" else pc + insn.imm) & MASK
        if e.taken:
            e.next_pc = target
            if target & 3:
                e.cause = 0
        if not insn.branch:
            e.value = (pc + 4) & MASK
    elif insn.load or insn.store:
        e.address = (a + insn.imm) & MASK
        if e.address % insn.width:
            e.cause = 6 if insn.store else 4
        elif not (DATA <= e.address < DATA + 8 * dmem_words or MMIO <= e.address < MMIO + 65536):
            e.cause = 7 if insn.store else 5
        elif MMIO <= e.address < MMIO + 65536 and response != 0:
            e.cause = 7 if insn.store else 5
        elif insn.load:
            raw = read(e.address, insn.width)
            e.value = raw if insn.unsigned else sext(raw, insn.width * 8)
            e.load_value = e.value
        else:
            lane = e.address & 7
            e.mask = ((1 << insn.width) - 1) << lane
            e.data = (b << (8 * lane)) & MASK
    elif insn.name != "FENCE":
        e.value = arithmetic(insn.name, a, b, pc, insn.imm)
    if insn.writes and insn.rd and e.cause is None:
        e.rd = insn.rd
    return e


@dataclass
class ISS:
    program: list
    memory: bytearray
    imem_words: int
    dmem_words: int
    response: int = 0
    pc: int = 0
    registers: list = field(default_factory=lambda: [0] * 32)
    mmio: bytearray = field(default_factory=lambda: bytearray(65536))
    history: list = field(default_factory=list)

    def read(self, address, width):
        base, data = (DATA, self.memory) if address < MMIO else (MMIO, self.mmio)
        offset = address - base
        if offset < 0 or offset + width > len(data):
            raise AssertionError(f"uninitialized oracle memory {address:#x}+{width}")
        return int.from_bytes(data[offset:offset + width], "little")

    def effect(self):
        word = self.program[self.pc // 4] if self.pc < len(self.program) * 4 and not self.pc & 3 else 0
        return evaluate(decode(word), self.pc, self.registers, self.read,
                        self.imem_words, self.dmem_words, self.response)

    def step(self):
        e = self.effect()
        if e.cause is not None:
            raise Fault(e.cause, e.pc)
        if e.rd:
            self.registers[e.rd] = e.value
        if e.insn.store:
            base, data = (DATA, self.memory) if e.address < MMIO else (MMIO, self.mmio)
            offset = e.address - base
            raw = self.registers[e.insn.rs2]
            data[offset:offset + e.insn.width] = (raw & ((1 << (8 * e.insn.width)) - 1)).to_bytes(e.insn.width, "little")
        self.pc = e.next_pc
        self.history.append(e)
        return e
