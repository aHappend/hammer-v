"""Architectural reference rules, independent of the DUT microarchitecture."""

from dataclasses import dataclass


MASK64 = (1 << 64) - 1


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


@dataclass(frozen=True)
class Translation:
    pa: int = 0
    fault: str = ""
    level: int = -1
    global_mapping: bool = False


def sv39(va, access, priv, satp, mstatus, read_pte):
    """Translate using a physical-memory callback; OSError denotes a bus fault.

    access is fetch/load/store/amo, encoded 0/1/2/3. No TLB is modeled:
    callers explicitly maintain architectural mappings across fence tests.
    """
    va &= MASK64
    if access != 0 and priv == 3 and mstatus & (1 << 17):
        priv = (mstatus >> 11) & 3
    if priv == 3 or satp >> 60 == 0:
        return Translation(va) if va < 1 << 56 else Translation(fault="access")
    if satp >> 60 != 8:
        raise ValueError("unsupported satp MODE is not a legal architectural state")
    if signed(va, 64) != signed(va, 39):
        return Translation(fault="page")
    table = (satp & ((1 << 44) - 1)) << 12
    inherited_global = False
    for level in (2, 1, 0):
        index = (va >> (12 + 9 * level)) & 511
        try:
            pte = read_pte(table + 8 * index)
        except OSError:
            return Translation(fault="access")
        flags = {letter: bool(pte & (1 << bit))
                 for bit, letter in enumerate("VRWXUGAD")}
        if pte >> 54 or not flags["V"] or (flags["W"] and not flags["R"]):
            return Translation(fault="page")
        inherited_global |= flags["G"]
        ppn = (pte >> 10) & ((1 << 44) - 1)
        if not (flags["R"] or flags["X"]):
            if level == 0 or flags["U"] or flags["A"] or flags["D"]:
                return Translation(fault="page")
            table = ppn << 12
            continue
        if ppn & ((1 << (9 * level)) - 1):
            return Translation(fault="page")
        if priv == 0 and not flags["U"]:
            return Translation(fault="page")
        if priv == 1 and flags["U"] and (
                access == 0 or not (mstatus & (1 << 18))):
            return Translation(fault="page")
        permitted = (
            flags["X"] if access == 0 else
            flags["R"] or (flags["X"] and bool(mstatus & (1 << 19))) if access == 1 else
            flags["W"] if access == 2 else flags["R"] and flags["W"]
        )
        if not permitted or not flags["A"] or (access in (2, 3) and not flags["D"]):
            return Translation(fault="page")
        span = 1 << (12 + 9 * level)
        return Translation((ppn << 12) | (va & (span - 1)),
                           level=level, global_mapping=inherited_global)
    raise AssertionError("all page-table levels must terminate")


class BareMachine:
    """Small instruction-level oracle for the initial Bare integration probe.

    Unsupported instructions raise, rather than producing a success-shaped
    default. This probe is not the complete admitted RV64IMA regression.
    """

    def __init__(self, words):
        self.words = words
        self.regs = [0] * 32
        self.memory = {}
        self.pc = 0
        self.priv = 3

    def fetch(self):
        return self.words[self.pc // 4]

    def physical(self, address, access):
        return address

    def step(self):
        pc = self.pc
        instruction = self.fetch()
        opcode = instruction & 127
        rd = (instruction >> 7) & 31
        funct3 = (instruction >> 12) & 7
        rs1 = (instruction >> 15) & 31
        rs2 = (instruction >> 20) & 31
        a, b = self.regs[rs1], self.regs[rs2]
        value = None
        memory = None
        next_pc = (pc + 4) & MASK64
        if opcode == 0x37:
            value = signed(instruction & 0xFFFFF000, 32)
        elif opcode == 0x17:
            value = pc + signed(instruction & 0xFFFFF000, 32)
        elif opcode in (0x13, 0x1B):
            imm = signed(instruction >> 20, 12)
            shamt = (instruction >> 20) & (31 if opcode == 0x1B else 63)
            if funct3 == 0:
                value = a + imm
            elif funct3 == 2:
                value = int(signed(a, 64) < imm)
            elif funct3 == 3:
                value = int(a < (imm & MASK64))
            elif funct3 == 4:
                value = a ^ (imm & MASK64)
            elif funct3 == 6:
                value = a | (imm & MASK64)
            elif funct3 == 7:
                value = a & (imm & MASK64)
            elif funct3 == 1:
                value = a << shamt
            elif funct3 == 5:
                width = 32 if opcode == 0x1B else 64
                value = (signed(a, width) if instruction & (1 << 30)
                         else a & ((1 << width) - 1)) >> shamt
            else:
                raise NotImplementedError(hex(instruction))
            if opcode == 0x1B:
                value = signed(value, 32)
        elif opcode in (0x33, 0x3B):
            funct7 = instruction >> 25
            width = 32 if opcode == 0x3B else 64
            shift = b & (width - 1)
            if funct7 == 1:
                aa, bb = signed(a, width), signed(b, width)
                ua, ub = a & ((1 << width) - 1), b & ((1 << width) - 1)
                if funct3 == 0:
                    value = ua * ub
                elif funct3 in (1, 2, 3) and width == 64:
                    lhs = aa if funct3 in (1, 2) else ua
                    rhs = bb if funct3 == 1 else ub
                    value = (lhs * rhs) >> 64
                elif funct3 in (4, 6):
                    quotient = (-1 if bb == 0 else
                                (abs(aa) // abs(bb)) * (-1 if (aa < 0) != (bb < 0) else 1))
                    value = quotient if funct3 == 4 else aa if bb == 0 else aa - quotient * bb
                elif funct3 in (5, 7):
                    value = ((1 << width) - 1 if ub == 0 else ua // ub) if funct3 == 5 else (
                        ua if ub == 0 else ua % ub)
                else:
                    raise NotImplementedError(hex(instruction))
            elif funct3 == 0 and funct7 in (0, 0x20):
                value = a - b if funct7 else a + b
            elif funct3 == 1 and funct7 == 0:
                value = a << shift
            elif funct3 == 2 and funct7 == 0:
                value = int(signed(a, 64) < signed(b, 64))
            elif funct3 == 3 and funct7 == 0:
                value = int(a < b)
            elif funct3 == 4 and funct7 == 0:
                value = a ^ b
            elif funct3 == 5 and funct7 in (0, 0x20):
                value = (signed(a, width) if funct7 else a & ((1 << width) - 1)) >> shift
            elif funct3 == 6 and funct7 == 0:
                value = a | b
            elif funct3 == 7 and funct7 == 0:
                value = a & b
            else:
                raise NotImplementedError(hex(instruction))
            if opcode == 0x3B:
                value = signed(value, 32)
        elif opcode == 0x23:
            imm = signed(((instruction >> 25) << 5) | ((instruction >> 7) & 31), 12)
            addr = (a + imm) & MASK64
            size = 1 << funct3
            assert funct3 <= 3 and addr % size == 0
            physical = self.physical(addr, 2)
            for byte in range(size):
                self.memory[physical + byte] = (b >> (8 * byte)) & 255
            memory = (1, addr, ((1 << size) - 1) << (addr & 7),
                      (b << (8 * (addr & 7))) & MASK64, 0)
        elif opcode == 0x03:
            addr = (a + signed(instruction >> 20, 12)) & MASK64
            size = 1 << (funct3 & 3)
            assert funct3 != 7 and addr % size == 0
            physical = self.physical(addr, 1)
            raw = sum(self.memory[physical + byte] << (8 * byte) for byte in range(size))
            value = raw if funct3 >= 4 else signed(raw, 8 * size)
            memory = (0, addr, 0, 0, value & MASK64)
        elif opcode == 0x63:
            imm = signed(((instruction >> 31) << 12) |
                         (((instruction >> 7) & 1) << 11) |
                         (((instruction >> 25) & 63) << 5) |
                         (((instruction >> 8) & 15) << 1), 13)
            condition = {0: a == b, 1: a != b,
                         4: signed(a, 64) < signed(b, 64),
                         5: signed(a, 64) >= signed(b, 64),
                         6: a < b, 7: a >= b}[funct3]
            if condition:
                next_pc = (pc + imm) & MASK64
        elif opcode == 0x6F:
            imm = signed(((instruction >> 31) << 20) |
                         (((instruction >> 12) & 255) << 12) |
                         (((instruction >> 20) & 1) << 11) |
                         (((instruction >> 21) & 1023) << 1), 21)
            value, next_pc = pc + 4, (pc + imm) & MASK64
        elif opcode == 0x0F:
            pass
        elif instruction == 0x00000073:
            return ("T", pc, {0: 8, 1: 9, 3: 11}[self.priv], 0, 3, 0)
        else:
            raise NotImplementedError(f"instruction {instruction:08x} at {pc:x}")
        write = value is not None and rd != 0
        if write:
            self.regs[rd] = value & MASK64
        self.regs[0] = 0
        self.pc = next_pc
        return ("R", pc, instruction, next_pc, int(write),
                rd if write else 0, self.regs[rd] if write else 0, memory, self.priv)


class StartupMachine(BareMachine):
    """Sv39 startup/CSR reference; deliberately bounded, not full ISA coverage."""

    def __init__(self, words, initial_data):
        super().__init__(words)
        self.csrs = {0x180: 0, 0x300: 0, 0x341: 0}
        for offset, word in initial_data.items():
            for byte in range(8):
                self.memory[0x10000000 + offset + byte] = (word >> (8 * byte)) & 255

    def read_pte(self, address):
        try:
            return sum(self.memory[address + b] << (8 * b) for b in range(8))
        except KeyError as error:
            raise OSError("uninitialized page-table memory") from error

    def physical(self, address, access):
        result = sv39(address, access, self.priv, self.csrs[0x180],
                      self.csrs[0x300], self.read_pte)
        if result.fault:
            raise AssertionError(f"unexpected startup {result.fault} fault: {address:x}")
        return result.pa

    def fetch(self):
        address = self.physical(self.pc, 0)
        if address % 4 or address >= len(self.words) * 4:
            raise AssertionError(f"unexpected startup fetch physical address: {address:x}")
        return self.words[address // 4]

    def step(self):
        instruction = self.fetch()
        if instruction & 127 != 0x73 or instruction == 0x73:
            return super().step()
        pc, privilege = self.pc, self.priv
        rd = (instruction >> 7) & 31
        rs1 = (instruction >> 15) & 31
        funct3 = (instruction >> 12) & 7
        write = False
        value = 0
        next_pc = pc + 4
        if instruction == 0x30200073:
            assert self.priv == 3
            status = self.csrs[0x300]
            self.priv = (status >> 11) & 3
            self.csrs[0x300] = (status & ~((3 << 11) | (1 << 3))) | (
                ((status >> 7) & 1) << 3) | (1 << 7)
            if self.priv != 3:
                self.csrs[0x300] &= ~(1 << 17)
            next_pc = self.csrs[0x341]
        elif instruction & 0xFE007FFF == 0x12000073:
            assert self.priv in (1, 3)
        elif funct3 in (1, 2, 3, 5, 6, 7):
            number = instruction >> 20
            assert self.priv >= ((number >> 8) & 3)
            old = self.csrs[number]
            source = rs1 if funct3 & 4 else self.regs[rs1]
            updated = source if funct3 & 3 == 1 else (
                old | source if funct3 & 3 == 2 else old & ~source)
            if funct3 & 3 == 1 or rs1 != 0:
                if number != 0x180 or updated >> 60 in (0, 8):
                    self.csrs[number] = updated & MASK64
            value = old
            if number == 0x300:
                value |= (2 << 32) | (2 << 34)
            write = rd != 0
            if write:
                self.regs[rd] = value
        else:
            raise NotImplementedError(hex(instruction))
        self.pc = next_pc
        return ("R", pc, instruction, next_pc, int(write),
                rd if write else 0, value if write else 0, None, privilege)


def i_type(opcode, rd, funct3, rs1, immediate):
    return ((immediate & 4095) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def r_type(opcode, rd, funct3, rs1, rs2, funct7=0):
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def s_type(funct3, rs1, rs2, immediate):
    return (((immediate & 4095) >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (
        funct3 << 12) | ((immediate & 31) << 7) | 0x23


def bare_program():
    words = [0x100000B7, i_type(0x13, 2, 0, 0, -37),
             i_type(0x13, 3, 0, 0, 7)]
    for funct3 in range(8):
        words.append(r_type(0x33, 4 + funct3, funct3, 2, 3))
    for funct3 in range(8):
        words.append(r_type(0x33, 12 + funct3, funct3, 2, 3, 1))
    words += [s_type(3, 1, 2, 0), i_type(0x03, 20, 3, 1, 0),
              i_type(0x13, 21, 0, 20, 11), s_type(0, 1, 3, 3),
              i_type(0x03, 22, 4, 1, 3), i_type(0x03, 23, 0, 1, 7),
              i_type(0x1B, 24, 0, 2, -1), 0x0000000F, 0x00000073]
    return words


def startup_program():
    words = [
        0x100000B7, i_type(0x13, 1, 5, 1, 12),
        i_type(0x13, 2, 0, 0, 8), i_type(0x13, 2, 1, 2, 60),
        r_type(0x33, 1, 6, 1, 2),
        (0x180 << 20) | (1 << 15) | (1 << 12) | 0x73,
        i_type(0x13, 3, 0, 0, 1), i_type(0x13, 3, 1, 3, 11),
        (0x300 << 20) | (3 << 15) | (1 << 12) | 0x73,
        i_type(0x13, 4, 0, 0, 0x100),
        (0x341 << 20) | (4 << 15) | (1 << 12) | 0x73,
        0x30200073,
    ]
    words += [0x13] * (64 - len(words))
    words += [0x400032B7, i_type(0x03, 6, 3, 5, 0),
              i_type(0x13, 6, 0, 6, 1), s_type(3, 5, 6, 0),
              0x12000073, i_type(0x03, 7, 3, 5, 0), 0x73]
    data = {}

    def pte(address, target, flags):
        line = address & ~31
        for offset in range(0, 32, 8):
            data.setdefault(line - 0x10000000 + offset, 0)
        data[address - 0x10000000] = ((target >> 12) << 10) | flags

    pte(0x10000000, 0x10001000, 1)
    pte(0x10000008, 0x10004000, 1)
    pte(0x10001000, 0x10002000, 1)
    pte(0x10002000, 0, 0x4B)
    pte(0x10004000, 0x10000000, 0xC7)
    for offset in range(0, 32, 8):
        data[0x3000 + offset] = 0
    data[0x3000] = 0x1234567887654321
    return words, data
