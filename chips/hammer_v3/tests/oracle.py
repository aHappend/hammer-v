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
        self.reservation = None

    def fetch(self):
        return self.words[self.pc // 4]

    def physical(self, address, access):
        return address

    def read_memory(self, address, size):
        return sum(self.memory[address + byte] << (8 * byte) for byte in range(size))

    def write_memory(self, address, size, value):
        for byte in range(size):
            self.memory[address + byte] = (value >> (8 * byte)) & 255

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
            self.write_memory(physical, size, b)
            memory = (1, addr, ((1 << size) - 1) << (addr & 7),
                      (b << (8 * (addr & 7))) & MASK64, 0)
            self.reservation = None
        elif opcode == 0x03:
            addr = (a + signed(instruction >> 20, 12)) & MASK64
            size = 1 << (funct3 & 3)
            assert funct3 != 7 and addr % size == 0
            physical = self.physical(addr, 1)
            raw = self.read_memory(physical, size)
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
        elif opcode == 0x67 and funct3 == 0:
            value, next_pc = pc + 4, ((a + signed(instruction >> 20, 12)) & MASK64) & ~1
        elif opcode == 0x2F:
            size = {2: 4, 3: 8}[funct3]
            operation = instruction >> 27
            physical = self.physical(a, 1 if operation == 2 else 2 if operation == 3 else 3)
            if a % size:
                raise ArchitecturalTrap(4 if operation == 2 else 6, a)
            width_mask = (1 << (size * 8)) - 1
            if operation == 3:
                success = self.reservation == (physical, size)
                self.reservation = None
                value = int(not success)
                updated, old = b & width_mask, 0
                writing = success
            else:
                old_raw = sum(self.memory[physical + byte] << (8 * byte) for byte in range(size))
                old = signed(old_raw, size * 8) & MASK64
                value, writing = old, operation != 2
                operand = b & width_mask
                if operation == 2:
                    self.reservation = (physical, size)
                    updated = 0
                elif operation == 1:
                    updated = operand
                elif operation == 0:
                    updated = old_raw + operand
                elif operation == 4:
                    updated = old_raw ^ operand
                elif operation == 12:
                    updated = old_raw & operand
                elif operation == 8:
                    updated = old_raw | operand
                elif operation in (16, 20):
                    choose_old = (signed(old_raw, size * 8) < signed(operand, size * 8)
                                  if operation == 16 else
                                  signed(old_raw, size * 8) > signed(operand, size * 8))
                    updated = old_raw if choose_old else operand
                elif operation in (24, 28):
                    updated = (min if operation == 24 else max)(old_raw, operand)
                else:
                    raise NotImplementedError(f"unmodeled AMO operation {operation}")
            shifted = ((updated & width_mask) << (8 * (a & 7))) & MASK64
            mask = ((1 << size) - 1) << (a & 7)
            if writing:
                for byte in range(size):
                    self.memory[physical + byte] = (updated >> (8 * byte)) & 255
                self.reservation = None
            memory = (int(writing), a, mask if writing else 0,
                      shifted if writing else 0, old)
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


class ArchitecturalTrap(Exception):
    def __init__(self, cause, tval):
        super().__init__(f"architectural exception {cause} tval={tval:x}")
        self.cause = cause
        self.tval = tval


class FaultMachine(StartupMachine):
    """Translation-fault reference for short real privileged software programs."""

    def __init__(self, words, initial_data):
        super().__init__(words, initial_data)
        self.csrs[0x302] = 0

    def physical(self, address, access):
        result = sv39(address, access, self.priv, self.csrs[0x180],
                      self.csrs[0x300], self.read_pte)
        if result.fault:
            raise ArchitecturalTrap(
                (12, 13, 15, 15)[access] if result.fault == "page" else
                (1, 5, 7, 7)[access], address)
        physical = result.pa
        legal = (0 <= physical < len(self.words) * 4 if access == 0 else
                 0x10000000 <= physical < 0x10008000)
        if not legal:
            raise ArchitecturalTrap((1, 5, 7, 7)[access], address)
        return physical

    def step(self):
        pc = self.pc
        try:
            event = super().step()
        except ArchitecturalTrap as trap:
            target = 1 if self.priv != 3 and self.csrs[0x302] & (1 << trap.cause) else 3
            return ("T", pc, trap.cause, trap.tval, target, 0)
        if event[0] == "T":
            target = 1 if self.priv != 3 and self.csrs[0x302] & (1 << event[2]) else 3
            return (*event[:4], target, 0)
        return event


def load_constant(register, value):
    """Positive 11-bit chunks avoid assembler and signed-immediate dependencies."""
    value &= MASK64
    chunks = []
    while value:
        chunks.append(value & 2047)
        value >>= 11
    if not chunks:
        return [i_type(0x13, register, 0, 0, 0)]
    words = [i_type(0x13, register, 0, 0, chunks.pop())]
    while chunks:
        words += [i_type(0x13, register, 1, register, 11),
                  i_type(0x13, register, 0, register, chunks.pop())]
    return words


class SystemMachine(FaultMachine):
    """Instruction/privilege oracle for actual software trap handlers and scheduling."""

    def __init__(self, words, initial_data):
        super().__init__(words, initial_data)
        for address in (0x105, 0x140, 0x141, 0x142, 0x143, 0x305, 0x340, 0x342, 0x343):
            self.csrs[address] = 0
        self.trap_counts = {}
        self.user_returns = 0
        self.stopped = False

    def physical(self, address, access):
        result = sv39(address, access, self.priv, self.csrs[0x180],
                      self.csrs[0x300], self.read_pte)
        if result.fault:
            raise ArchitecturalTrap(
                (12, 13, 15, 15)[access] if result.fault == "page" else
                (1, 5, 7, 7)[access], address)
        legal = (0 <= result.pa < len(self.words) * 4 if access == 0 else
                 0x10000000 <= result.pa < 0x10010000)
        if not legal:
            raise ArchitecturalTrap((1, 5, 7, 7)[access], address)
        return result.pa

    def trap(self, cause, tval):
        pc = self.pc
        target = 1 if self.priv != 3 and self.csrs[0x302] & (1 << cause) else 3
        status = self.csrs[0x300]
        if target == 1:
            self.csrs[0x141], self.csrs[0x142], self.csrs[0x143] = pc, cause, tval
            status = (status & ~((1 << 8) | (1 << 5) | (1 << 1))) | (
                int(self.priv == 1) << 8) | (((status >> 1) & 1) << 5)
        else:
            self.csrs[0x341], self.csrs[0x342], self.csrs[0x343] = pc, cause, tval
            status = (status & ~((3 << 11) | (1 << 7) | (1 << 3))) | (
                self.priv << 11) | (((status >> 3) & 1) << 7)
        self.csrs[0x300] = status
        self.priv = target
        self.pc = self.csrs[0x105 if target == 1 else 0x305] & ~3
        self.trap_counts[cause] = self.trap_counts.get(cause, 0) + 1
        self.stopped = cause == 9
        return ("T", pc, cause, tval, target, 0)

    def csr_read(self, address):
        if address == 0x100:
            return (self.csrs[0x300] & 0xC0122) | (2 << 32)
        if address == 0x300:
            return self.csrs[address] | (2 << 32) | (2 << 34)
        if address not in self.csrs:
            raise NotImplementedError(f"unmodeled system CSR {address:03x}")
        return self.csrs[address]

    def csr_write(self, address, value):
        if address == 0x100:
            mask = sum(1 << bit for bit in (1, 5, 8, 18, 19))
            self.csrs[0x300] = (self.csrs[0x300] & ~mask) | (value & mask)
        elif address == 0x180:
            if value >> 60 in (0, 8):
                self.csrs[address] = value
        elif address in (0x141, 0x341):
            self.csrs[address] = value & ~3
        elif address == 0x300:
            mask = sum(1 << bit for bit in (1, 3, 5, 7, 8, 11, 12, 17, 18, 19, 20, 21, 22))
            self.csrs[address] = value & mask
        elif address == 0x302:
            self.csrs[address] = value & sum(1 << bit for bit in
                                            (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 15))
        else:
            if address not in self.csrs:
                raise NotImplementedError(f"unmodeled system CSR write {address:03x}")
            self.csrs[address] = value & MASK64

    def step(self):
        try:
            instruction = self.fetch()
            pc, privilege = self.pc, self.priv
            if instruction & 127 != 0x73:
                return BareMachine.step(self)
            if instruction == 0x73:
                return self.trap({0: 8, 1: 9, 3: 11}[self.priv], 0)
            rd, rs1 = (instruction >> 7) & 31, (instruction >> 15) & 31
            operation = (instruction >> 12) & 7
            next_pc = pc + 4
            value, write = 0, False
            if instruction in (0x30200073, 0x10200073):
                status = self.csrs[0x300]
                if instruction == 0x30200073:
                    if self.priv != 3:
                        return self.trap(2, instruction)
                    self.priv = (status >> 11) & 3
                    next_pc = self.csrs[0x341]
                    status = (status & ~((3 << 11) | (1 << 3))) | (
                        ((status >> 7) & 1) << 3) | (1 << 7)
                else:
                    if self.priv == 0 or self.priv == 1 and status & (1 << 22):
                        return self.trap(2, instruction)
                    self.priv = (status >> 8) & 1
                    next_pc = self.csrs[0x141]
                    status = (status & ~((1 << 8) | (1 << 1))) | (
                        ((status >> 5) & 1) << 1) | (1 << 5)
                    if self.priv == 0:
                        self.user_returns += 1
                if self.priv < 3:
                    status &= ~(1 << 17)
                self.csrs[0x300] = status
            elif instruction & 0xFE007FFF == 0x12000073:
                if self.priv == 0 or self.priv == 1 and self.csrs[0x300] & (1 << 20):
                    return self.trap(2, instruction)
            elif operation in (1, 2, 3, 5, 6, 7):
                address = instruction >> 20
                if self.priv < ((address >> 8) & 3):
                    return self.trap(2, instruction)
                if address == 0x180 and self.priv == 1 and self.csrs[0x300] & (1 << 20):
                    return self.trap(2, instruction)
                old = self.csr_read(address)
                source = rs1 if operation & 4 else self.regs[rs1]
                updated = source if operation & 3 == 1 else (
                    old | source if operation & 3 == 2 else old & ~source)
                if operation & 3 == 1 or rs1 != 0:
                    self.csr_write(address, updated)
                value, write = old, rd != 0
                if write:
                    self.regs[rd] = old
            else:
                raise NotImplementedError(f"unmodeled system instruction {instruction:08x}")
            self.pc = next_pc
            return ("R", pc, instruction, next_pc, int(write),
                    rd if write else 0, value if write else 0, None, privilege)
        except ArchitecturalTrap as trap:
            return self.trap(trap.cause, trap.tval)


class ConsoleMachine(SystemMachine):
    """Minimal register oracle for the compact software console experiment."""

    def __init__(self, words, initial_data):
        super().__init__(words, initial_data)
        self.console = []
        self.line_control = 0

    def physical(self, address, access):
        result = sv39(address, access, self.priv, self.csrs[0x180],
                      self.csrs[0x300], self.read_pte)
        if not result.fault and access in (1, 2) and 0x10010000 <= result.pa < 0x10010008:
            return result.pa
        return super().physical(address, access)

    def read_memory(self, address, size):
        if 0x10010000 <= address < 0x10010008:
            if address == 0x10010005 and size == 1:
                # The program waits >160 retired NOPs after its only THR write.
                return 0x60
            raise NotImplementedError(f"unmodeled compact console read {address:x}/{size}")
        return super().read_memory(address, size)

    def write_memory(self, address, size, value):
        if 0x10010000 <= address < 0x10010008:
            if size != 1:
                raise AssertionError("compact console software must issue byte writes")
            if address == 0x10010003:
                self.line_control = value & 255
            elif address == 0x10010000 and self.line_control == 3:
                self.console.append(value & 255)
            else:
                raise NotImplementedError(f"unmodeled compact console write {address:x}/{value:x}")
            return
        return super().write_memory(address, size, value)
