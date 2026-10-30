#!/usr/bin/env python3
"""Independent architectural RV64IMA/M/S/U interpreter.

This model is deliberately NOT a timed full-system oracle: one functional tick
per interpreter step does not predict the pipelined RTL's released edges.
UART writes here are register transactions, not a serialized pin capture.
"""

from dataclasses import dataclass
from collections import deque
import struct
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from architecture import PageFault, XLEN_MASK, amo, leaf, muldiv, signed, walk


MASK = XLEN_MASK
RAM_BASE = 0x80000000
RAM_BYTES = 128 * 1024 * 1024
STATUS_BITS = sum(1 << bit for bit in (1, 3, 5, 7, 8, 11, 12, 17, 18, 19, 20, 21, 22))
SSTATUS_BITS = sum(1 << bit for bit in (1, 5, 8, 18, 19))
XLEN_FIELDS = (2 << 32) | (2 << 34)


class ArchitecturalTrap(Exception):
    def __init__(self, cause, tval=0):
        self.cause, self.tval = cause, tval & MASK
        super().__init__(f"trap {cause:#x}, tval={self.tval:#x}")


class ReferencePlatform:
    """Byte RAM and functional MMIO; tick identity is explicitly not RTL time."""

    def __init__(self):
        self.ram = bytearray(RAM_BYTES)
        self.rom = bytearray(128)
        self.ticks = 0
        self.mtime = 0
        self.mtimecmp = MASK
        self.msip = 0
        self.uart = bytearray()
        self.uart_registers = [0] * 8
        self.divisor = 1
        self.rx = deque()
        self.thre_pending = False
        self.plic_priority = [0] * 33
        self.plic_enable = [0, 0]
        self.plic_threshold = [0, 0]
        self.plic_pending = 0
        self.plic_service = 0
        self.plic_claims = 0
        self.plic_completions = 0

    def load_image(self, path, address):
        blob = Path(path).read_bytes()
        offset = address - RAM_BASE
        if not blob or offset < 0 or offset + len(blob) > RAM_BYTES:
            raise ValueError(f"Image outside declared RAM: {path}")
        self.ram[offset:offset + len(blob)] = blob

    def tick(self):
        self.ticks += 1
        self.mtime = (self.mtime + 1) & MASK
        if self.uart_irq() and not (self.plic_service & 2):
            self.plic_pending |= 2

    def uart_irq(self):
        ier = self.uart_registers[1]
        return bool((ier & 1 and self.rx) or (ier & 2 and self.thre_pending))

    def plic_source(self, context):
        eligible = self.plic_pending & self.plic_enable[context] & ~self.plic_service
        if not eligible:
            return 0
        candidates = [source for source in range(1, 33) if eligible >> source & 1 and
                      self.plic_priority[source] > self.plic_threshold[context]]
        if not candidates:
            return 0
        return max(candidates, key=lambda source: (self.plic_priority[source], -source))

    def plic_register(self, address):
        if 0x0C000004 <= address <= 0x0C000080 and address % 4 == 0:
            return "priority", (address - 0x0C000000) // 4
        for context in (0, 1):
            if address in (0x0C002000 + context * 128, 0x0C002004 + context * 128):
                return "enable", (context, (address & 4) * 8)
            if address == 0x0C200000 + context * 4096:
                return "threshold", context
            if address == 0x0C200004 + context * 4096:
                return "claim", context
        if address in (0x0C001000, 0x0C001004):
            return "pending", (address & 4) * 8
        return None

    def memory(self, address, width):
        if RAM_BASE <= address and address + width <= RAM_BASE + RAM_BYTES:
            return self.ram, address - RAM_BASE
        if 0 <= address and address + width <= len(self.rom):
            return self.rom, address
        return None

    def read(self, address, width):
        region = self.memory(address, width)
        if region:
            data, offset = region
            return int.from_bytes(data[offset:offset + width], "little")
        for base, extent, value in (
            (0x02000000, 4, self.msip),
            (0x02004000, 8, self.mtimecmp),
            (0x0200BFF8, 8, self.mtime),
        ):
            if base <= address and address + width <= base + extent:
                return (value >> (8 * (address - base))) & ((1 << (8 * width)) - 1)
        if 0x10010000 <= address < 0x10010008 and width == 1:
            offset = address - 0x10010000
            if self.uart_registers[3] & 0x80 and offset < 2:
                return self.divisor >> (8 * offset) & 255
            if offset == 5:
                return 0x60 | int(bool(self.rx))
            if offset == 2:
                fifo = 0xC0 if self.uart_registers[2] & 1 else 0
                if self.uart_registers[1] & 1 and self.rx:
                    return fifo | 4
                if self.uart_registers[1] & 2 and self.thre_pending:
                    self.thre_pending = False
                    return fifo | 2
                return fifo | 1
            if offset == 0:
                return self.rx.popleft() if self.rx else 0
            return self.uart_registers[offset]
        register = self.plic_register(address)
        if register and width == 4:
            kind, index = register
            if kind == "priority":
                return self.plic_priority[index]
            if kind == "threshold":
                return self.plic_threshold[index]
            if kind == "enable":
                context, shift = index
                return self.plic_enable[context] >> shift & 0xFFFFFFFF
            if kind == "pending":
                return self.plic_pending >> index & 0xFFFFFFFF
            source = self.plic_source(index)
            if source:
                self.plic_pending &= ~(1 << source)
                self.plic_service |= 1 << source
                self.plic_claims += 1
            return source
        raise ArchitecturalTrap(5, address)

    def write(self, address, width, value):
        value &= (1 << (8 * width)) - 1
        region = self.memory(address, width)
        if region:
            data, offset = region
            data[offset:offset + width] = value.to_bytes(width, "little")
            return
        for base, extent, attribute in (
            (0x02000000, 4, "msip"),
            (0x02004000, 8, "mtimecmp"),
            (0x0200BFF8, 8, "mtime"),
        ):
            if base <= address and address + width <= base + extent:
                shift = 8 * (address - base)
                mask = ((1 << (8 * width)) - 1) << shift
                updated = (getattr(self, attribute) & ~mask) | value << shift
                setattr(self, attribute, updated & (1 if attribute == "msip" else MASK))
                return
        if 0x10010000 <= address < 0x10010008 and width == 1:
            offset = address - 0x10010000
            if self.uart_registers[3] & 0x80 and offset < 2:
                mask = 255 << (8 * offset)
                self.divisor = self.divisor & ~mask | value << (8 * offset)
            elif offset == 0:
                self.uart.append(value)
                self.thre_pending = bool(self.uart_registers[1] & 2)
            else:
                if offset == 1 and value & 2 and not self.uart_registers[1] & 2:
                    self.thre_pending = True
                if offset == 2:
                    if value & 2:
                        self.rx.clear()
                    if value & 4 and self.uart_registers[1] & 2:
                        self.thre_pending = True
                self.uart_registers[offset] = value
            return
        register = self.plic_register(address)
        if register and width == 4:
            kind, index = register
            if kind == "priority":
                self.plic_priority[index] = value & 7
            elif kind == "threshold":
                self.plic_threshold[index] = value & 7
            elif kind == "enable":
                context, shift = index
                mask = 0xFFFFFFFF << shift
                self.plic_enable[context] = (
                    self.plic_enable[context] & ~mask | value << shift
                ) & ((1 << 33) - 2)
            elif kind == "claim":
                if 1 <= value <= 32 and self.plic_service >> value & 1:
                    self.plic_service &= ~(1 << value)
                    self.plic_completions += 1
            return
        raise ArchitecturalTrap(7, address)


@dataclass(frozen=True)
class Commit:
    pc: int
    instruction: int
    next_pc: int
    privilege: int
    rd: int
    value: int
    memory: tuple | None


class Machine:
    """ISA-level state, abstract translation cache and standard trap semantics."""

    def __init__(self, platform):
        self.platform = platform
        self.registers = [0] * 32
        self.pc = 0
        self.privilege = 3
        self.csrs = {key: 0 for key in (
            0x300, 0x302, 0x303, 0x304, 0x305, 0x306, 0x340, 0x341,
            0x342, 0x343, 0x344, 0x105, 0x106, 0x140, 0x141, 0x142,
            0x143, 0x180, 0xB00, 0xB02,
        )}
        self.translations = {"fetch": [], "data": []}
        self.reservation = None
        self.sleeping = False
        self.commits = 0
        self.traps = []

    def pending(self):
        return (self.csrs[0x344] & 0x22) | self.platform.msip << 3 | \
            int(self.platform.mtime >= self.platform.mtimecmp) << 7 | \
            int(bool(self.platform.plic_source(0))) << 11 | \
            int(bool(self.platform.plic_source(1))) << 9

    def effective_privilege(self, access):
        status = self.csrs[0x300]
        if access != "fetch" and self.privilege == 3 and status & (1 << 17):
            return status >> 11 & 3
        return self.privilege

    def translate(self, address, access):
        satp = self.csrs[0x180]
        privilege = self.effective_privilege(access)
        if privilege == 3 or satp >> 60 == 0:
            return address
        sum_enabled = bool(self.csrs[0x300] & (1 << 18))
        mxr = bool(self.csrs[0x300] & (1 << 19))
        asid = satp >> 44 & 0xFFFF
        cache = self.translations["fetch" if access == "fetch" else "data"]
        try:
            for entry in cache:
                size = 4096 * 512 ** entry["level"]
                if (entry["global"] or entry["asid"] == asid) and \
                        address // size == entry["va"] // size:
                    return leaf(address, entry["ppn"], entry["level"], entry["flags"],
                                access, privilege, sum_enabled, mxr).physical
            result = walk(lambda pa: self.platform.read(pa, 8), address, satp,
                          access, privilege, sum_enabled, mxr)
            size = 4096 * 512 ** result.level
            ppn = (result.physical - address % size) // 4096
            cache.append({"va": address, "ppn": ppn, "level": result.level,
                          "flags": result.flags, "asid": asid,
                          "global": result.global_mapping})
            if len(cache) > 8:
                cache.pop(0)
            return result.physical
        except PageFault as error:
            raise ArchitecturalTrap(error.cause, address) from error
        except ArchitecturalTrap as error:
            raise ArchitecturalTrap({"fetch": 1, "load": 5, "store": 7, "atomic": 7}[access],
                                    address) from error

    def sfence(self, va, asid):
        for kind, entries in self.translations.items():
            retained = []
            for entry in entries:
                size = 4096 * 512 ** entry["level"]
                matches_va = va is None or va // size == entry["va"] // size
                matches_asid = asid is None or (
                    not entry["global"] and entry["asid"] == (asid & 0xFFFF)
                )
                if not (matches_va and matches_asid):
                    retained.append(entry)
            self.translations[kind] = retained

    def read(self, address, width, access="load"):
        if address % width:
            raise ArchitecturalTrap(0 if access == "fetch" else 4, address)
        physical = self.translate(address, access)
        try:
            return self.platform.read(physical, width)
        except ArchitecturalTrap as error:
            raise ArchitecturalTrap(1 if access == "fetch" else 5, address) from error

    def write(self, address, width, value):
        if address % width:
            raise ArchitecturalTrap(6, address)
        physical = self.translate(address, "store")
        try:
            self.platform.write(physical, width, value)
        except ArchitecturalTrap as error:
            raise ArchitecturalTrap(7, address) from error
        self.reservation = None

    def csr_read(self, address, instruction=0):
        if self.privilege < (address >> 8 & 3):
            raise ArchitecturalTrap(2, instruction)
        status = self.csrs[0x300]
        if address == 0x180 and self.privilege == 1 and status & (1 << 20):
            raise ArchitecturalTrap(2, instruction)
        if address in (0xC00, 0xC01, 0xC02):
            bit = address - 0xC00
            if self.privilege != 3 and (
                not (self.csrs[0x306] >> bit & 1) or
                (self.privilege == 0 and not (self.csrs[0x106] >> bit & 1))
            ):
                raise ArchitecturalTrap(2, instruction)
            return (self.csrs[0xB00], self.platform.mtime, self.csrs[0xB02])[bit]
        if address == 0x100:
            return (status & SSTATUS_BITS) | (2 << 32)
        if address == 0x300:
            return status | XLEN_FIELDS
        if address == 0x301:
            return (2 << 62) | sum(1 << (ord(letter) - ord("A")) for letter in "IMASU")
        if address == 0x344:
            return self.pending()
        if address == 0x144:
            return self.pending() & self.csrs[0x303] & 0x222
        if address == 0x104:
            return self.csrs[0x304] & self.csrs[0x303] & 0x222
        if address in (0xF11, 0xF12, 0xF13, 0xF14):
            return 0
        if address not in self.csrs:
            raise ArchitecturalTrap(2, instruction)
        return self.csrs[address]

    def csr_write(self, address, value, instruction):
        if address >> 10 == 3:
            raise ArchitecturalTrap(2, instruction)
        value &= MASK
        if address == 0x100:
            self.csrs[0x300] = (self.csrs[0x300] & ~SSTATUS_BITS) | value & SSTATUS_BITS
        elif address == 0x300:
            status = value & STATUS_BITS
            if status >> 11 & 3 == 2:
                status &= ~(3 << 11)
            self.csrs[address] = status
        elif address in (0x104, 0x304):
            mask = self.csrs[0x303] & 0x222 if address == 0x104 else 0xAAA
            self.csrs[0x304] = self.csrs[0x304] & ~mask | value & mask
        elif address in (0x144, 0x344):
            mask = self.csrs[0x303] & 2 if address == 0x144 else 0x22
            self.csrs[0x344] = self.csrs[0x344] & ~mask | value & mask
        elif address in (0x105, 0x305):
            self.csrs[address] = value & ~3 | int(value & 3 == 1)
        elif address in (0x141, 0x341):
            self.csrs[address] = value & ~3
        elif address in (0x106, 0x306):
            self.csrs[address] = value & 7
        elif address in (0x302, 0x303):
            self.csrs[address] = value & (0xB3FF if address == 0x302 else 0x222)
        elif address == 0x180:
            if value >> 60 in (0, 8):
                self.csrs[address] = value
                self.sfence(None, None)
        elif address == 0x301:
            pass
        elif address in self.csrs:
            self.csrs[address] = value
        else:
            raise ArchitecturalTrap(2, instruction)

    def trap(self, cause, tval=0, interrupt=False):
        delegated = self.csrs[0x303 if interrupt else 0x302] >> cause & 1
        target = 1 if self.privilege != 3 and delegated else 3
        status = self.csrs[0x300]
        prefix = 0x100 if target == 1 else 0x300
        self.csrs[prefix + 0x41] = self.pc
        self.csrs[prefix + 0x42] = cause | ((1 << 63) if interrupt else 0)
        self.csrs[prefix + 0x43] = tval
        enable = 1 if target == 1 else 3
        previous = 5 if target == 1 else 7
        status = status & ~(1 << previous) | ((status >> enable & 1) << previous)
        status &= ~(1 << enable)
        if target == 1:
            status = status & ~(1 << 8) | int(self.privilege == 1) << 8
        else:
            status = status & ~(3 << 11) | self.privilege << 11
        self.csrs[0x300] = status
        vector = self.csrs[prefix + 5]
        self.traps.append((self.pc, cause, tval, target, interrupt))
        self.pc = (vector & ~3) + (4 * cause if interrupt and vector & 3 == 1 else 0)
        self.privilege = target
        self.reservation = None
        self.sleeping = False

    def interrupt(self):
        pending = self.pending() & self.csrs[0x304]
        status = self.csrs[0x300]
        for cause in (11, 3, 7, 9, 1, 5):
            if not (pending >> cause & 1):
                continue
            target = 1 if self.csrs[0x303] >> cause & 1 else 3
            enabled = self.privilege < target or (
                self.privilege == target and status >> (1 if target == 1 else 3) & 1
            )
            if enabled:
                self.trap(cause, interrupt=True)
                return True
        return False

    def step(self):
        self.platform.tick()
        self.csrs[0xB00] = (self.csrs[0xB00] + 1) & MASK
        if self.interrupt():
            return None
        if self.sleeping:
            if self.pending() & self.csrs[0x304]:
                self.sleeping = False
            return None
        try:
            return self.execute()
        except ArchitecturalTrap as error:
            self.trap(error.cause, error.tval)
            return None

    def atomic(self, instruction, address, operand):
        width, operation = 1 << (instruction >> 12 & 7), instruction >> 27
        if width not in (4, 8) or operation not in (0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 28) or \
                operation == 2 and instruction >> 20 & 31:
            raise ArchitecturalTrap(2, instruction)
        if address % width:
            raise ArchitecturalTrap(4 if operation == 2 else 6, address)
        if operation == 2:
            value = signed(self.read(address, width), width * 8)
            self.reservation = (self.translate(address, "load"), width)
            return value, ("load", address, width, value & MASK)
        if operation == 3:
            physical = self.translate(address, "store")
            success = self.reservation == (physical, width)
            self.reservation = None
            if success:
                self.write(address, width, operand)
            return int(not success), (
                ("store", address, width, operand & ((1 << (width * 8)) - 1))
                if success else None
            )
        physical = self.translate(address, "atomic")
        old = self.platform.read(physical, width)
        updated = amo(operation, old, operand, width)
        self.platform.write(physical, width, updated)
        self.reservation = None
        return signed(old, width * 8), ("atomic", address, width, updated)

    def execute(self):
        pc, privilege = self.pc, self.privilege
        instruction = self.read(pc, 4, "fetch")
        opcode = instruction & 127
        rd, funct3 = instruction >> 7 & 31, instruction >> 12 & 7
        rs1, rs2 = instruction >> 15 & 31, instruction >> 20 & 31
        funct7 = instruction >> 25
        x, y = self.registers[rs1], self.registers[rs2]
        immediate = signed(instruction >> 20, 12)
        next_pc, value, write_rd, memory = (pc + 4) & MASK, 0, False, None

        def illegal():
            raise ArchitecturalTrap(2, instruction)

        if opcode in (0x37, 0x17):
            value = signed(instruction & 0xFFFFF000, 32)
            if opcode == 0x17:
                value += pc
            write_rd = True
        elif opcode == 0x6F:
            displacement = ((instruction >> 31) << 20) | \
                ((instruction >> 12 & 255) << 12) | \
                ((instruction >> 20 & 1) << 11) | ((instruction >> 21 & 1023) << 1)
            value, write_rd = next_pc, True
            next_pc = (pc + signed(displacement, 21)) & MASK
        elif opcode == 0x67 and funct3 == 0:
            value, write_rd = next_pc, True
            next_pc = (x + immediate) & MASK & ~1
        elif opcode == 0x63:
            displacement = ((instruction >> 31) << 12) | \
                ((instruction >> 7 & 1) << 11) | \
                ((instruction >> 25 & 63) << 5) | (instruction >> 8 & 15) << 1
            predicates = {0: x == y, 1: x != y, 4: signed(x) < signed(y),
                          5: signed(x) >= signed(y), 6: x < y, 7: x >= y}
            if funct3 not in predicates:
                illegal()
            if predicates[funct3]:
                next_pc = (pc + signed(displacement, 13)) & MASK
        elif opcode in (0x03, 0x23):
            store = opcode == 0x23
            if store:
                immediate = signed((instruction >> 25) << 5 | instruction >> 7 & 31, 12)
            if funct3 > (3 if store else 6):
                illegal()
            width = 1 << (funct3 & 3)
            address = (x + immediate) & MASK
            if store:
                self.write(address, width, y)
                memory = ("store", address, width, y & ((1 << (8 * width)) - 1))
            else:
                value = self.read(address, width)
                if funct3 < 4:
                    value = signed(value, width * 8)
                write_rd = True
                memory = ("load", address, width, value & MASK)
        elif opcode in (0x13, 0x1B):
            word = opcode == 0x1B
            bits = 32 if word else 64
            shift = instruction >> 20 & (bits - 1)
            if funct3 == 0:
                value = x + immediate
            elif not word and funct3 in (2, 3, 4, 6, 7):
                value = {2: int(signed(x) < immediate), 3: int(x < (immediate & MASK)),
                         4: x ^ immediate, 6: x | immediate, 7: x & immediate}[funct3]
            elif funct3 == 1:
                if instruction >> (25 if word else 26):
                    illegal()
                value = x << shift
            elif funct3 == 5:
                upper = instruction >> (25 if word else 26)
                if upper not in (0, 0x20 if word else 0x10):
                    illegal()
                value = signed(x, bits) >> shift if upper else \
                    (x & ((1 << bits) - 1)) >> shift
            else:
                illegal()
            if word:
                value = signed(value, 32)
            write_rd = True
        elif opcode in (0x33, 0x3B):
            word = opcode == 0x3B
            shift = y & (31 if word else 63)
            if funct7 == 1:
                operations = ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu")
                if word and funct3 in (1, 2, 3):
                    illegal()
                value = muldiv(operations[funct3], x, y, word)
            elif funct7 in (0, 0x20):
                if funct7 == 0x20 and funct3 not in (0, 5):
                    illegal()
                if word and funct3 not in (0, 1, 5):
                    illegal()
                value = {
                    0: x - y if funct7 else x + y, 1: x << shift,
                    2: int(signed(x) < signed(y)), 3: int(x < y), 4: x ^ y,
                    5: signed(x, 32 if word else 64) >> shift if funct7 else
                        (x & (0xFFFFFFFF if word else MASK)) >> shift,
                    6: x | y, 7: x & y,
                }[funct3]
                if word:
                    value = signed(value, 32)
            else:
                illegal()
            write_rd = True
        elif opcode == 0x0F:
            if funct3 not in (0, 1):
                illegal()
            self.reservation = None
        elif opcode == 0x2F:
            value, memory = self.atomic(instruction, x, y)
            write_rd = True
        elif opcode == 0x73:
            if funct3:
                if funct3 == 4:
                    illegal()
                address = instruction >> 20
                value = self.csr_read(address, instruction)
                source = rs1 if funct3 & 4 else x
                operation = funct3 & 3
                if operation == 1 or rs1:
                    changed = source if operation == 1 else \
                        value | source if operation == 2 else value & ~source
                    self.csr_write(address, changed, instruction)
                write_rd = True
            elif instruction == 0x00000073:
                raise ArchitecturalTrap(8 + privilege, 0)
            elif instruction == 0x00100073:
                raise ArchitecturalTrap(3, pc)
            elif instruction in (0x30200073, 0x10200073):
                machine = instruction == 0x30200073
                status = self.csrs[0x300]
                if (machine and privilege != 3) or (not machine and (
                    privilege == 0 or privilege == 1 and status & (1 << 22)
                )):
                    illegal()
                if machine:
                    self.privilege = status >> 11 & 3
                    status = status & ~(1 << 3) | (status >> 7 & 1) << 3 | (1 << 7)
                    status &= ~(3 << 11)
                else:
                    self.privilege = 1 if status & (1 << 8) else 0
                    status = status & ~(1 << 1) | (status >> 5 & 1) << 1 | (1 << 5)
                    status &= ~(1 << 8)
                if self.privilege != 3:
                    status &= ~(1 << 17)
                self.csrs[0x300] = status
                next_pc = self.csrs[0x341 if machine else 0x141]
                self.reservation = None
            elif instruction == 0x10500073:
                if privilege == 0 or (privilege != 3 and self.csrs[0x300] & (1 << 21)):
                    illegal()
                self.sleeping = not bool(self.pending() & self.csrs[0x304])
                self.reservation = None
            elif instruction & 0xFE007FFF == 0x12000073:
                if privilege == 0 or (privilege == 1 and self.csrs[0x300] & (1 << 20)):
                    illegal()
                self.sfence(x if rs1 else None, y if rs2 else None)
                self.reservation = None
            else:
                illegal()
        else:
            illegal()
        if next_pc & 3:
            raise ArchitecturalTrap(0, next_pc)
        value &= MASK
        if write_rd and rd:
            self.registers[rd] = value
        self.registers[0] = 0
        self.pc = next_pc
        self.commits += 1
        wrote_instret = opcode == 0x73 and funct3 and instruction >> 20 == 0xB02 and \
            ((funct3 & 3) == 1 or rs1 != 0)
        if not wrote_instret:
            self.csrs[0xB02] = (self.csrs[0xB02] + 1) & MASK
        return Commit(pc, instruction, next_pc, privilege, rd if write_rd else 0, value, memory)


def install_trampoline(platform):
    # Derived from the frozen handoff ABI; independent of the ROM source file.
    words = (0x00000513, 0x043F05B7, 0x00559593,
             0x00100293, 0x01F29293, 0x00028067)
    for index, word in enumerate(words):
        struct.pack_into("<I", platform.rom, index * 4, word)
