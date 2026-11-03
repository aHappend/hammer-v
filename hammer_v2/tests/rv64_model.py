"""Architectural RV64 integer/atomic oracle, independent of pipeline timing."""

from dataclasses import dataclass
import clint_model

MASK = (1 << 64) - 1
RAM_BASE = 0x10000000


def signed(value, width=64):
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


def sext(value, width):
    return signed(value, width) & MASK


def quotient(a, b):
    magnitude = abs(a) // abs(b)
    return -magnitude if (a < 0) != (b < 0) else magnitude


class Fault(Exception):
    def __init__(self, cause, tval):
        self.cause, self.tval = cause, tval & MASK
        super().__init__(f"architectural exception {cause}, tval={tval:#x}")


@dataclass
class Retirement:
    pc: int
    next_pc: int
    insn: int
    priv: int = 3
    rd_we: int = 0
    rd: int = 0
    rd_data: int = 0
    mem_valid: int = 0
    mem_write: int = 0
    mem_addr: int = 0
    mem_wmask: int = 0
    mem_wdata: int = 0
    mem_rdata: int = 0


class Machine:
    def __init__(self, instructions, dwords=128, clint_operations=None):
        self.instructions = list(instructions)
        self.regs = [0] * 32
        self.pc = 0
        self.priv = 3
        self.memory = bytearray(dwords * 8)
        self.touched = set()
        self.reservation = None
        self.instret = 0
        self.csrs = {
            0x300: 0, 0x302: 0, 0x303: 0, 0x304: 0, 0x305: 0,
            0x306: 0, 0x340: 0, 0x341: 0, 0x342: 0, 0x343: 0,
            0x344: 0, 0x105: 0, 0x106: 0, 0x140: 0, 0x141: 0,
            0x142: 0, 0x143: 0, 0x180: 0,
        }
        self.cycle_offset = 0
        self.time_offset = 0
        self.external_pending = 0
        self.mtimecmp = MASK
        self.msip = 0
        self.mmio = bytearray(65536)
        self.bus_events = []
        self.clint_operations = clint_operations
        self.clint_consumed = 0

    def pending(self, edge):
        if self.clint_operations is not None:
            time, compare, software = clint_model.state_before(self.clint_operations, edge)
            return (self.csrs[0x344] | self.external_pending | (software << 3) |
                    (int(time >= compare) << 7))
        return (self.csrs[0x344] | self.external_pending |
                (self.msip << 3) |
                (int(((edge - 1 + self.time_offset) & MASK) >= self.mtimecmp) << 7))

    def eligible_interrupt(self, edge):
        pending = self.pending(edge) & self.csrs[0x304]
        for cause in (11, 3, 7, 9, 1, 5):
            delegated = bool(self.csrs[0x303] & (1 << cause))
            target = 1 if delegated else 3
            enabled = self.priv < target or (
                self.priv == target and bool(self.csrs[0x300] & (1 << target)))
            if pending & (1 << cause) and enabled:
                return cause
        return None

    def read_memory(self, address, size):
        off = address - RAM_BASE
        if address % size:
            raise Fault(4, address)
        if self.clint_operations is not None and 0x02000000 <= address < 0x02010000:
            return self.clint_access(address, size, False, 0)
        if 0x40000000 <= address and address + size <= 0x40010000:
            return self.mmio_access(address, size, False, 0)
        if off < 0 or off + size > len(self.memory):
            raise Fault(5, address)
        self.touched.update(range(off, off + size))
        return int.from_bytes(self.memory[off:off + size], "little")

    def write_memory(self, address, size, value):
        if address % size:
            raise Fault(6, address)
        if self.clint_operations is not None and 0x02000000 <= address < 0x02010000:
            self.clint_access(address, size, True, value)
            return
        if 0x40000000 <= address and address + size <= 0x40010000:
            self.mmio_access(address, size, True, value)
            return
        if address in (0x02000000, 0x02004000):
            if address == 0x02000000 and size <= 4:
                self.msip = value & 1
                return
            if address == 0x02004000 and size == 8:
                self.mtimecmp = value & MASK
                return
            raise Fault(7, address)
        off = address - RAM_BASE
        if address % size:
            raise Fault(6, address)
        if off < 0 or off + size > len(self.memory):
            raise Fault(7, address)
        self.memory[off:off + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(
            size, "little")
        self.touched.update(range(off, off + size))
        if self.reservation and address // 8 == self.reservation[0] // 8:
            self.reservation = None

    def mmio_access(self, address, size, write, value):
        if not self.bus_events:
            raise AssertionError(f"MMIO {address:#x}: missing public bus transaction")
        observed = self.bus_events.pop(0)
        aligned = address & ~7
        off = aligned - 0x40000000
        error = int(off >= 65520)
        mask = ((1 << size) - 1) << (address & 7) if write else 0
        data = (value << (8 * (address & 7))) & MASK if write else 0
        read = 0 if write or error else int.from_bytes(self.mmio[off:off + 8], "little")
        expected = {"write": int(write), "address": aligned, "data": data,
                    "mask": mask, "read": read, "error": error}
        actual = {key: observed[key] for key in expected}
        if actual != expected:
            raise AssertionError(f"MMIO expected={expected}, observed={actual}")
        if error:
            raise Fault(7 if write else 5, address)
        offset = address - 0x40000000
        if write:
            self.mmio[offset:offset + size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
            return 0
        return int.from_bytes(self.mmio[offset:offset + size], "little")

    def clint_access(self, address, size, write, value):
        selected = [(base, length) for base, length in clint_model.REGISTERS
                    if base <= address < base + length]
        if not selected:
            raise Fault(7 if write else 5, address)
        if self.clint_consumed >= len(self.clint_operations):
            raise AssertionError(f"CLINT {address:#x}: missing accepted public request")
        operation = self.clint_operations[self.clint_consumed]
        self.clint_consumed += 1
        expected = {"write": int(write), "size": size.bit_length() - 1,
                    "address": address, "data": (value << (8 * (address & 7))) & MASK if write else 0,
                    "strobe": ((1 << size) - 1) << (address & 7) if write else 0}
        actual = {key: operation[key] for key in expected}
        if expected != actual:
            raise AssertionError(f"CLINT expected request={expected}, observed={actual}")
        if operation["error"]:
            raise Fault(7 if write else 5, address)
        return (operation["snapshot"] >> (8 * (address & 7))) & ((1 << (size * 8)) - 1)

    def read_csr(self, address, edge):
        status_fixed = (2 << 32) | (2 << 34)
        if address == 0x300:
            return self.csrs[address] | status_fixed
        if address == 0x100:
            return (self.csrs[0x300] & 0x122) | (2 << 32)
        if address == 0x301:
            return (2 << 62) | sum(1 << x for x in (0, 8, 12, 18, 20))
        if address == 0x104:
            return self.csrs[0x304] & self.csrs[0x303] & 0x222
        if address in (0x144, 0x344):
            pending = self.pending(edge)
            return pending if address == 0x344 else pending & self.csrs[0x303] & 0x222
        if address in (0xB00, 0xC00):
            return (edge - 1 + self.cycle_offset) & MASK
        if address == 0xC01:
            if self.clint_operations is not None:
                return clint_model.state_before(self.clint_operations, edge)[0]
            return (edge - 1 + self.time_offset) & MASK
        if address in (0xB02, 0xC02):
            return self.instret
        if address in (0xF11, 0xF12, 0xF13, 0xF14):
            return 0
        if address in self.csrs:
            return self.csrs[address]
        raise KeyError(address)

    def write_csr(self, address, value, edge):
        value &= MASK
        if address in (0x301, 0x180):
            return
        if address == 0x100:
            self.csrs[0x300] = (self.csrs[0x300] & ~0x122) | (value & 0x122)
        elif address == 0x300:
            status_mask = sum(1 << x for x in (1, 3, 5, 7, 8, 11, 12, 17, 20, 21, 22))
            value &= status_mask
            if (value >> 11) & 3 == 2:
                value &= ~(3 << 11)
            self.csrs[address] = value
        elif address in (0x105, 0x305):
            self.csrs[address] = (value & ~3) | (1 if value & 3 == 1 else 0)
        elif address in (0x141, 0x341):
            self.csrs[address] = value & ~3
        elif address == 0x302:
            self.csrs[address] = value & 0x3FF
        elif address == 0x303:
            self.csrs[address] = value & 0x222
        elif address == 0x304:
            self.csrs[address] = value & 0xAAA
        elif address == 0x104:
            mask = self.csrs[0x303] & 0x222
            self.csrs[0x304] = (self.csrs[0x304] & ~mask) | (value & mask)
        elif address == 0x344:
            self.csrs[address] = value & 0x22
        elif address == 0x144:
            if self.csrs[0x303] & 2:
                self.csrs[0x344] = (self.csrs[0x344] & ~2) | (value & 2)
        elif address in (0x106, 0x306):
            self.csrs[address] = value & 7
        elif address == 0xB00:
            self.cycle_offset = value - edge
        elif address == 0xB02:
            # step() applies the ordinary retirement increment below.
            self.instret = (value - 1) & MASK
        else:
            self.csrs[address] = value

    def step(self, edge=0):
        pc = self.pc
        if pc & 3:
            raise Fault(0, pc)
        if pc < 0 or pc // 4 >= len(self.instructions):
            raise Fault(1, pc)
        insn = self.instructions[pc // 4]
        opcode = insn & 127
        rd, f3 = (insn >> 7) & 31, (insn >> 12) & 7
        rs1, rs2 = (insn >> 15) & 31, (insn >> 20) & 31
        f7 = insn >> 25
        a, b = self.regs[rs1], self.regs[rs2]
        imm = signed(insn >> 20, 12)
        result = None
        event = Retirement(pc, (pc + 4) & MASK, insn, self.priv)

        def illegal():
            raise Fault(2, insn)

        if opcode in (0x37, 0x17):
            result = sext(insn & 0xFFFFF000, 32)
            if opcode == 0x17:
                result += pc
        elif opcode == 0x6F:
            offset = ((insn >> 31) << 20) | (((insn >> 12) & 255) << 12)
            offset |= ((insn >> 20) & 1) << 11
            offset |= ((insn >> 21) & 1023) << 1
            event.next_pc = (pc + signed(offset, 21)) & MASK
            result = pc + 4
        elif opcode == 0x67:
            if f3:
                illegal()
            event.next_pc = ((a + imm) & MASK) & ~1
            result = pc + 4
        elif opcode == 0x63:
            offset = ((insn >> 31) << 12) | (((insn >> 7) & 1) << 11)
            offset |= ((insn >> 25) & 63) << 5
            offset |= ((insn >> 8) & 15) << 1
            conditions = {0: a == b, 1: a != b, 4: signed(a) < signed(b),
                          5: signed(a) >= signed(b), 6: a < b, 7: a >= b}
            if f3 not in conditions:
                illegal()
            if conditions[f3]:
                event.next_pc = (pc + signed(offset, 13)) & MASK
        elif opcode in (0x13, 0x1B, 0x33, 0x3B):
            immediate = opcode in (0x13, 0x1B)
            width = 32 if opcode in (0x1B, 0x3B) else 64
            rhs = (imm & MASK) if immediate else b
            wm = (1 << width) - 1
            aa, bb = a & wm, rhs & wm
            shift = bb & (width - 1)
            if not immediate and f7 == 1:
                if width == 32 and f3 in (1, 2, 3):
                    illegal()
                sa, sb = signed(aa, width), signed(bb, width)
                if f3 == 0:
                    result = aa * bb
                elif f3 == 1:
                    result = (sa * sb) >> 64
                elif f3 == 2:
                    result = (sa * bb) >> 64
                elif f3 == 3:
                    result = (aa * bb) >> 64
                elif f3 in (4, 6):
                    q = -1 if sb == 0 else quotient(sa, sb)
                    result = q if f3 == 4 else sa if sb == 0 else sa - q * sb
                else:
                    q = wm if bb == 0 else aa // bb
                    result = q if f3 == 5 else aa if bb == 0 else aa % bb
            else:
                if width == 32 and f3 not in (0, 1, 5):
                    illegal()
                if not immediate and f7 not in (0, 32):
                    illegal()
                if not immediate and f7 == 32 and f3 not in (0, 5):
                    illegal()
                if immediate and f3 in (1, 5):
                    upper = insn >> (20 + (5 if width == 32 else 6))
                    if upper not in ((0,) if f3 == 1 else (0, 32 if width == 32 else 16)):
                        illegal()
                if f3 == 0:
                    result = aa - bb if not immediate and f7 == 32 else aa + bb
                elif f3 == 1:
                    result = aa << shift
                elif f3 == 2:
                    result = int(signed(a) < signed(rhs))
                elif f3 == 3:
                    result = int(a < rhs)
                elif f3 == 4:
                    result = a ^ rhs
                elif f3 == 5:
                    result = signed(aa, width) >> shift if insn & (1 << 30) else aa >> shift
                elif f3 == 6:
                    result = a | rhs
                else:
                    result = a & rhs
            if width == 32:
                result = sext(result, 32)
        elif opcode in (0x03, 0x23):
            store = opcode == 0x23
            if store:
                if f3 > 3:
                    illegal()
                offset = signed(((insn >> 25) << 5) | ((insn >> 7) & 31), 12)
            else:
                if f3 > 6:
                    illegal()
                offset = imm
            size = 1 << (f3 & 3)
            address = (a + offset) & MASK
            event.mem_valid, event.mem_write, event.mem_addr = 1, int(store), address
            if store:
                self.write_memory(address, size, b)
                event.mem_wmask = ((1 << size) - 1) << (address & 7)
                event.mem_wdata = (b << (8 * (address & 7))) & MASK
            else:
                loaded = self.read_memory(address, size)
                result = sext(loaded, 8 * size) if f3 < 4 else loaded
                event.mem_rdata = result
        elif opcode == 0x2F:
            op = insn >> 27
            if f3 not in (2, 3) or op not in (0, 1, 2, 3, 4, 8, 12, 16, 20, 24, 28):
                illegal()
            if op == 2 and rs2:
                illegal()
            size = 1 << f3
            if a % size:
                raise Fault(4 if op == 2 else 6, a)
            if a < RAM_BASE or a + size > RAM_BASE + len(self.memory):
                raise Fault(5 if op == 2 else 7, a)
            old_reservation = self.reservation
            if op in (2, 3):
                self.reservation = None
            # SC checks legality even when its reservation fails.
            try:
                old = self.read_memory(a, size)
            except Fault as fault:
                if op != 2:
                    raise Fault(fault.cause + 2, a) from fault
                raise
            mask = (1 << (8 * size)) - 1
            rhs = b & mask
            event.mem_valid, event.mem_addr = 1, a
            if op == 2:
                self.reservation = (a, size)
                result = sext(old, size * 8)
                event.mem_rdata = result
            elif op == 3:
                result = int(old_reservation != (a, size))
                if result == 0:
                    event.mem_write = 1
                    self.write_memory(a, size, rhs)
            else:
                values = {
                    0: old + rhs, 1: rhs, 4: old ^ rhs, 8: old | rhs, 12: old & rhs,
                    16: old if signed(old, size * 8) < signed(rhs, size * 8) else rhs,
                    20: old if signed(old, size * 8) > signed(rhs, size * 8) else rhs,
                    24: min(old, rhs), 28: max(old, rhs),
                }
                rhs = values[op] & mask
                self.write_memory(a, size, rhs)
                event.mem_write = 1
                result = sext(old, size * 8)
                event.mem_rdata = result
            if event.mem_write:
                event.mem_wmask = ((1 << size) - 1) << (a & 7)
                event.mem_wdata = (rhs << (8 * (a & 7))) & MASK
        elif opcode == 0x73:
            if f3 in (1, 2, 3, 5, 6, 7):
                address = insn >> 20
                writing = f3 in (1, 5) or rs1 != 0
                if self.priv < ((address >> 8) & 3) or (writing and address >> 10 == 3):
                    illegal()
                if address == 0x180 and self.priv == 1 and self.csrs[0x300] & (1 << 20):
                    illegal()
                if address in (0xC00, 0xC01, 0xC02) and self.priv != 3:
                    bit = 1 << (address - 0xC00)
                    if not self.csrs[0x306] & bit or (self.priv == 0 and not self.csrs[0x106] & bit):
                        illegal()
                try:
                    old = self.read_csr(address, edge)
                except KeyError:
                    illegal()
                source = rs1 if f3 >= 5 else a
                if writing:
                    changed = source if f3 in (1, 5) else old | source if f3 in (2, 6) else old & ~source
                    self.write_csr(address, changed, edge)
                result = old
            elif insn == 0x00000073:
                raise Fault({0: 8, 1: 9, 3: 11}[self.priv], 0)
            elif insn == 0x00100073:
                raise Fault(3, pc)
            elif insn in (0x30200073, 0x10200073):
                status = self.csrs[0x300]
                if insn == 0x30200073:
                    if self.priv != 3:
                        illegal()
                    self.priv = (status >> 11) & 3
                    status = (status & ~((1 << 3) | (3 << 11))) | (((status >> 7) & 1) << 3) | (1 << 7)
                    event.next_pc = self.csrs[0x341]
                    if self.priv != 3:
                        status &= ~(1 << 17)
                else:
                    if self.priv == 0 or (self.priv == 1 and status & (1 << 22)):
                        illegal()
                    self.priv = (status >> 8) & 1
                    status = (status & ~((1 << 1) | (1 << 8) | (1 << 17))) | (((status >> 5) & 1) << 1) | (1 << 5)
                    event.next_pc = self.csrs[0x141]
                self.csrs[0x300] = status
            elif insn == 0x10500073:
                if self.priv != 3 and self.csrs[0x300] & (1 << 21):
                    illegal()
            elif f3 == 0 and (insn >> 25) == 9 and rd == 0:
                if self.priv == 0 or (self.priv == 1 and self.csrs[0x300] & (1 << 20)):
                    illegal()
            else:
                illegal()
        elif opcode == 0x0F:
            if f3 not in (0, 1):
                illegal()
        else:
            illegal()
        if event.next_pc & 3:
            raise Fault(0, event.next_pc)
        if result is not None and rd:
            self.regs[rd] = result & MASK
            event.rd_we, event.rd, event.rd_data = 1, rd, result & MASK
        self.pc = event.next_pc
        self.instret = (self.instret + 1) & MASK
        return event

    def trap(self, fault, interrupt=False):
        cause = fault.cause
        delegated = self.priv != 3 and bool(
            self.csrs[0x303 if interrupt else 0x302] & (1 << cause))
        target = 1 if delegated else 3
        epc = self.pc
        status = self.csrs[0x300]
        if delegated:
            self.csrs[0x141], self.csrs[0x142], self.csrs[0x143] = epc & ~3, cause | (int(interrupt) << 63), fault.tval
            status = (status & ~0x122) | (((status >> 1) & 1) << 5) | (int(self.priv == 1) << 8)
            vector = self.csrs[0x105]
        else:
            self.csrs[0x341], self.csrs[0x342], self.csrs[0x343] = epc & ~3, cause | (int(interrupt) << 63), fault.tval
            status = (status & ~0x1888) | (((status >> 3) & 1) << 7) | (self.priv << 11)
            vector = self.csrs[0x305]
        self.csrs[0x300], self.priv, self.reservation = status, target, None
        self.pc = (vector & ~3) + (4 * cause if interrupt and vector & 3 == 1 else 0)
        return (epc, cause | (int(interrupt) << 63), fault.tval, target, int(interrupt))
