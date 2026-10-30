#!/usr/bin/env python3
"""Independent RISC-V integer and Sv39 rules from the privileged/unprivileged ISA."""

from dataclasses import dataclass


XLEN_MASK = (1 << 64) - 1
PPN_MASK = (1 << 44) - 1


def signed(value, bits=64):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def canonical(va):
    va &= XLEN_MASK
    return va < (1 << 38) or va >= (1 << 64) - (1 << 38)


class PageFault(Exception):
    def __init__(self, va, access, reason):
        self.va = va & XLEN_MASK
        self.cause = {"fetch": 12, "load": 13, "store": 15, "atomic": 15}[access]
        self.reason = reason
        super().__init__(f"Sv39 page fault {self.cause} at {self.va:#x}: {reason}")


@dataclass(frozen=True)
class Translation:
    physical: int
    level: int
    flags: int
    global_mapping: bool


def leaf(va, ppn, level, flags, access, privilege, sum_enabled=False, mxr=False):
    """Translate a leaf; A/D management is the admitted software-fault policy."""
    va &= XLEN_MASK
    reason = None
    permissions = {bit for bit in "VRWXUGAD" if flags & (1 << "VRWXUGAD".index(bit))}
    if not canonical(va):
        reason = "noncanonical virtual address"
    elif level not in (0, 1, 2):
        reason = "invalid page size"
    elif "V" not in permissions or ("W" in permissions and "R" not in permissions):
        reason = "invalid PTE encoding"
    elif not permissions.intersection({"R", "X"}):
        reason = "not a leaf"
    elif ppn * 4096 % (4096 * 512 ** level):
        reason = "misaligned superpage"
    elif privilege == 0 and "U" not in permissions:
        reason = "U-mode cannot access supervisor pages"
    elif privilege == 1 and "U" in permissions and (access == "fetch" or not sum_enabled):
        reason = "S-mode access to U page denied"
    elif access == "fetch" and "X" not in permissions:
        reason = "execute denied"
    elif access == "load" and not ("R" in permissions or (mxr and "X" in permissions)):
        reason = "read denied"
    elif access in ("store", "atomic") and "W" not in permissions:
        reason = "write denied"
    elif access == "atomic" and "R" not in permissions:
        reason = "atomic read denied"
    elif "A" not in permissions:
        reason = "accessed bit clear"
    elif access in ("store", "atomic") and "D" not in permissions:
        reason = "dirty bit clear"
    if reason:
        raise PageFault(va, access, reason)
    page_size = 4096 * 512 ** level
    return Translation(
        (ppn & PPN_MASK) * 4096 + va % page_size, level, flags, "G" in permissions
    )


def walk(read_u64, va, satp, access, privilege, sum_enabled=False, mxr=False):
    """Independent byte-addressed walk; read_u64 raises on physical bus errors."""
    if satp >> 60 == 0 or privilege == 3:
        return Translation(va & XLEN_MASK, -1, 0, False)
    if satp >> 60 != 8:
        raise ValueError("Only Bare and Sv39 are admitted")
    if not canonical(va):
        raise PageFault(va, access, "noncanonical virtual address")
    table = (satp & PPN_MASK) * 4096
    global_mapping = False
    for level in (2, 1, 0):
        vpn = (va // (4096 * 512 ** level)) % 512
        pte = read_u64(table + 8 * vpn)
        if pte >> 54 or not pte & 1 or (pte & 4 and not pte & 2):
            raise PageFault(va, access, "reserved or invalid PTE")
        flags = pte & 255
        ppn = (pte >> 10) & PPN_MASK
        global_mapping |= bool(flags & 32)
        if flags & 10:
            result = leaf(va, ppn, level, flags, access, privilege, sum_enabled, mxr)
            return Translation(result.physical, level, flags, global_mapping)
        if flags & (16 | 64 | 128):
            raise PageFault(va, access, "reserved nonleaf flags")
        table = ppn * 4096
    raise PageFault(va, access, "nonleaf at bottom level")


def muldiv(operation, lhs, rhs, word=False):
    """Exact M-extension wrap, signed quotient, remainder and overflow rules."""
    bits = 32 if word else 64
    mask = (1 << bits) - 1
    unsigned_lhs, unsigned_rhs = lhs & mask, rhs & mask
    signed_lhs, signed_rhs = signed(lhs, bits), signed(rhs, bits)
    if operation == "mul":
        answer = unsigned_lhs * unsigned_rhs
    elif operation == "mulh":
        answer = (signed_lhs * signed_rhs) >> bits
    elif operation == "mulhsu":
        answer = (signed_lhs * unsigned_rhs) >> bits
    elif operation == "mulhu":
        answer = (unsigned_lhs * unsigned_rhs) >> bits
    elif operation in ("div", "rem"):
        if signed_rhs == 0:
            answer = -1 if operation == "div" else signed_lhs
        else:
            quotient = abs(signed_lhs) // abs(signed_rhs)
            if (signed_lhs < 0) != (signed_rhs < 0):
                quotient = -quotient
            answer = quotient if operation == "div" else signed_lhs - quotient * signed_rhs
    elif operation in ("divu", "remu"):
        if unsigned_rhs == 0:
            answer = mask if operation == "divu" else unsigned_lhs
        else:
            answer = unsigned_lhs // unsigned_rhs if operation == "divu" else unsigned_lhs % unsigned_rhs
    else:
        raise ValueError(f"Unknown M-extension operation {operation}")
    answer &= mask
    return (signed(answer, 32) if word else answer) & XLEN_MASK


def amo(operation, old, operand, width):
    """Value stored by an RV64A read/modify/write, before result sign extension."""
    if width not in (4, 8):
        raise ValueError("An AMO is a word or doubleword")
    mask = (1 << (width * 8)) - 1
    old, operand = old & mask, operand & mask
    if operation == 0:
        return (old + operand) & mask
    if operation == 1:
        return operand
    if operation == 4:
        return old ^ operand
    if operation == 8:
        return old | operand
    if operation == 12:
        return old & operand
    if operation in (16, 20):
        comparison = signed(old, width * 8) < signed(operand, width * 8)
        return old if comparison == (operation == 16) else operand
    if operation in (24, 28):
        return min(old, operand) if operation == 24 else max(old, operand)
    raise ValueError(f"Unknown AMO operation {operation}")
