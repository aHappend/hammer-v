"""Ratified integer RV64C decode oracle, expressed as immediate bit maps."""
NOP = 0x00000013


def bits(value, low, width):
    return (value >> low) & ((1 << width) - 1)


def immediate(value, mapping, sign_bit=None, width=12):
    result = sum(((value >> source) & 1) << target for target, source in mapping)
    if sign_bit is not None and result & (1 << sign_bit):
        result -= 1 << (sign_bit + 1)
    return result & ((1 << width) - 1)


def iword(opcode, rd, funct3, rs1, imm):
    return (imm & 4095) << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode


def rword(opcode, rd, funct3, rs1, rs2, funct7=0):
    return funct7 << 25 | rs2 << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode


def sword(rs1, rs2, funct3, imm):
    return ((imm >> 5) & 127) << 25 | rs2 << 20 | rs1 << 15 | funct3 << 12 | \
        (imm & 31) << 7 | 0x23


CI = tuple(enumerate((2, 3, 4, 5, 6, 12)))
ADDI4SPN = ((2, 6), (3, 5), (4, 11), (5, 12),
            (6, 7), (7, 8), (8, 9), (9, 10))
LW = ((2, 6), (3, 10), (4, 11), (5, 12), (6, 5))
LD = ((3, 10), (4, 11), (5, 12), (6, 5), (7, 6))
ADDI16SP = ((4, 6), (5, 2), (6, 5), (7, 3), (8, 4), (9, 12))
JUMP = ((1, 3), (2, 4), (3, 5), (4, 11), (5, 2), (6, 7),
        (7, 6), (8, 9), (9, 10), (10, 8), (11, 12))
BRANCH = ((1, 3), (2, 4), (3, 10), (4, 11),
          (5, 2), (6, 5), (7, 6), (8, 12))
LWSP = ((2, 4), (3, 5), (4, 6), (5, 12), (6, 2), (7, 3))
LDSP = ((3, 5), (4, 6), (5, 12), (6, 2), (7, 3), (8, 4))
SWSP = ((2, 9), (3, 10), (4, 11), (5, 12), (6, 7), (7, 8))
SDSP = ((3, 10), (4, 11), (5, 12), (6, 7), (7, 8), (8, 9))


def decode(c):
    """Return (expanded instruction, illegal, instruction family).

    Hints map to a side-effect-free NOP. Illegal output is canonicalized only
    for comparison of this documented decompressor, not as trap emulation.
    """
    quadrant, group = c & 3, c >> 13
    rd, rs2 = bits(c, 7, 5), bits(c, 2, 5)
    crd, crs1 = 8 + bits(c, 2, 3), 8 + bits(c, 7, 3)
    ci = immediate(c, CI, 5)
    shamt = immediate(c, CI)
    high = bits(c, 12, 1)

    def legal(word, family):
        return word, False, family

    def illegal():
        return NOP, True, "reserved-or-unsupported"

    if quadrant == 0:
        if group == 0:
            imm = immediate(c, ADDI4SPN)
            return legal(iword(0x13, crd, 0, 2, imm), "addi4spn") if imm else illegal()
        if group in (2, 3):
            imm = immediate(c, LW if group == 2 else LD)
            return legal(iword(0x03, crd, group, crs1, imm), "lw" if group == 2 else "ld")
        if group in (6, 7):
            imm = immediate(c, LW if group == 6 else LD)
            return legal(sword(crs1, crd, group - 4, imm), "sw" if group == 6 else "sd")
        return illegal()
    if quadrant == 1:
        if group == 0:
            return legal(iword(0x13, rd, 0, rd, ci) if rd and ci else NOP, "addi-hint")
        if group == 1:
            return legal(iword(0x1B, rd, 0, rd, ci), "addiw") if rd else illegal()
        if group == 2:
            return legal(iword(0x13, rd, 0, 0, ci) if rd else NOP, "li-hint")
        if group == 3:
            if rd == 2:
                imm = immediate(c, ADDI16SP, 9)
                return legal(iword(0x13, 2, 0, 2, imm), "addi16sp") if imm else illegal()
            if not ci:
                return illegal()
            upper = immediate(c, CI, 5, 20)
            return legal(upper << 12 | rd << 7 | 0x37 if rd else NOP, "lui-hint")
        if group == 4:
            sub = bits(c, 10, 2)
            if sub in (0, 1):
                word = iword(0x13, crs1, 5, crs1, shamt | (sub << 10))
                return legal(word if shamt else NOP, "srli-hint" if sub == 0 else "srai-hint")
            if sub == 2:
                return legal(iword(0x13, crs1, 7, crs1, ci), "andi")
            alu = bits(c, 5, 2)
            if high:
                if alu >= 2:
                    return illegal()
                return legal(rword(0x3B, crs1, 0, crs1, crd, 0x20 if alu == 0 else 0),
                             "subw" if alu == 0 else "addw")
            return legal(rword(0x33, crs1, (0, 4, 6, 7)[alu], crs1, crd,
                               0x20 if alu == 0 else 0), ("sub", "xor", "or", "and")[alu])
        if group == 5:
            imm = immediate(c, JUMP, 11, 21)
            word = ((imm >> 20) & 1) << 31 | bits(imm, 1, 10) << 21 | \
                bits(imm, 11, 1) << 20 | bits(imm, 12, 8) << 12 | 0x6F
            return legal(word, "j")
        imm = immediate(c, BRANCH, 8, 13)
        word = bits(imm, 12, 1) << 31 | bits(imm, 5, 6) << 25 | \
            crs1 << 15 | (group - 6) << 12 | bits(imm, 1, 4) << 8 | \
            bits(imm, 11, 1) << 7 | 0x63
        return legal(word, "beqz" if group == 6 else "bnez")
    if quadrant == 2:
        if group == 0:
            return legal(iword(0x13, rd, 1, rd, shamt) if rd and shamt else NOP,
                         "slli-hint")
        if group in (2, 3):
            if not rd:
                return illegal()
            imm = immediate(c, LWSP if group == 2 else LDSP)
            return legal(iword(0x03, rd, group, 2, imm), "lwsp" if group == 2 else "ldsp")
        if group == 4:
            if not rs2:
                if not rd:
                    return legal(0x00100073, "ebreak") if high else illegal()
                return legal(iword(0x67, high, 0, rd, 0), "jalr" if high else "jr")
            return legal(rword(0x33, rd, 0, rd if high else 0, rs2) if rd else NOP,
                         "add-hint" if high else "mv-hint")
        if group in (6, 7):
            imm = immediate(c, SWSP if group == 6 else SDSP)
            return legal(sword(2, rs2, group - 4, imm), "swsp" if group == 6 else "sdsp")
    return illegal()
