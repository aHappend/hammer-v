"""Architectural page-table stimuli, with expected results from the Python oracle."""

import random

from oracle import MASK64, sv39
from oracle import i_type, r_type, s_type, load_constant, startup_program


def walker_cases(seed=17, count=1200):
    rng = random.Random(seed)
    classes = ("legal", "invalid-v", "write-only", "reserved-upper",
               "nonleaf-u", "nonleaf-a", "nonleaf-d", "access-root",
               "access-middle", "access-bottom", "misaligned-superpage",
               "accessed-clear", "dirty-clear", "noncanonical", "execute-only",
               "user-leaf", "supervisor-leaf")
    for number in range(count):
        kind = classes[number % len(classes)]
        level = number % 3
        # Cases requiring all three table levels deliberately use 4 KiB leaves.
        if kind in ("access-middle", "access-bottom"):
            level = 0
        if kind in ("nonleaf-u", "nonleaf-a", "nonleaf-d"):
            level = number % 2
        va = rng.getrandbits(39)
        if va & (1 << 38):
            va |= MASK64 ^ ((1 << 39) - 1)
        if kind == "noncanonical":
            va ^= 1 << 63
        access = (number // 3) % 4
        privilege = (number // 12) % 2
        sum_enable = bool(number & 1)
        mxr_enable = bool(number & 2)
        root = rng.getrandbits(44)
        asid = rng.getrandbits(16)
        tables = [rng.getrandbits(44), rng.getrandbits(44), root]
        physical_ppn = rng.getrandbits(44) & ~((1 << (9 * level)) - 1)
        flags = 0xCF  # V/R/W/X/A/D, supervisor leaf.
        if privilege == 0:
            flags |= 0x10
        if kind == "invalid-v":
            flags &= ~1
        elif kind == "write-only":
            flags = (flags | 4) & ~2
        elif kind == "accessed-clear":
            flags &= ~0x40
        elif kind == "dirty-clear":
            flags &= ~0x80
            access = 2 if number & 1 else 3
        elif kind == "execute-only":
            flags &= ~6
        elif kind == "user-leaf":
            flags |= 0x10
        elif kind == "supervisor-leaf":
            flags &= ~0x10
        elif kind == "misaligned-superpage":
            level = 1 + (number & 1)
            physical_ppn = (physical_ppn & ~((1 << (9 * level)) - 1)) | 1
        entries = {}
        errors = set()
        for walk_level in range(2, level - 1, -1):
            address = (tables[walk_level] << 12) + (
                ((va >> (12 + 9 * walk_level)) & 511) * 8)
            if walk_level == level:
                pte = (physical_ppn << 10) | flags
                if kind == "reserved-upper":
                    pte |= 1 << rng.randrange(54, 64)
            else:
                pte = (tables[walk_level - 1] << 10) | 1
                if number & 4:
                    pte |= 0x20
                if kind in ("nonleaf-u", "nonleaf-a", "nonleaf-d") and walk_level == 2:
                    pte |= {"nonleaf-u": 0x10, "nonleaf-a": 0x40, "nonleaf-d": 0x80}[kind]
            entries[address] = pte
            if (kind == "access-root" and walk_level == 2 or
                kind == "access-middle" and walk_level == 1 or
                    kind == "access-bottom" and walk_level == 0):
                errors.add(address)
        reads = []

        def read_pte(address):
            if address not in entries:
                raise AssertionError(f"scenario omitted PTE at {address:x}")
            reads.append((address, entries[address], int(address in errors)))
            if address in errors:
                raise OSError("deliberately injected physical read error")
            return entries[address]

        expected = sv39(va, access, privilege, (8 << 60) | root,
                        (int(sum_enable) << 18) | (int(mxr_enable) << 19), read_pte)
        yield {
            "class": kind, "va": va, "root": root, "asid": asid,
            "access": access, "priv": privilege, "sum": int(sum_enable),
            "mxr": int(mxr_enable), "expected_pa": expected.pa,
            "fault": {"": 0, "page": 1, "access": 2}[expected.fault],
            "level": max(0, expected.level), "global": int(expected.global_mapping),
            "reads": reads,
        }


def fault_programs():
    cases = []
    for privilege in (0, 1):
        for sum_enable in (False, True):
            for mxr_enable in (False, True):
                for user in (False, True):
                    for access in (1, 2):
                        cases.append({
                            "name": f"permission-p{privilege}-s{int(sum_enable)}-"
                                    f"m{int(mxr_enable)}-u{int(user)}-a{access}",
                            "privilege": privilege, "sum": sum_enable,
                            "mxr": mxr_enable, "flags": 0xCF | (0x10 if user else 0),
                            "access": access,
                        })
    for flags, label in ((0xC5, "write-only"), (0xCE, "invalid"),
                         (0x87, "accessed-clear"), (0x47, "dirty-clear"),
                         (0x49, "execute-only"), (0xC3, "read-only")):
        for access in (1, 2):
            for mxr_enable in (False, True):
                cases.append({"name": f"{label}-a{access}-mxr{int(mxr_enable)}",
                              "flags": flags, "access": access, "mxr": mxr_enable})
    for address in (0x80000040003000, 0xFFFFFFC040003000, 1 << 39,
                    0xFFFFFFFF40003000, 0x40003008):
        cases.append({"name": f"virtual-address-{address:016x}", "address": address})
    for fault in ("pte-reserved", "pte-superpage", "pte-nonleaf-u",
                  "pte-nonleaf-a", "pte-nonleaf-d", "physical-root",
                  "physical-middle", "physical-bottom", "leaf-access"):
        cases.append({"name": fault, "fault": fault})
    for delegated in (False, True):
        for specification in cases:
            spec = dict(specification, delegated=delegated)
            privilege = spec.get("privilege", 1)
            root = 0x10000000
            _, data = startup_program()
            instruction_flags = 0x4B | (0x10 if privilege == 0 else 0)
            data[0x2000] = instruction_flags
            data[0x4000] = ((0x10000000 >> 12) << 10) | spec.get("flags", 0xCF)
            address = spec.get("address", 0x40003000)
            root_line = ((((address >> 30) & 511) * 8) & ~31)
            for offset in range(0, 32, 8):
                data.setdefault(root_line + offset, 0)
            if address == 0xFFFFFFC040003000:
                # The upper-half mapping uses root index 257.
                data[257 * 8] = data[8]
                line = (257 * 8) & ~31
                for offset in range(0, 32, 8):
                    data.setdefault(line + offset, 0)
            fault = spec.get("fault")
            if fault == "pte-reserved":
                data[0x4000] |= 1 << 54
            elif fault == "pte-superpage":
                data[0x4000] |= 1 << 10
            elif fault in ("pte-nonleaf-u", "pte-nonleaf-a", "pte-nonleaf-d"):
                data[8] |= {"pte-nonleaf-u": 0x10, "pte-nonleaf-a": 0x40,
                            "pte-nonleaf-d": 0x80}[fault]
            elif fault == "physical-root":
                root = 0x12345000
            elif fault == "physical-middle":
                data[8] = (0x12345000 >> 12) << 10 | 1
            elif fault == "physical-bottom":
                data[0x4000] = (0x12345000 >> 12) << 10 | 1
            elif fault == "leaf-access":
                data[0x4000] = (0x20000000 >> 12) << 10 | 0xCF
            words = load_constant(1, (8 << 60) | (root >> 12))
            words.append((0x180 << 20) | (1 << 15) | (1 << 12) | 0x73)
            status = (privilege << 11) | (int(spec.get("sum", False)) << 18) | (
                int(spec.get("mxr", False)) << 19)
            words += load_constant(2, status)
            words.append((0x300 << 20) | (2 << 15) | (1 << 12) | 0x73)
            if delegated:
                words += load_constant(3, (1 << 12) | (1 << 13) | (1 << 15))
                words.append((0x302 << 20) | (3 << 15) | (1 << 12) | 0x73)
            words += load_constant(4, 0x100)
            words += [(0x341 << 20) | (4 << 15) | (1 << 12) | 0x73, 0x30200073]
            if len(words) >= 64:
                raise AssertionError("fault boot overlaps supervisor/user entry")
            words += [0x13] * (64 - len(words))
            words += load_constant(5, address)
            if spec.get("access", 1) == 1:
                words.append(i_type(0x03, 6, 3, 5, 0))
            else:
                words.append(s_type(3, 5, 5, 0))
            words.append(0x73)
            yield spec, words, data


def branch(rs1, rs2, funct3, offset):
    if offset & 1 or not -4096 <= offset < 4096:
        raise ValueError(f"invalid branch displacement {offset}")
    immediate = offset & 8191
    return (((immediate >> 12) & 1) << 31) | (((immediate >> 5) & 63) << 25) | (
        rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (((immediate >> 1) & 15) << 8) | (
        ((immediate >> 11) & 1) << 7) | 0x63


def context_program(rounds=20):
    words = [0x13] * 1088
    data = {}

    def pte(address, target, flags):
        for offset in range(0, 32, 8):
            data.setdefault((address & ~31) - 0x10000000 + offset, 0)
        data[address - 0x10000000] = ((target >> 12) << 10) | flags

    def emit(address, code):
        words[address // 4:address // 4 + len(code)] = code

    def csr(address, source, rd=0, operation=1):
        return (address << 20) | (source << 15) | (operation << 12) | (rd << 7) | 0x73

    root_a, root_b = 0x10000000, 0x10005000
    satp_a, satp_b = (8 << 60) | (1 << 44) | (root_a >> 12), (
        (8 << 60) | (2 << 44) | (root_b >> 12))
    for root, middle, leaf, physical in (
            (root_a, 0x10004000, 0x10007000, 0x10003000),
            (root_b, 0x10006000, 0x10009000, 0x10008000)):
        pte(root, 0x10001000, 1)
        pte(root + 8, middle, 1)
        pte(middle, leaf, 1)
        pte(leaf + 24, physical, 0xD7 if root == root_b else 0x97)
    pte(0x10001000, 0x10002000, 1)
    pte(0x10001400, 0x10000000, 0xC7)
    pte(0x10002000, 0, 0x4B)
    pte(0x10002008, 0x1000, 0x5B)
    for physical, initial in ((0x10003000, 0xA000), (0x10008000, 0xB000)):
        for offset in range(0, 32, 8):
            data[physical - 0x10000000 + offset] = initial if offset == 0 else 0
    boot = load_constant(1, satp_a) + [csr(0x180, 1)]
    boot += load_constant(2, (1 << 8) | (1 << 13)) + [csr(0x302, 2)]
    boot += load_constant(3, 1 << 11) + [csr(0x300, 3)]
    boot += load_constant(4, 0x100) + [csr(0x341, 4), 0x30200073]
    if len(boot) > 64:
        raise AssertionError("M-mode boot overlaps S entry")
    emit(0, boot)
    supervisor = load_constant(10, 0) + load_constant(11, rounds)
    supervisor += load_constant(12, satp_a) + load_constant(13, satp_b)
    supervisor += load_constant(14, 0x1000) + load_constant(15, 0x200)
    supervisor += [csr(0x105, 15), csr(0x141, 14), csr(0x100, 0), 0x10200073]
    if len(supervisor) > 64:
        raise AssertionError("supervisor entry overlaps trap handler")
    emit(0x100, supervisor)
    handler = [csr(0x142, 0, 20, 2), csr(0x141, 0, 21, 2),
               csr(0x143, 0, 22, 2), i_type(0x13, 23, 0, 0, 13)]
    handler += [branch(20, 23, 0, 0x300 - (0x200 + len(handler) * 4))]
    handler += [i_type(0x13, 10, 0, 10, 1), csr(0x180, 0, 15, 2)]
    # Alternate address spaces while preserving a single user VA.
    handler += [branch(15, 12, 1, 12), csr(0x180, 13),
                0x0080006F, csr(0x180, 12), 0x12000073, csr(0x141, 14)]
    handler += [branch(10, 11, 5, 8), 0x10200073, 0x73]
    emit(0x200, handler)
    repair = load_constant(23, 0x10007018)
    repair += [i_type(0x03, 24, 3, 23, 0), i_type(0x13, 24, 6, 24, 0x40),
               s_type(3, 23, 24, 0), 0x12000073, 0x10200073]
    emit(0x300, repair)
    emit(0x1000, [0x400032B7, i_type(0x03, 6, 3, 5, 0),
                  i_type(0x13, 6, 0, 6, 1), s_type(3, 5, 6, 0), 0x73])
    return words, data


def isa_program(seed=17):
    rng = random.Random(seed)
    words = [0x100000B7]
    labels = {}

    def add(instruction, label):
        labels[4 * len(words)] = label
        words.append(instruction)

    pairs = [(0, 0), (1, 0), (MASK64, 1), (1 << 63, MASK64),
             (0xFFFFFFFF80000000, MASK64),
             (rng.getrandbits(64), rng.getrandbits(64)),
             (rng.getrandbits(64), rng.getrandbits(64))]
    for a, b in pairs:
        words += load_constant(2, a) + load_constant(3, b)
        for funct3 in range(8):
            add(r_type(0x33, 4, funct3, 2, 3), f"rv64i-reg-{funct3}")
            add(r_type(0x33, 4, funct3, 2, 3, 1), f"rv64m-{funct3}")
        for funct3 in (0, 5):
            add(r_type(0x33, 4, funct3, 2, 3, 0x20), f"rv64i-alt-{funct3}")
        for funct3 in (0, 1, 5):
            add(r_type(0x3B, 4, funct3, 2, 3), f"rv64i-word-{funct3}")
        for funct3 in (0, 5):
            add(r_type(0x3B, 4, funct3, 2, 3, 0x20), f"rv64i-word-alt-{funct3}")
        for funct3 in (0, 4, 5, 6, 7):
            add(r_type(0x3B, 4, funct3, 2, 3, 1), f"rv64m-word-{funct3}")
        for funct3 in (0, 2, 3, 4, 6, 7):
            add(i_type(0x13, 4, funct3, 2, -17), f"rv64i-immediate-{funct3}")
        for opcode, maximum in ((0x13, 63), (0x1B, 31)):
            for shift in (0, 1, maximum):
                for funct3, alternate in ((1, 0), (5, 0), (5, 0x400)):
                    add(i_type(opcode, 4, funct3, 2, shift | alternate),
                        f"shift-{opcode:x}-{funct3}-{alternate:x}")
        add(i_type(0x1B, 4, 0, 2, -17), "addiw")
    words += load_constant(2, 0xFEDCBA9876543210)
    for offset in range(0, 64, 8):
        add(s_type(3, 1, 2, offset), "initialize-memory")
    for funct3 in range(4):
        size = 1 << funct3
        for offset in range(0, 8, size):
            add(s_type(funct3, 1, 2, offset), f"store-{size}")
            add(i_type(0x03, 4, funct3, 1, offset), f"load-signed-{size}")
            if funct3 < 3:
                add(i_type(0x03, 4, funct3 + 4, 1, offset), f"load-unsigned-{size}")
    for a, b in ((MASK64, 1), (1, MASK64), (7, 7)):
        words += load_constant(2, a) + load_constant(3, b)
        for funct3 in (0, 1, 4, 5, 6, 7):
            add(branch(2, 3, funct3, 8), f"branch-{funct3}")
            add(i_type(0x13, 4, 0, 4, 1), "branch-fallthrough")
    add(0x00800CEF, "jal")
    add(i_type(0x13, 4, 0, 4, -1), "jump-skipped")
    add(0x00000D17, "auipc")
    add(0x00000D97, "jalr-auipc")
    add(i_type(0x13, 27, 0, 27, 13), "jalr-target")
    add(i_type(0x67, 25, 0, 27, 0), "jalr")
    words += load_constant(2, 0x800000017FFFFFFF)
    for size in (2, 3):
        for offset in ((0, 4) if size == 2 else (0,)):
            words += [i_type(0x13, 5, 0, 1, offset)]
            for operation in (1, 0, 4, 12, 8, 16, 20, 24, 28):
                add((operation << 27) | (2 << 20) | (5 << 15) | (
                    size << 12) | (6 << 7) | 0x2F, f"amo-{operation}-{size}")
            lr = (2 << 27) | (5 << 15) | (size << 12) | (6 << 7) | 0x2F
            sc = (3 << 27) | (2 << 20) | (5 << 15) | (size << 12) | (7 << 7) | 0x2F
            add(lr, f"lr-{size}")
            add(sc, f"sc-success-{size}")
            add(sc, f"sc-failure-{size}")
            add(lr, f"lr-interference-{size}")
            add(s_type(size, 5, 2, 0), "interfering-cpu-store")
            add(sc, f"sc-interference-{size}")
    for operation in (1, 2, 3, 5, 6, 7):
        add((0x340 << 20) | (2 << 15) | (operation << 12) | (4 << 7) | 0x73,
            f"csr-operation-{operation}")
    add(0x0000000F, "fence")
    add(0x0000100F, "fence-i")
    add(0x73, "terminal-ecall")
    if len(words) > 1024:
        raise AssertionError(f"ISA regression no longer fits smallest system RAM: {len(words)}")
    return words, labels


def shootdown_program():
    words, data = startup_program()
    data[0x4000] = (0x10005000 >> 12) << 10 | 1
    for offset in range(0, 32, 8):
        data[0x5000 + offset] = 0
        data[0x6000 + offset] = 0
        data[0x1400 + offset] = 0
    data[0x5018] = (0x10003000 >> 12) << 10 | 0xC7
    data[0x6000] = 0x55AA55AA55667788
    data[0x1400] = (0x10000000 >> 12) << 10 | 0xC7
    code = [0x400032B7, i_type(0x03, 6, 3, 5, 0)]
    code += load_constant(7, 0x10005018)
    code += load_constant(8, (0x10006000 >> 12) << 10 | 0xC7)
    code += [s_type(3, 7, 8, 0), 0x12000073,
             i_type(0x03, 9, 3, 5, 0), 0x73]
    words = words[:64] + code
    return words, data
