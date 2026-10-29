"""Real CPU programs for per-row directed coverage, independent of RTL internals."""

import itertools
import random

from oracle import MASK64, i_type, load_constant, s_type
from scenarios import isa_program


ROOT = 0x80080000
MIDDLE = 0x80081000
LEAF = 0x80082000
DATA = 0x80090000
ENTRY = 0x80020000
VA = 0x40003000


def csr(address, source, rd=0, operation=1):
    return (address << 20) | (source << 15) | (operation << 12) | (rd << 7) | 0x73


def atomic(operation, size=3, destination=6):
    return ((operation << 27) | ((0 if operation == 2 else 9) << 20) |
            (5 << 15) | (size << 12) | (destination << 7) | 0x2F)


class Program:
    def __init__(self, limit=ROOT):
        self.code = []
        self.image = {}
        self.limit = limit

    @property
    def pc(self):
        return ENTRY + 4 * len(self.code)

    def emit(self, *words):
        self.code.extend(words)

    def constant(self, register, value):
        self.code.extend(load_constant(register, value))

    def write(self, address, value):
        self.constant(7, address)
        self.constant(8, value)
        self.emit(s_type(3, 7, 8, 0))

    def put(self, address, value, size=8):
        for byte in range(size):
            self.image[address + byte] = (value >> (8 * byte)) & 255

    def resume_patch(self):
        patch = len(self.code)
        self.emit(*([0x13] * 11), csr(0x340, 10))
        return patch

    def resume_at(self, patch, address):
        recipe = load_constant(10, address)
        if len(recipe) > 11:
            raise AssertionError("resume recipe exceeds fixed reservation")
        self.code[patch:patch + 11] = recipe + [0x13] * (11 - len(recipe))

    def finish(self):
        # A real S-mode ECALL is the common public terminal condition.
        self.constant(1, 0)
        self.emit(csr(0x180, 1))
        self.constant(1, 1 << 11)
        self.emit(csr(0x300, 1))
        # A fixed-width recipe keeps the target independent of chunk boundaries.
        target = self.pc + 13 * 4
        recipe = load_constant(1, target)
        self.emit(*recipe, *([0x13] * (11 - len(recipe))), csr(0x341, 1), 0x30200073, 0x73)
        if self.pc >= self.limit:
            raise AssertionError("directed program exceeds its executable region")
        for index, word in enumerate(self.code):
            self.put(ENTRY + index * 4, word, 4)
        boot = load_constant(1, 0x200) + [csr(0x305, 1)]
        boot += load_constant(1, ENTRY) + [i_type(0x67, 0, 0, 1, 0)]
        boot += [0x13] * (256 - len(boot))
        handler = [csr(0x342, 0, 20, 2), csr(0x341, 0, 21, 2),
                   csr(0x343, 0, 22, 2)]
        handler += load_constant(23, 1 << 17) + [csr(0x300, 23, operation=3)]
        handler += load_constant(23, 3 << 11) + [csr(0x300, 23, operation=2),
                                                csr(0x340, 0, 23, 2),
                                                csr(0x341, 23), 0x30200073]
        boot[128:128 + len(handler)] = handler
        return boot, self.image


def fault_workload(seed):
    """Data faults use real MPRV; fetch permissions use real MRET into S/U."""
    rng = random.Random(seed)
    program = Program()
    cases = []
    specifications = []
    for privilege, sum_bit, mxr_bit, user, access in itertools.product(
            (0, 1, 3), (0, 1), (0, 1), (0, 1), (1, 2, 3)):
        specifications.append(dict(
            name="permission", privilege=privilege, sum=sum_bit, mxr=mxr_bit,
            flags=0xCF | (user << 4), access=access))
    for privilege, sum_bit, mxr_bit, user in itertools.product(
            (0, 1), (0, 1), (0, 1), (0, 1)):
        specifications.append(dict(
            name="fetch-permission", privilege=privilege, sum=sum_bit, mxr=mxr_bit,
            flags=0xCF | (user << 4), access=0))
    for flags, name in ((0xCE, "invalid-v"), (0xC5, "write-only"),
                        (0x87, "accessed-clear-repair"), (0x47, "dirty-clear-repair"),
                        (0x49, "execute-only"), (0xC3, "read-only")):
        for access in (1, 2, 3):
            specifications.append(dict(name=name, flags=flags, access=access))
    for name in ("reserved-upper", "nonleaf-u", "nonleaf-a", "nonleaf-d",
                 "root-read-error", "middle-read-error", "bottom-read-error",
                 "superpage-misalignment", "noncanonical", "root-high-rejection"):
        for access in (1, 2, 3):
            specifications.append(dict(name=name, access=access))
    for access in (1, 2, 3):
        for offset in (0, 0xFF8):
            specifications.append(dict(name="page-edges", access=access, offset=offset))
    specifications.append(dict(name="failed-sc-permission", flags=0xC3, access=2, sc=True))
    program.put(DATA, rng.getrandbits(64))
    program.put(DATA + 0xFF8, rng.getrandbits(64))
    # A mapped fetch ends with a precise breakpoint rather than the suite's terminal ECALL.
    program.put(DATA, 0x00100073, 4)
    for number, specification in enumerate(specifications):
        spec = dict(privilege=1, sum=0, mxr=0, flags=0xCF)
        spec.update(specification)
        name, access = spec["name"], spec["access"]
        address = (DATA if spec["privilege"] == 3 else VA) + spec.get("offset", 0)
        root, middle, leaf = ROOT, MIDDLE, LEAF
        root_pte = (middle >> 12) << 10 | 1
        middle_pte = (leaf >> 12) << 10 | 1
        leaf_pte = (DATA >> 12) << 10 | spec["flags"]
        if name == "reserved-upper":
            leaf_pte |= 1 << 54
        elif name.startswith("nonleaf-"):
            root_pte |= {"nonleaf-u": 0x10, "nonleaf-a": 0x40, "nonleaf-d": 0x80}[name]
        elif name == "root-read-error":
            root = 0x20000000
        elif name == "middle-read-error":
            root_pte = (0x20000000 >> 12) << 10 | 1
        elif name == "bottom-read-error":
            middle_pte = (0x20000000 >> 12) << 10 | 1
        elif name == "root-high-rejection":
            root = 1 << 55
        elif name == "superpage-misalignment":
            middle_pte = (DATA >> 12) << 10 | 0xCF
        elif name == "noncanonical":
            address |= 1 << 39
        program.write(ROOT + 8, root_pte)
        program.write(MIDDLE, middle_pte)
        program.write(LEAF + 24, leaf_pte)
        # Also clears any previous reservation before failed-SC permission testing.
        program.write(DATA, 0x00100073 if access == 0 else rng.getrandbits(64))
        program.constant(1, (8 << 60) | ((number & 65535) << 44) | (root >> 12))
        program.emit(csr(0x180, 1))
        program.constant(5, address)
        program.constant(6, 0xCAFE0000 + number)
        program.constant(9, rng.getrandbits(64))
        status = ((spec["privilege"] << 11) | (spec["sum"] << 18) |
                  (spec["mxr"] << 19) | ((access != 0) << 17))
        program.constant(1, status)
        # Reserve eleven instructions for the resume address recipe.
        resume_patch = len(program.code)
        program.emit(*([0x13] * 11), csr(0x340, 10), csr(0x300, 1))
        if access == 0:
            program.emit(csr(0x341, 5), 0x30200073)
            operation_pc = address
        else:
            operation_pc = program.pc
            program.emit(i_type(0x03, 6, 3, 5, 0) if access == 1 else
                         atomic(3) if spec.get("sc") else
                         s_type(3, 5, 9, 0) if access == 2 else atomic(0))
        resume_pc = program.pc
        recipe = load_constant(10, resume_pc)
        program.code[resume_patch:resume_patch + 11] = recipe + [0x13] * (11 - len(recipe))
        program.emit(csr(0x300, 0))
        # These public retirements detect register/memory effects from a faulting instruction.
        program.emit(i_type(0x13, 11, 0, 6, 0))
        program.constant(12, DATA + spec.get("offset", 0))
        program.emit(i_type(0x03, 13, 3, 12, 0))
        witness_pc = program.pc - 4
        case = dict(spec, number=number, operation_pc=operation_pc, witness_pc=witness_pc,
                    resume_pc=resume_pc)
        if name in ("accessed-clear-repair", "dirty-clear-repair"):
            # Repair the actual dirty cached PTE, fence, and retry the same instruction.
            program.write(LEAF + 24, leaf_pte | 0xC0)
            program.emit(0x12000073)
            program.constant(1, status)
            program.emit(csr(0x300, 1))
            case["repair_pc"] = program.pc
            program.emit(i_type(0x03, 6, 3, 5, 0) if access == 1 else
                         s_type(3, 5, 9, 0) if access == 2 else atomic(0))
            program.emit(csr(0x300, 0))
        cases.append(case)
    # Sequential fetch falls into an invalid page; the taken JAL must redirect to
    # another mapped page without committing the wrong-path instruction fault.
    program.write(ROOT + 8, (MIDDLE >> 12) << 10 | 1)
    program.write(MIDDLE, (LEAF >> 12) << 10 | 1)
    program.write(LEAF + 32, ((DATA + 0x2000) >> 12) << 10 | 0xDB)
    program.write(LEAF + 40, 0)
    program.write(LEAF + 48, ((DATA + 0x3000) >> 12) << 10 | 0xDB)
    displacement = 0x1004
    jump = (((displacement >> 20) & 1) << 31 |
            ((displacement >> 1) & 1023) << 21 |
            ((displacement >> 11) & 1) << 20 |
            ((displacement >> 12) & 255) << 12 | 0x6F)
    program.put(DATA + 0x2FFC, jump, 4)
    program.put(DATA + 0x3000, 0x00100073, 4)
    program.constant(1, (8 << 60) | (ROOT >> 12))
    program.emit(csr(0x180, 1))
    program.constant(1, 0)
    program.emit(csr(0x300, 1))
    program.constant(5, 0x40004FFC)
    patch = program.resume_patch()
    program.emit(csr(0x341, 5), 0x30200073)
    program.resume_at(patch, program.pc)
    witness_pc = program.pc
    program.emit(csr(0x300, 0))
    cases.append(dict(number=len(cases), name="wrong-path-fault-suppression",
                      access=0, operation_pc=0x40004FFC, target_pc=0x40006000,
                      witness_pc=witness_pc))
    words, image = program.finish()
    return words, image, {"scenario": "faults", "cases": cases}


def isa_workload(seed):
    program = Program()
    instructions, labels = isa_program(seed)
    program.emit(*instructions[:-1])
    labels = {ENTRY + address: name for address, name in labels.items()
              if name != "terminal-ecall"}
    # Explicit adjacent dependencies, not just an instruction-class histogram.
    program.constant(5, DATA)
    program.constant(9, 0x1234567887654321)
    for instruction, label in (
            (s_type(3, 5, 9, 0), "hazard-store"),
            (i_type(0x03, 6, 3, 5, 0), "hazard-load"),
            (i_type(0x13, 7, 0, 6, 17), "hazard-load-use"),
            (i_type(0x13, 8, 0, 7, -9), "hazard-forward"),
            (s_type(3, 5, 8, 8), "hazard-store-forward"),
            (i_type(0x03, 9, 3, 5, 8), "hazard-witness")):
        labels[program.pc] = label
        program.emit(instruction)
    cases = []
    operations = []
    for width in (1, 2, 3):
        operations.extend((
            (i_type(0x03, 6, width, 5, 0), (1 << width) - 1, 4, "misalignment"),
            (s_type(width, 5, 9, 0), (1 << width) - 1, 6, "misalignment")))
    for width in (2, 3):
        for operation in (2, 3, 0):
            operations.append((atomic(operation, width), 1, 4 if operation == 2 else 6,
                               "misalignment"))
    operations.append((i_type(0x67, 6, 0, 5, 0), 2, 0, "misalignment"))
    for instruction, offset, cause, name in operations:
        program.constant(5, DATA + offset)
        patch = program.resume_patch()
        operation_pc = program.pc
        program.emit(instruction)
        program.resume_at(patch, program.pc)
        witness_pc = program.pc
        program.emit(i_type(0x13, 11, 0, 6, 0))
        program.constant(12, DATA)
        program.emit(i_type(0x03, 13, 3, 12, 0))
        cases.append(dict(number=len(cases), name=name, operation_pc=operation_pc,
                          witness_pc=program.pc - 4, expected_cause=cause))
    for privilege, status_bits, instruction in (
            (0, 0, csr(0x180, 0, 6, 2)), (0, 0, 0x12000073),
            (0, 0, csr(0x300, 0, 6, 2)), (1, 0, csr(0x300, 0, 6, 2)),
            (1, 1 << 20, csr(0x180, 0, 6, 2)),
            (1, 1 << 20, csr(0x180, 9)), (1, 1 << 20, 0x12000073),
            (1, 1 << 21, 0x10500073), (1, 1 << 22, 0x10200073)):
        target = DATA + 0x1000 + len(cases) * 4
        program.put(target, instruction, 4)
        program.constant(1, (privilege << 11) | status_bits)
        program.emit(csr(0x300, 1))
        program.constant(5, target)
        patch = program.resume_patch()
        program.emit(csr(0x341, 5), 0x30200073)
        program.resume_at(patch, program.pc)
        witness_pc = program.pc
        program.emit(csr(0x300, 0))
        cases.append(dict(number=len(cases), name="csr-permissions", operation_pc=target,
                          witness_pc=witness_pc, expected_cause=2))
    # satp WARL writes must preserve the entire old value on unsupported MODE.
    program.constant(1, 0x1234 << 44)
    program.emit(csr(0x180, 1))
    program.constant(1, (9 << 60) | 0xABCDE)
    program.emit(csr(0x180, 1))
    labels[program.pc] = "satp-warl"
    program.emit(csr(0x180, 0, 6, 2))
    words, image = program.finish()
    return words, image, {"scenario": "isa", "cases": cases,
                          "labels": {str(pc): name for pc, name in labels.items()}}


def fence_workload(seed, capacity, only_satp=False):
    """Distinguish required invalidation from selective/global cached survivors."""
    rng = random.Random(seed)
    program = Program()
    cases = []
    old_value, new_value = rng.getrandbits(64), rng.getrandbits(64)
    program.put(DATA, old_value)
    program.put(DATA + 0x10000, new_value)

    def context(asid, inherited_global=False, flags=0xCF):
        program.write(ROOT + 8, (MIDDLE >> 12) << 10 | 1 | (0x20 if inherited_global else 0))
        program.write(MIDDLE, (LEAF >> 12) << 10 | 1)
        program.write(LEAF + 24, (DATA >> 12) << 10 | flags)
        program.constant(14, (8 << 60) | (asid << 44) | (ROOT >> 12))
        program.emit(csr(0x180, 14), 0x12000073)
        program.constant(5, VA)

    def load(status=(1 << 17) | (1 << 11), access=1):
        program.constant(1, status)
        program.emit(csr(0x300, 1))
        patch = program.resume_patch()
        pc = program.pc
        program.emit(i_type(0x03, 6, 3, 5, 0) if access == 1 else
                     s_type(3, 5, 9, 0) if access == 2 else atomic(0))
        program.resume_at(patch, program.pc)
        program.emit(csr(0x300, 0))
        return pc

    def observation(name, bins, required, **request):
        pc = load(**request)
        witness = program.pc
        program.emit(i_type(0x13, 11, 0, 6, 0))
        cases.append(dict(number=len(cases), name=name, operation_pc=pc,
                          witness_pc=witness, required_result=required, bins=bins))

    forms = (
            ("fence-all-all", None, None, 7, False, False),
            ("fence-va-all", VA + 16, None, 7, False, False),
            ("fence-all-asid", None, 7, 7, False, False),
            ("fence-va-asid", VA + 16, 7, 7, False, False),
            ("fence-zero-register-operand", 0, None, 7, False, False),
            ("fence-zero-register-operand", None, 0, 7, False, False),
            ("fence-va-asid", VA, 0, 0, False, False),
            ("fence-global-survivor", None, 7, 7, True, False),
            ("fence-inherited-global", VA, 7, 7, False, True),
            ("fence-selective-survivor", VA + 0x1000, None, 7, False, False))
    for form, va_operand, asid_operand, asid, global_leaf, inherited in (
            () if only_satp else forms):
        context(asid, inherited, 0xEF if global_leaf else 0xCF)
        load()
        program.write(LEAF + 24, ((DATA + 0x10000) >> 12) << 10 |
                      (0xEF if global_leaf else 0xCF))
        rs1, rs2 = (0 if va_operand is None else 15), (0 if asid_operand is None else 16)
        if rs1:
            program.constant(rs1, va_operand)
        if rs2:
            program.constant(rs2, asid_operand)
        program.emit(0x12000073 | (rs1 << 15) | (rs2 << 20))
        invalidates = ((va_operand is None or VA <= va_operand < VA + 0x1000) and
                       (asid_operand is None or not (global_leaf or inherited) and asid_operand == asid))
        observation(form, [form], new_value if invalidates else old_value)
        program.emit(0x12000073)
        observation("post-full-fence-remap", ["dirty-pte-remap", "fence-no-stale-refill"], new_value)

    # A same-value satp write is still a write under the frozen conservative
    # invalidation contract; it must not be mistaken for "no context operation".
    context(11)
    load()
    program.write(LEAF + 24, ((DATA + 0x10000) >> 12) << 10 | 0xCF)
    program.emit(csr(0x180, 14))
    observation("same-value-satp-write", ["satp-drain-invalidation"], new_value)
    if not only_satp:
        # All architectural CSR write forms must invalidate, even when the
        # operation leaves the CSR unchanged. Read-only forms must not fence.
        for operation, source, value, invalidates in (
                (1, 14, None, True), (2, 15, 0, True), (3, 15, 0, True),
                (5, 0, None, True), (6, 1, None, True), (7, 1, None, True),
                (2, 0, None, False), (3, 0, None, False),
                (6, 0, None, False), (7, 0, None, False),
                (1, 15, (9 << 60) | 0xABCDE, True)):
            context(11)
            load()
            program.write(LEAF + 24, ((DATA + 0x10000) >> 12) << 10 | 0xCF)
            if value is not None:
                program.constant(source, value)
            program.emit(csr(0x180, source, 19, operation))
            # Immediate write/set/clear forms change MODE to Bare, so restore
            # the Sv39 context before the translated observation.
            if operation in (5, 6, 7) and source:
                program.emit(csr(0x180, 14))
            elif operation == 5:
                program.emit(csr(0x180, 14))
            observation("satp-csr-write-form" if invalidates else "satp-read-only-form",
                        ["satp-drain-invalidation"],
                        new_value if invalidates else old_value)

        # SFENCE VA matching covers the entire 2 MiB/1 GiB cached leaf, not
        # merely the 4 KiB containing the original request.
        for level in (1, 2):
            context(7)
            pte_address = MIDDLE if level == 1 else ROOT + 8
            program.write(pte_address, (0x80000000 >> 12) << 10 | 0xCF)
            program.emit(0x12000073)
            mapped_address = 0x80000000 | (VA & ((1 << (12 + 9 * level)) - 1))
            value = rng.getrandbits(64)
            program.write(mapped_address, value)
            observation("superpage-prime", [], value)
            program.write(pte_address, 0)
            program.constant(15, VA + 0x2000)
            program.emit(0x12000073 | (15 << 15))
            observation("superpage-span-invalidation", ["fence-va-all"], "fault")

        # Permission decisions must use current context even when a leaf was
        # cached under a less restrictive context.
        for flags, allowed, denied, access in (
                (0xDF, (1 << 18) | (1 << 11), 1 << 11, 1),
                (0xDF, 0, 1 << 11, 1),
                (0xC9, (1 << 19) | (1 << 11), 1 << 11, 1),
                (0xC3, 1 << 11, 1 << 11, 3),
                (0x47, 1 << 11, 1 << 11, 2)):
            context(7, flags=flags)
            observation("permission-hit-prime", [], old_value, status=(1 << 17) | allowed)
            observation("permission-hit-denial", ["permission-hit-reevaluation"], "fault",
                        status=(1 << 17) | denied, access=access)

        # Distinct stale physical values make incorrect victim selection an
        # architectural mismatch rather than an unobservable cache statistic.
        context(7)
        old_pages, new_pages = [], []
        for page in range(capacity + 1):
            physical = 0x800C0000 + page * 0x1000
            replacement = 0x800D8000 + page * 0x1000
            before, after = rng.getrandbits(64), rng.getrandbits(64)
            old_pages.append(before)
            new_pages.append(after)
            program.put(physical, before)
            program.put(replacement, after)
            program.write(LEAF + (3 + page) * 8, (physical >> 12) << 10 | 0xCF)
        program.emit(0x12000073)
        for page in range(capacity):
            program.constant(5, VA + page * 0x1000)
            observation("replacement-prime", [], old_pages[page])
        for page in range(capacity):
            replacement = 0x800D8000 + page * 0x1000
            program.write(LEAF + (3 + page) * 8, (replacement >> 12) << 10 | 0xCF)
        program.constant(5, VA + capacity * 0x1000)
        observation("replacement-overflow", [], old_pages[capacity])
        for page in range(1, capacity):
            program.constant(5, VA + page * 0x1000)
            observation("round-robin-survivor", ["tlb-hit-miss-replacement"], old_pages[page])
        program.constant(5, VA)
        observation("round-robin-victim", ["tlb-hit-miss-replacement"], new_pages[0])

        # Refill a selective invalidation hole while all other entries remain
        # valid, then verify every unselected mapping still retains its PTE.
        program.emit(0x12000073)
        for page in range(capacity):
            program.constant(5, VA + page * 0x1000)
            observation("first-invalid-prime", [], new_pages[page])
        hole = capacity // 2
        program.constant(15, VA + hole * 0x1000)
        program.emit(0x12000073 | (15 << 15))
        program.constant(5, VA + capacity * 0x1000)
        observation("first-invalid-refill", [], old_pages[capacity])
        for page in range(capacity):
            program.write(LEAF + (3 + page) * 8, 0)
        for page in range(capacity):
            if page != hole:
                program.constant(5, VA + page * 0x1000)
                observation("first-invalid-survivor", ["tlb-first-invalid-round-robin"],
                            new_pages[page])
        program.constant(5, VA + capacity * 0x1000)
        observation("first-invalid-refill-survived", ["tlb-first-invalid-round-robin"],
                    old_pages[capacity])
        context(19, flags=0xD7)
        program.write(LEAF + 7 * 8, (0x80004000 >> 12) << 10 | 0xDB)
        program.write(LEAF + 8 * 8, (0x80005000 >> 12) << 10 | 0xDB)
        program.put(0x80004FFC, i_type(0x03, 6, 3, 5, 0), 4)
        program.put(0x80005000, i_type(0x13, 11, 0, 6, 0), 4)
        program.put(0x80005004, 0x73, 4)
        program.emit(0x0000000F)
        # Evict all three relevant PTE lines without altering their contents.
        # The 2048-byte offset conflicts for every frozen direct-mapped cache.
        for offset in (0, 32, 64):
            program.constant(7, LEAF + 2048 + offset)
            program.emit(i_type(0x03, 8, 3, 7, 0))
        program.constant(5, VA)
        patch = program.resume_patch()
        program.constant(1, 0)
        program.emit(csr(0x300, 1))
        program.constant(1, 0x40007FFC)
        program.emit(csr(0x341, 1), 0x30200073)
        program.resume_at(patch, program.pc)
        cases.append(dict(number=len(cases), name="overlap-page-boundary-load",
                          operation_pc=0x40007FFC, witness_pc=0x40008000,
                          required_result=old_value, bins=[]))
    words, image = program.finish()
    return words, image, {"scenario": "satp" if only_satp else "fences", "cases": cases,
                          "dtlb_entries": capacity, "old_value": old_value,
                          "new_value": new_value, "old_pa": DATA, "new_pa": DATA + 0x10000,
                          "overlap_pte": None if only_satp else LEAF + 8 * 8}
