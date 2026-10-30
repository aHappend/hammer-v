"""CPU-executed peripheral recipes, compared independently at public retirement."""

from oracle import ArchitecturalTrap, i_type, s_type, load_constant
from peripherals import character_cycles, plic_vectors, uart_vectors
from scenarios import branch
from system_directed import Program, csr


MAILBOX = 0x4000FFF0


def peripheral_workload(unit):
    vectors = plic_vectors() if unit == "plic" else uart_vectors()
    program = Program(limit=0x800F0000)
    operations, interrupt_reads, script, skipped = {}, {}, [], []
    external_interrupt = None
    program.constant(27, MAILBOX)

    def bus(address, write=False, value=0, size=0, expected=0, error=False):
        program.constant(5, address)
        if write:
            program.constant(6, value)
        patch = program.resume_patch() if error else None
        pc = program.pc
        program.emit(s_type(size, 5, 6, 0) if write else i_type(0x03, 6, size + 4 if size < 3 else 3, 5, 0))
        if patch is not None:
            program.resume_at(patch, program.pc)
        witness = program.pc
        program.emit(i_type(0x13, 11, 0, 6, 0))
        operations[pc] = dict(address=address, size=size, write=write, value=value,
                              expected=expected, error=error, witness_pc=witness)

    def signal(commands):
        identity = 1 + sum(line.startswith("C ") for line in script)
        script.extend([f"C {identity}", *commands, "E"])
        program.constant(26, identity)
        program.emit(s_type(3, 27, 26, 0))
        loop = program.pc
        program.emit(i_type(0x03, 25, 3, 27, 8),
                     branch(25, 26, 1, loop - (program.pc + 4)))

    def irq(expected):
        interrupt_reads[program.pc] = expected
        program.emit(csr(0x344, 0, 6, 2))

    lines = iter(vectors.lines)
    pending = None
    while True:
        line = pending if pending is not None else next(lines, None)
        pending = None
        if line is None:
            break
        fields = line.split()
        if fields[0] == "B":
            _, _, write, address, size, data, mask, expected, error, _, blocked = fields
            address, size = int(address, 16), int(size)
            mask = int(mask, 16)
            natural_mask = ((1 << (1 << size)) - 1) << (address & 7)
            if mask != natural_mask or address & ((1 << size) - 1):
                skipped.append({"command": line, "reason": "not a naturally aligned CPU access"})
                continue
            bus(address, bool(int(write)), int(data, 16) >> (8 * (address & 7)), size,
                int(expected, 16) >> (8 * (address & 7)), bool(int(error)))
            operations[max(operations)]["minimum_blocked"] = int(blocked)
        elif fields[0] == "S":
            levels = int(fields[1], 16)
            # Source 1 is the real UART THRE interrupt at the top, not an
            # invented external source pin.
            bus(0x10010001, True, 2 if levels & 1 else 0)
            signal([f"S {levels >> 1:x}"])
        elif fields[0] == "Q":
            if unit == "plic":
                expected = int(fields[2])
                irq((0x800 if expected & 2 else 0) | (0x200 if expected & 4 else 0))
        elif fields[0] == "U":
            commands = [line]
            for candidate in lines:
                if not candidate.startswith("U "):
                    pending = candidate
                    break
                commands.append(candidate)
            signal(commands)
        elif fields[0] in ("W", "M"):
            signal([line])
        else:
            raise AssertionError(f"unknown peripheral recipe {line}")

    if unit == "uart":
        # Exact console bytes are emitted by real CPU stores, with no external
        # serial transmitter standing in for the processor.
        bus(0x10010003, True, 0x83)
        bus(0x10010000, True, 27)
        bus(0x10010001, True, 0)
        bus(0x10010003, True, 3)
        bus(0x10010002, True, 7)
        console = b"HAMMER-V3 supervisor console\r\n"
        marker = len(vectors.frames) + len(vectors.streams)
        signal([f"M {marker}"])
        for value in console:
            bus(0x10010000, True, value)
        signal([f"W {len(console) * character_cycles(3, 27) + 100}"])
        bus(0x10010005, expected=0x60)
        vectors.streams.append(dict(marker=marker, values=list(console), lcr=3, divisor=27))
        # UART -> PLIC ID1 -> architectural MEIP, claim and completion.
        bus(0x0C000004, True, 3, 2)
        bus(0x0C002000, True, 2, 2)
        bus(0x10010001, True, 2)
        irq(0x800)
        bus(0x0C200004, size=2, expected=1)
        bus(0x10010001, True, 0)
        bus(0x0C200004, True, 1, 2)
        irq(0)
        # A real delegated external interrupt executes S-mode claim/complete
        # software before returning to the interrupted instruction boundary.
        skip_handler = len(program.code)
        program.emit(0x13)
        handler = program.pc
        program.emit(csr(0x142, 0, 20, 2), csr(0x141, 0, 21, 2), csr(0x143, 0, 22, 2))
        bus(0x0C201004, size=2, expected=1)
        bus(0x10010001, True, 0)
        bus(0x0C201004, True, 1, 2)
        program.emit(csr(0x104, 0), 0x10200073)
        program.code[skip_handler] = branch(0, 0, 0, program.pc - (handler - 4))
        bus(0x0C002000, True, 0, 2)
        bus(0x0C002080, True, 2, 2)
        program.constant(1, handler)
        program.emit(csr(0x105, 1))
        program.constant(1, 1 << 9)
        program.emit(csr(0x303, 1), csr(0x304, 1))
        bus(0x10010001, True, 2)
        program.constant(1, (1 << 11) | 2)
        program.emit(csr(0x300, 1))
        target = program.pc + 13 * 4
        recipe = load_constant(1, target)
        program.emit(*recipe, *([0x13] * (11 - len(recipe))), csr(0x341, 1), 0x30200073)
        external_interrupt = dict(pc=program.pc, cause=(1 << 63) | 9, handler=handler)
        # S-mode software reaches the real terminal ECALL after SRET.
        program.emit(0x73)
    words, image = program.finish()
    return words, image, {
        "scenario": unit, "cases": [], "operations": operations,
        "final_memory_addresses": sorted(program.final_addresses),
        "interrupt_reads": interrupt_reads, "script": script,
        "frames": vectors.frames, "streams": vectors.streams,
        "recipe_bins": vectors.coverage, "leaf_only_commands": skipped,
        "external_interrupt": external_interrupt,
    }


def peripheral_machine(base):
    class PeripheralMachine(base):
        def __init__(self, words, image, dmem_words, metadata):
            super().__init__(words, image, dmem_words)
            self.operations = {int(pc): item for pc, item in metadata["operations"].items()}
            self.interrupt_reads = {int(pc): value for pc, value in metadata["interrupt_reads"].items()}
            self.peripheral_comparisons = 0
            self.interrupt_comparisons = 0
            self.mailbox_responses = []
            self.expected_external_interrupt = metadata["external_interrupt"]
            self.external_interrupts = 0

        def take_interrupt(self, cause, cycle):
            expected = self.expected_external_interrupt
            if (not expected or self.external_interrupts or cause != expected["cause"] or
                    self.pc != expected["pc"] or self.priv != 1 or
                    not self.csrs[0x300] & 2 or not self.csrs[0x303] & (1 << 9) or
                    not self.csrs[0x304] & (1 << 9)):
                raise AssertionError(f"PERIPHERAL_EXTERNAL_INTERRUPT cause={cause:x} pc={self.pc:x}")
            self.external_interrupts += 1
            return self.trap(cause, 0)

        def physical(self, address, access):
            operation = self.operations.get(self.pc) if access != 0 else None
            if operation is not None and address == operation["address"]:
                if operation["error"]:
                    raise ArchitecturalTrap(7 if operation["write"] else 5, address)
                return address
            return super().physical(address, access)

        def read_memory(self, address, size):
            if address == MAILBOX + 8:
                if size != 8 or not self.mailbox_responses:
                    raise AssertionError("PERIPHERAL_MAILBOX_RESPONSE_MISSING")
                value = self.mailbox_responses.pop(0)
                if value > super().read_memory(address, size):
                    raise AssertionError("PERIPHERAL_MAILBOX_RESPONSE_BEFORE_ACKNOWLEDGEMENT")
                return value
            operation = self.operations.get(self.pc)
            if operation and not operation["write"] and address == operation["address"]:
                if (address, size) != (operation["address"], 1 << operation["size"]):
                    raise AssertionError(f"PERIPHERAL_ORACLE_ADDRESS pc={self.pc:x}")
                self.peripheral_comparisons += 1
                return operation["expected"]
            return super().read_memory(address, size)

        def write_memory(self, address, size, value):
            operation = self.operations.get(self.pc)
            if operation and operation["write"]:
                if (address, size, value) != (
                        operation["address"], 1 << operation["size"], operation["value"]):
                    raise AssertionError(f"PERIPHERAL_ORACLE_WRITE pc={self.pc:x}")
                self.peripheral_comparisons += 1
            else:
                super().write_memory(address, size, value)

        def csr_read(self, address):
            if address == 0x344 and self.pc in self.interrupt_reads:
                self.interrupt_comparisons += 1
                return self.interrupt_reads[self.pc]
            return super().csr_read(address)

    return PeripheralMachine
