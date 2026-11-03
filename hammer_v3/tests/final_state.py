"""Independent final architectural-state comparison, separate from retirement."""

from collections import defaultdict


def ram_address(address, dmem_words):
    return (0x10000000 <= address < 0x10000000 + 8 * dmem_words or
            0x80000000 <= address < 0x80100000)


class ObservedMemory(defaultdict):
    """Track model writes, including AMOs that update byte memory directly."""

    def __init__(self, image, dmem_words):
        super().__init__(int, image)
        self.dmem_words = dmem_words
        self.modified = set()
        # Public host setup initializes this word before every integrated program.
        for byte in range(8):
            dict.__setitem__(self, 0x10000000 + byte,
                             (0x01234567A5ABCDEF >> (8 * byte)) & 255)

    def __setitem__(self, address, value):
        super().__setitem__(address, value)
        if ram_address(address, self.dmem_words):
            self.modified.add(address)

    def __missing__(self, address):
        return 0


def write_plan(path, addresses):
    addresses = sorted(set(addresses) | {0x10000000})
    if any(address & 7 for address in addresses):
        raise AssertionError("FINAL_MEMORY_PLAN_UNALIGNED")
    path.write_text("".join(f"{address:016x}\n" for address in addresses))
    return addresses


class FinalState:
    def __init__(self, addresses):
        self.addresses = set(addresses)
        self.registers = {}
        self.memory = {}
        self.begun = self.ended = False

    def accept(self, line, model):
        fields = line.split()
        if not fields or fields[0] != "F":
            return False
        if not model.stopped:
            raise AssertionError("FINAL_STATE_BEFORE_TERMINAL")
        kind = fields[1]
        if kind == "B" and len(fields) == 2:
            if self.begun or self.ended:
                raise AssertionError("FINAL_STATE_DUPLICATE_BEGIN")
            self.begun = True
        elif kind == "E" and len(fields) == 2:
            if not self.begun or self.ended:
                raise AssertionError("FINAL_STATE_BAD_END")
            self.ended = True
        elif kind in ("R", "M") and len(fields) == 4:
            if not self.begun or self.ended:
                raise AssertionError("FINAL_STATE_OBSERVATION_OUTSIDE_SNAPSHOT")
            if any(character in fields[2].lower() + fields[3].lower()
                   for character in "xz"):
                raise AssertionError("FINAL_STATE_ACTIVE_XZ")
            key, value = (int(field, 16) for field in fields[2:])
            target = self.registers if kind == "R" else self.memory
            if key in target:
                raise AssertionError(f"FINAL_STATE_DUPLICATE_{kind} {key:x}")
            if key not in (set(range(32)) if kind == "R" else self.addresses):
                raise AssertionError(f"FINAL_STATE_UNREQUESTED_{kind} {key:x}")
            target[key] = value
        else:
            raise AssertionError(f"FINAL_STATE_RECORD_FORMAT {line}")
        return True

    def compare(self, model):
        if (not self.begun or not self.ended or set(self.registers) != set(range(32)) or
                set(self.memory) != self.addresses):
            raise AssertionError("FINAL_STATE_MISSING_OBSERVATIONS")
        modified_words = {address & ~7 for address in model.memory.modified}
        missing = modified_words - self.addresses
        if missing:
            raise AssertionError(f"FINAL_MEMORY_PLAN_INCOMPLETE {sorted(missing)}")
        for register, value in self.registers.items():
            if value != model.regs[register]:
                raise AssertionError(f"FINAL_REGISTER_MISMATCH x{register} "
                                     f"expected={model.regs[register]:016x} actual={value:016x}")
        for address, value in self.memory.items():
            if not ram_address(address, model.dmem_words):
                raise AssertionError(f"FINAL_MEMORY_NOT_RAM {address:x}")
            if address < 0x80000000 and any(
                    address + byte not in model.memory for byte in range(8)):
                raise AssertionError(f"FINAL_MEMORY_UNDEFINED_BYTES {address:x}")
            expected = sum(model.memory.get(address + byte, 0) << (8 * byte)
                           for byte in range(8))
            if value != expected:
                raise AssertionError(f"FINAL_MEMORY_MISMATCH address={address:016x} "
                                     f"expected={expected:016x} actual={value:016x}")
        return {"register_comparisons": len(self.registers),
                "memory_word_comparisons": len(self.memory),
                "modified_memory_words": len(modified_words),
                "modified_memory_bytes": len(model.memory.modified),
                "observation_coherent_reads": len(self.memory),
                "workload_coverage_credit": 0}
