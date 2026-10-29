"""AXI stimulus and byte-memory reference, derived from the public burst contract."""

import random


READ_ERROR = 0x8007F000
WRITE_ERROR = 0x8007F008


def geometry_response(address, length, size, burst, lock, dmem_words):
    if (size not in range(4) or burst not in (0, 1) or lock or
            length not in range(1, 17)):
        return 2
    step = 1 << size
    final = address + ((length - 1) * step if burst == 1 else 0)
    if address % step or address // 4096 != (final + step - 1) // 4096:
        return 2
    if not (0x10000000 <= address and final + step <= 0x10000000 + 8 * dmem_words or
            0x80000000 <= address and final + step <= 0x100000000):
        return 3
    return 0


def vectors(seed, dmem_words):
    rng = random.Random(seed ^ 0x41584934)
    commands = []

    def add(write, address, length=1, size=3, burst=1, lock=0, malformed=None):
        response = geometry_response(address, length, size, burst, lock, dmem_words)
        beats = []
        for beat in range(length):
            current = address + (beat * (1 << size) if burst == 1 else 0)
            mask = (((1 << (1 << size)) - 1) << (current % 8)) & 255 if size <= 3 else 255
            if malformed == "strobe":
                mask |= 1 << ((current + (1 << size)) % 8)
            last = int(beat == length - 1)
            if malformed == "early-last" and beat == 0:
                last = 1
            if malformed == "missing-last" and beat == length - 1:
                last = 0
            beats.append((rng.getrandbits(64), mask, last))
        if malformed:
            response = response or 2
        if response == 0 and ((write and address == WRITE_ERROR) or
                              (not write and address == READ_ERROR)):
            response = 2
        command = dict(write=write, address=address, length=length, size=size, burst=burst,
                       lock=lock, identity=len(commands) % 16, response=response,
                       malformed=malformed, beats=beats)
        commands.append(command)

    for length in (1, 2, 16):
        for burst in (0, 1):
            for size in range(4):
                for lane in range(0, 8, 1 << size):
                    address = 0x80070000 + lane
                    add(True, address, length, size, burst)
                    add(False, address, length, size, burst)
    for kwargs in (
            {"length": 17}, {"length": 256}, {"size": 4}, {"size": 7},
            {"burst": 2}, {"burst": 3}, {"lock": 1},
            {"address": 0x80070001, "size": 1},
            {"address": 0x80070002, "size": 2},
            {"address": 0x80070004, "size": 3},
            {"address": 0x80070FF8, "length": 2},
            {"address": 0x10000000 + 8 * dmem_words},
            {"address": 0}, {"address": 0x10010000}, {"address": 0x20000000},
            {"address": 1 << 56}):
        for write in (True, False):
            add(write, **({"address": 0x80070000} | kwargs))
        # A real successful readback detects collateral writes in the sandbox.
        add(False, 0x80070000, 16)
    for malformed in ("strobe", "early-last", "missing-last"):
        add(True, 0x80070000, 2, 0, malformed=malformed)
        add(False, 0x80070000, 16)
    add(False, READ_ERROR)
    add(True, WRITE_ERROR)
    add(False, WRITE_ERROR)
    return commands


def write_vectors(path, commands):
    with path.open("w") as stream:
        for command in commands:
            stream.write(" ".join(f"{command[key]:x}" for key in
                                 ("write", "address", "length", "size", "burst", "lock",
                                  "identity", "response")) + "\n")
            if command["write"]:
                for value, mask, last in command["beats"]:
                    stream.write(f"{value:x} {mask:x} {last:x}\n")


class AxiScoreboard:
    def __init__(self, commands):
        self.commands = commands
        self.memory = {}
        self.command = 0
        self.beat = 0
        self.bins = {}

    def accept(self, fields):
        index, identity, status, value, last = (int(field, 16) for field in fields[2:])
        if index != self.command:
            raise AssertionError(f"SYSTEM_AXI_ORDER expected command {self.command}, got {fields}")
        command = self.commands[index]
        if identity != command["identity"] or status != command["response"]:
            raise AssertionError(f"SYSTEM_AXI_RESPONSE expected={command} got={fields}")
        address = command["address"]
        if command["write"]:
            if fields[1] != "W":
                raise AssertionError(f"SYSTEM_AXI_CHANNEL expected B, got={fields}")
            if status == 0:
                for beat, (data, mask, _) in enumerate(command["beats"]):
                    current = address + (beat * (1 << command["size"]) if command["burst"] == 1 else 0)
                    for lane in range(8):
                        if mask & (1 << lane):
                            self.memory[(current & ~7) + lane] = (data >> (8 * lane)) & 255
        else:
            if fields[1] != "R" or last != int(self.beat == command["length"] - 1):
                raise AssertionError(f"SYSTEM_AXI_RLAST expected={command} beat={self.beat} got={fields}")
            current = address + (self.beat * (1 << command["size"]) if command["burst"] == 1 else 0)
            expected = (sum(self.memory.get(current + b, 0) << (8 * (current % 8 + b))
                            for b in range(1 << command["size"])) if status == 0 else 0)
            if value != expected:
                raise AssertionError(f"SYSTEM_AXI_READ address={current:x} expected={expected:x} got={fields}")
            self.beat += 1
            if self.beat < command["length"]:
                return
        label = ("malformed-" + command["malformed"] if command["malformed"] else
                 f"{'write' if command['write'] else 'read'}-len{command['length']}-"
                 f"size{command['size']}-burst{command['burst']}-lock{command['lock']}-"
                 f"response{status}")
        self.bins[label] = self.bins.get(label, 0) + 1
        self.command += 1
        self.beat = 0

    def finish(self):
        if self.command != len(self.commands) or self.beat:
            raise AssertionError(f"SYSTEM_AXI_INCOMPLETE {self.command}/{len(self.commands)}")
        return {"compared_transactions": self.command, "bins": self.bins}
