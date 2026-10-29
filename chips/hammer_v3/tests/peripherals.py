"""Public peripheral experiments derived from PLIC and 16550 register semantics."""


class Vectors:
    def __init__(self):
        self.lines = []
        self.frames = []
        self.coverage = {}

    def cover(self, key):
        # These are expected bins, admitted only after the entire comparison succeeds.
        self.coverage[key] = self.coverage.get(key, 0) + 1

    def bus(self, unit, write, address, size, data=0, expected=0, error=0,
            mask=None, stall=3, minimum_blocked=0):
        if mask is None:
            mask = ((1 << (1 << size)) - 1) << (address & 7)
        self.lines.append(
            f"B {unit} {int(write)} {address:x} {size} {data:x} {mask:x} "
            f"{expected:x} {error} {stall} {minimum_blocked}")

    def uart(self, offset, write=False, data=0, expected=0, **kwargs):
        self.bus(0, write, 0x10010000 + offset, 0, data << (8 * offset),
                 expected << (8 * offset), **kwargs)

    def plic(self, offset, write=False, data=0, expected=0, **kwargs):
        shift = 8 * (offset & 7)
        self.bus(1, write, 0x0C000000 + offset, 2, data << shift,
                 expected << shift, **kwargs)

    def wait(self, cycles):
        self.lines.append(f"W {cycles}")

    def sources(self, levels):
        self.lines.append(f"S {levels:x}")
        self.wait(6)

    def irq(self, mask, expected):
        self.lines.append(f"Q {mask} {expected}")


def plic_vectors():
    v = Vectors()
    # Reset register values, including the reserved source-zero register.
    for source in range(33):
        v.plic(4 * source)
    for context in range(2):
        v.plic(0x2000 + 0x80 * context)
        v.plic(0x2004 + 0x80 * context)
        v.plic(0x200000 + 0x1000 * context)
        v.plic(0x200004 + 0x1000 * context)
    v.irq(6, 0)
    for context in range(2):
        v.plic(0x2000 + context * 0x80, True, 0xFFFFFFFE)
        v.plic(0x2004 + context * 0x80, True, 1)
    # An asserted source is shared across contexts, not independently claimable.
    for priority in range(8):
        for source in range(1, 33):
            v.plic(source * 4, True, priority)
            v.plic(source * 4, expected=priority)
            v.sources(1 << (source - 1))
            if priority == 0:
                v.irq(6, 0)
                v.plic(0x200004)
                # Deasserting a level does not erase a latched pending event.
                v.sources(0)
                v.plic(source * 4, True, 1)
                v.wait(3)
            else:
                v.irq(6, 6)
            context = (priority + source) & 1
            claim = 0x200004 + context * 0x1000
            other_claim = 0x200004 + (1 - context) * 0x1000
            v.plic(claim, expected=source)
            v.plic(other_claim, expected=0)
            # Wrong-context and out-of-range completion must not release ownership.
            v.plic(other_claim, True, source)
            v.plic(claim, True, 33)
            v.plic(claim)
            v.plic(other_claim)
            if priority != 0:
                # A correct completion of a held level produces a fresh pending event.
                v.plic(claim, True, source)
                v.wait(3)
                v.plic(other_claim, expected=source)
                v.sources(0)
                v.plic(other_claim, True, source)
            else:
                v.plic(claim, True, source)
            v.plic(source * 4, True, 0)
            v.wait(3)
            v.irq(6, 0)
            v.cover(f"source-{source}")
            v.cover(f"priority-{priority}")
            v.cover(f"context-{context}")
    # Equal-priority ties select the lowest ID; threshold equality is masked.
    for source in (1, 2, 17, 32):
        v.plic(source * 4, True, 4)
    for threshold in range(8):
        for context in range(2):
            v.plic(0x200000 + context * 0x1000, True, threshold)
        v.sources((1 << 31) | (1 << 16) | 3)
        v.irq(6, 6 if threshold < 4 else 0)
        if threshold >= 4:
            v.plic(0x200004)
            for context in range(2):
                v.plic(0x200000 + context * 0x1000, True, 0)
        for number, source in enumerate((1, 2, 17, 32)):
            v.plic(0x200004 + 0x1000 * (number & 1), expected=source)
        v.sources(0)
        for number, source in enumerate((1, 2, 17, 32)):
            v.plic(0x200004 + 0x1000 * (number & 1), True, source)
        v.cover(f"threshold-{threshold}")
    # Enable masks and pending words, including ID32's second word.
    v.plic(0x2000, True, 0)
    v.plic(0x2004, True, 0)
    v.plic(0x2080, True, 0)
    v.plic(0x2084, True, 0)
    v.sources((1 << 31) | 1)
    v.irq(6, 0)
    v.plic(0x1000, expected=2)
    v.plic(0x1004, expected=1)
    v.plic(0x2084, True, 1)
    v.wait(3)
    v.irq(6, 4)
    v.plic(0x201004, expected=32)
    v.sources(0)
    v.plic(0x201004, True, 32)
    v.plic(0x2000, True, 2)
    v.wait(3)
    v.plic(0x200004, expected=1)
    v.plic(0x200004, True, 1)
    for address in (0x0C000084, 0x0C001008, 0x0C002008, 0x0C200008,
                    0x10C000004):
        v.bus(1, False, address, 2, error=1)
    v.bus(1, False, 0x0C000005, 2, mask=0xF0, error=1)
    v.bus(1, False, 0x0C000004, 3, error=1)
    v.bus(1, True, 0x0C000004, 2, data=1 << 32, mask=0x10, error=1)
    v.plic(0x1000, True, 0, error=1)
    return v


def frame_bits(value, lcr):
    width = 5 + (lcr & 3)
    bits = [(value >> bit) & 1 for bit in range(width)]
    if lcr & 8:
        parity = (1 - ((lcr >> 4) & 1)) if lcr & 32 else (
            (sum(bits) & 1) if lcr & 16 else 1 - (sum(bits) & 1))
        bits.append(parity)
    return [0, *bits]


def character_cycles(lcr, divisor):
    stop_ticks = (24 if lcr & 3 == 0 else 32) if lcr & 4 else 16
    return (16 * len(frame_bits(0, lcr)) + stop_ticks) * max(1, divisor)


def uart_vectors():
    v = Vectors()
    for offset, expected in ((1, 0), (2, 1), (3, 0), (4, 0), (5, 0x60),
                             (6, 0), (7, 0)):
        v.uart(offset, expected=expected)
    v.irq(1, 0)
    for value in (0, 0x5A, 0xFF):
        v.uart(7, True, value)
        v.uart(7, expected=value)
    # THRE interrupt enable/read-clear and loopback modem mappings/deltas.
    v.uart(1, True, 2)
    v.irq(1, 1)
    v.uart(2, expected=2)
    v.irq(1, 0)
    v.uart(1, True, 8)
    v.uart(4, True, 0x1F)
    v.wait(3)
    v.irq(1, 1)
    v.uart(2, expected=0)
    v.uart(6, expected=0xFB)
    v.uart(6, expected=0xF0)
    v.irq(1, 0)
    v.uart(4, True, 0x10)
    v.wait(3)
    v.uart(6, expected=0x0F)
    v.uart(6)
    v.uart(1, True, 0)
    v.uart(4, True, 0)
    # Validate serial TX and RX across all word lengths, parity and stop formats.
    formats = [width | stop | parity for width in range(4)
               for stop in (0, 4) for parity in (0, 8, 24, 40, 56)]
    for divisor in (1, 2, 27):
        v.uart(3, True, 0x80)
        v.uart(0, True, divisor)
        v.uart(1, True, 0)
        v.uart(0, expected=divisor)
        v.uart(1, expected=0)
        for lcr in formats:
            value = (0xA5 ^ (lcr * 13)) & 255
            v.uart(3, True, lcr)
            v.uart(2, True, 7)
            v.uart(4, True, 0)
            marker = len(v.frames)
            v.lines.append(f"M {marker}")
            v.frames.append({"marker": marker, "value": value, "lcr": lcr,
                             "divisor": divisor})
            v.uart(0, True, value)
            v.wait(character_cycles(lcr, divisor) + 10)
            v.uart(5, expected=0x60)
            # External RX, not an expectation driven into the DUT's TX path.
            for bit in frame_bits(value, lcr):
                v.lines.append(f"U {bit} {16 * divisor}")
            stop_ticks = (24 if lcr & 3 == 0 else 32) if lcr & 4 else 16
            v.lines.append(f"U 1 {stop_ticks * divisor + 10}")
            v.uart(5, expected=0x61)
            v.uart(0, expected=value & ((1 << (5 + (lcr & 3))) - 1))
            v.uart(5, expected=0x60)
            v.cover(f"format-{lcr:02x}-divisor-{divisor}")
    v.uart(3, True, 0x83)
    v.uart(0, True, 0)
    v.uart(1, True, 0)
    v.uart(0, expected=0)
    v.uart(3, True, 3)
    v.uart(4, True, 0x10)
    for trigger, level in enumerate((1, 4, 8, 14)):
        v.uart(2, True, 7 | (trigger << 6))
        v.uart(1, True, 1)
        for count in range(level):
            v.uart(0, True, 0x41 + count)
            v.wait(180)
            v.irq(1, int(count + 1 >= level))
        v.uart(2, expected=0xC4)
        for count in range(level):
            v.uart(0, expected=0x41 + count)
        v.irq(1, 0)
        v.cover(f"trigger-{level}")
    # RX timeout below trigger, cleared by RBR read.
    v.uart(2, True, 0xC7)
    v.uart(0, True, 0x55)
    v.wait(1000)
    v.irq(1, 1)
    v.uart(2, expected=0xCC)
    v.uart(0, expected=0x55)
    v.irq(1, 0)
    # RX overflow retains all queued bytes and clears overrun on LSR read.
    v.uart(1, True, 4)
    v.uart(2, True, 7)
    for byte in range(17):
        v.uart(0, True, byte)
        v.wait(180)
    v.uart(5, expected=0x63)
    v.uart(5, expected=0x61)
    for byte in range(16):
        v.uart(0, expected=byte)
    v.uart(5, expected=0x60)
    for address in (0x10010008, 0x110010000):
        v.bus(0, False, address, 0, error=1)
    v.bus(0, True, 0x10010000, 1, mask=3, error=1)
    v.bus(0, True, 0x10010001, 0, mask=1, error=1)
    return v


def compare_waveform(path, frames):
    events = []
    markers = {}
    for line in path.read_text().splitlines():
        kind, first, second = line.split()
        if kind == "T":
            events.append((int(first), int(second)))
        elif kind == "M":
            markers[int(second)] = int(first)
        else:
            raise AssertionError(f"unknown UART waveform record: {line}")
    comparisons = 0
    for frame in frames:
        marker = frame["marker"]
        if marker not in markers:
            raise AssertionError(f"missing UART frame marker {marker}")
        lo = markers[marker]
        hi = markers.get(marker + 1, 1 << 63)
        starts = [cycle for cycle, bit in events if lo < cycle < hi and bit == 0]
        if not starts:
            raise AssertionError(f"no real serial TX frame {marker}")
        start = starts[0]
        divisor = max(1, frame["divisor"])
        bits = frame_bits(frame["value"], frame["lcr"])
        transitions = [(cycle - start, value) for cycle, value in events
                       if start <= cycle < start + character_cycles(frame["lcr"], divisor)]
        expected = []
        previous = 1
        for bit_index, bit in enumerate([*bits, 1]):
            if bit != previous:
                expected.append((bit_index * 16 * divisor, bit))
                previous = bit
        if transitions != expected:
            raise AssertionError(f"UART_SERIAL frame={marker} format={frame} "
                                 f"expected={expected} observed={transitions}")
        comparisons += 1
    return comparisons
