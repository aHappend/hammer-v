"""Clock-accurate CLINT oracle: byte-addressed register image and bus transactions."""

MASK = (1 << 64) - 1
REGISTERS = ((0x02000000, 4), (0x02004000, 8), (0x0200BFF8, 8))


class Clint:
    def __init__(self):
        self.time = 0
        self.compare = MASK
        self.software = 0
        self.response = None
        self.counts = {name: 0 for name in (
            "accepted", "reads", "writes", "errors", "zero_strobe_time",
            "time_write_overrides", "response_stalls", "reset_outstanding",
            "mtip_rises", "mtip_falls", "msip_rises", "msip_falls")}
        self.lanes = set()
        self.sizes = set()
        self.simultaneous_compare = 0

    def outputs(self, reset_n):
        if not reset_n:
            return (0, 0, 0, 0, 0, 0, 0)
        error, data = self.response if self.response else (0, 0)
        return (int(self.response is None), int(self.response is not None),
                error, data, self.time, self.software, int(self.time >= self.compare))

    def edge(self, vector):
        reset_n, valid, write, size_log2, address, data, strobe, ready = vector
        before = self.outputs(reset_n)
        if not reset_n:
            self.counts["reset_outstanding"] += int(self.response is not None)
            self.time, self.compare, self.software, self.response = 0, MASK, 0, None
            return before, self.outputs(reset_n)
        old_time = self.time
        self.time = (old_time + 1) & MASK
        if self.response is not None:
            if ready:
                self.response = None
            else:
                self.counts["response_stalls"] += 1
        if valid and before[0]:
            self.counts["accepted"] += 1
            self.counts["writes" if write else "reads"] += 1
            size = 1 << size_log2
            matches = [(base, length) for base, length in REGISTERS
                       if base <= address and address + size <= base + length]
            legal = address % size == 0 and bool(matches)
            if not legal:
                self.response = (1, 0)
                self.counts["errors"] += 1
            else:
                base, _ = matches[0]
                snapshot = {0x02000000: self.software, 0x02004000: self.compare,
                            0x0200BFF8: old_time}[base]
                self.response = (0, snapshot)
                self.sizes.add(size)
                if write:
                    image = bytearray(snapshot.to_bytes(8, "little"))
                    for lane in range(8):
                        if strobe & (1 << lane):
                            image[lane] = (data >> (8 * lane)) & 255
                            self.lanes.add((base, lane))
                    merged = int.from_bytes(image, "little")
                    if base == 0x02000000:
                        self.software = merged & 1
                    elif base == 0x02004000:
                        self.compare = merged
                        self.simultaneous_compare += int(merged == old_time)
                    elif strobe:
                        self.time = merged
                        self.counts["time_write_overrides"] += 1
                    else:
                        self.counts["zero_strobe_time"] += 1
        after = self.outputs(reset_n)
        for label, index in (("msip", 5), ("mtip", 6)):
            self.counts[label + "_rises"] += int(before[index] == 0 and after[index] == 1)
            self.counts[label + "_falls"] += int(before[index] == 1 and after[index] == 0)
        return before, after


def vectors(seed):
    import random
    rng = random.Random(seed)
    model = Clint()
    result = []

    def emit(vector):
        result.append(vector)
        model.edge(vector)

    def idle(count=1, ready=1, reset=1):
        for _ in range(count):
            emit((reset, 0, 0, 0, 0, 0, 0, ready))

    def access(write, size, address, data=0, strobe=0, stall=2):
        while model.response is not None:
            idle()
        emit((1, 1, write, size, address, data, strobe, 0))
        idle(stall, ready=0)
        idle()

    idle(reset=0)
    for base, length in REGISTERS:
        for size in range(4):
            for lane in range(length):
                address = base + lane
                mask = (((1 << (1 << size)) - 1) << (address & 7)) & 255
                access(1, size, address, rng.getrandbits(64), mask)
                access(0, size, address)
    for address in (0x02000004, 0x02000008, 0x02004008, 0x0200BFF0,
                    0x0200C000, 0x102004000, MASK):
        for size in range(4):
            access(1, size, address, MASK, 255)
            access(0, size, address)
    access(1, 3, 0x02004000, MASK, 255)
    access(1, 3, 0x0200BFF8, 0, 255)
    access(1, 3, 0x0200BFF8, MASK, 0)
    access(1, 3, 0x02004000, model.time, 255)
    access(1, 3, 0x02004000, MASK, 255)
    access(1, 3, 0x0200BFF8, MASK - 2, 255, stall=0)
    idle(5)
    access(1, 2, 0x02000000, 1, 15)
    access(1, 2, 0x02000000, 0, 15)
    emit((1, 1, 0, 3, 0x0200BFF8, 0, 0, 0))
    idle(2, ready=0)
    idle(reset=0)
    idle(3)
    # A held request overlaps a stalled response; acceptance waits until
    # the previous response has been consumed, never the consuming edge.
    emit((1, 1, 0, 3, 0x0200BFF8, 0, 0, 0))
    for ready in (0, 0, 1, 1):
        emit((1, 1, 1, 2, 0x02000000, 1, 15, ready))
    idle(3)
    return result


def compare(path, stimulus):
    model = Clint()
    rows = 0
    done = False
    with path.open() as stream:
        for raw in stream:
            fields = raw.split()
            if fields[0] == "DONE":
                if fields != ["DONE", str(len(stimulus))]:
                    raise AssertionError("CLINT completion conservation mismatch")
                done = True
                continue
            if done or fields[:2] != ["E", str(rows + 1)] or len(fields) != 24:
                raise AssertionError(f"CLINT malformed event {raw.strip()}")
            observed_inputs = tuple(int(value, 16 if field in (4, 5, 6) else 10)
                                    for field, value in enumerate(fields[2:10]))
            if observed_inputs != stimulus[rows]:
                raise AssertionError(f"CLINT edge {rows + 1} input mismatch: "
                                     f"expected={stimulus[rows]}, observed={observed_inputs}")
            before, after = model.edge(stimulus[rows])
            rows += 1
            for index, expected in enumerate((before, after)):
                raw_sample = fields[10 + index * 7:17 + index * 7]
                sample = tuple(int(value, 16 if field in (3, 4) else 10)
                               for field, value in enumerate(raw_sample))
                if sample != expected:
                    raise AssertionError(f"CLINT edge {rows} {'post' if index else 'pre'}: "
                                         f"expected={expected}, observed={sample}")
    if not done or rows != len(stimulus):
        raise AssertionError("CLINT missing edge comparisons")
    if any(not count for count in model.counts.values()):
        raise AssertionError(f"CLINT required event missing: {model.counts}")
    required_lanes = {(base, lane) for base, length in REGISTERS for lane in range(length)}
    if model.sizes != {1, 2, 4, 8} or not required_lanes <= model.lanes:
        raise AssertionError("CLINT legal sizes/byte lanes not compared")
    if not model.simultaneous_compare:
        raise AssertionError("CLINT comparison-equality edge not compared")
    return {"edges_compared": rows, **model.counts, "sizes": sorted(model.sizes),
            "write_lanes": sorted(model.lanes), "compare_equality_edges": model.simultaneous_compare}


def compare_integrated(path):
    model = Clint()
    edge = 0
    transitions = []
    operations = []
    complete = False

    def clock(vector):
        nonlocal edge
        edge += 1
        before, after = model.edge(vector)
        if before[5:] != after[5:]:
            transitions.append((edge, after[4], *after[5:]))
        return before, after

    def advance(target):
        if target < edge:
            raise AssertionError("CLINT integrated event time reversed")
        while edge < target:
            clock((1, 0, 0, 0, 0, 0, 0, 0))

    with path.open() as stream:
        for raw in stream:
            fields = raw.split()
            kind, observed_edge = fields[0], int(fields[1])
            if complete:
                raise AssertionError("CLINT event after completion")
            if kind in ("Q", "R"):
                advance(observed_edge - 1)
                before = model.outputs(1)
                if kind == "Q":
                    write, size = int(fields[2]), int(fields[3])
                    address, data, strobe = (int(fields[4], 16), int(fields[5], 16),
                                             int(fields[6], 16))
                    observed_clock = (int(fields[7], 16), int(fields[8]), int(fields[9]))
                    if before[0] != 1:
                        raise AssertionError("CLINT accepted an overlapping request")
                    _, after = clock((1, 1, write, size, address, data, strobe, 0))
                    operations.append({"edge": observed_edge, "write": write, "size": size,
                                       "address": address, "data": data, "strobe": strobe,
                                       "snapshot": after[3], "error": after[2]})
                else:
                    observed_clock = (int(fields[4], 16), int(fields[5]), int(fields[6]))
                    if (int(fields[2], 16), int(fields[3])) != (before[3], before[2]) or (
                            before[1] != 1):
                        raise AssertionError(f"CLINT edge {observed_edge}: incorrect/orphan response")
                    clock((1, 0, 0, 0, 0, 0, 0, 1))
                if observed_clock != before[4:]:
                    raise AssertionError(f"CLINT edge {observed_edge}: pre-edge timer/IRQ "
                                         f"expected={before[4:]}, observed={observed_clock}")
            elif kind in ("P", "DONE"):
                advance(observed_edge)
                observed = (observed_edge, int(fields[2], 16), int(fields[3]), int(fields[4]))
                if kind == "P":
                    if not transitions or transitions.pop(0) != observed:
                        raise AssertionError(f"CLINT edge {observed_edge}: pending transition mismatch")
                else:
                    if observed[1:] != model.outputs(1)[4:] or transitions or model.response:
                        raise AssertionError("CLINT final clock/pending/channel conservation mismatch")
                    complete = True
            else:
                raise AssertionError(f"unknown CLINT integrated event: {kind}")
    if not complete or not operations:
        raise AssertionError("CLINT integrated comparisons did not execute")
    return operations, {"observed_edges": edge, "accepted_operations": len(operations),
                        **model.counts}


def state_before(operations, edge):
    model = Clint()
    previous = 0
    for operation in operations:
        acceptance = operation["edge"]
        if acceptance >= edge:
            break
        model.time = (model.time + acceptance - previous - 1) & MASK
        model.response = None
        model.edge((1, 1, operation["write"], operation["size"],
                    operation["address"], operation["data"], operation["strobe"], 0))
        previous = acceptance
    model.time = (model.time + edge - previous - 1) & MASK
    return model.time, model.compare, model.software
