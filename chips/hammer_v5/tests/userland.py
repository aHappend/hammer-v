"""Independent UART numerical and hardware-counter interval comparisons."""
import json

from reference import MASK64, add32, bf16_dot, int8_dot, rms

CASE_OPERANDS = (
    (0, 0x3F803F803F803F80),
    (0x8000800080008000, 0x3F803F803F803F80),
    (0x3F803F803F803F80, 0x8000800080008000),
    (0x7F807F807F807F80, 0),
    (0x7FC17FC17FC17FC1, 0x3F803F803F803F80),
    (0x0001000100010001, 0x3F803F803F803F80),
    (0x0080008000800080, 0x3F003F003F003F00),
    (0x3F803F80BF80BF80, 0x3F803F803F803F80),
    (0x7F7F7F7F7F7F7F7F, 0x7F7F7F7F7F7F7F7F),
    (0x3F813F813F813F81, 0x3F813F813F813F81),
    (0x3F800001BF800001, 0x3F803F803F803F80),
    (0x8080008080800080, 0x3F003F003F003F00),
)


def expected(seed):
    state = seed

    def random_word():
        nonlocal state
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        return state

    def packed(bf):
        result = 0
        for lane in range(4 if bf else 8):
            value = random_word()
            bits = ((value & 0x8000) | ((122 + ((value >> 8) % 12)) << 7) |
                    (value & 127)) if bf else value & 255
            result |= bits << ((16 if bf else 8) * lane)
        return result

    pairs_i = [(packed(False), packed(False)) for _ in range(32)]
    pairs_b = [(packed(True), packed(True)) for _ in range(64)]

    def reduce(pairs, bf):
        accumulator = 0
        for a, b in pairs:
            accumulator = add32(accumulator, bf16_dot(a, b)) if bf else (
                accumulator + int8_dot(a, b)) & MASK64
        return accumulator

    tile_i = [[(packed(False), packed(False)) for _ in range(8)] for _ in range(8)]
    tile_b = [[(packed(True), packed(True)) for _ in range(8)] for _ in range(4)]
    matrices = {}
    for kind, matrix in (("int8", tile_i), ("bf16", tile_b)):
        matrices[kind] = {
            (row, column): reduce(
                [(matrix[row][group][0], matrix[column][group][1]) for group in range(8)],
                kind == "bf16")
            for row in range(len(matrix)) for column in range(len(matrix))}
    accumulator = 0xFFFFFFFFFFFFFF00
    for a, _ in pairs_i:
        accumulator = rms(a, accumulator)
    return {"int8": reduce(pairs_i, False), "bf16": reduce(pairs_b, True),
            "rms": accumulator, "matrices": matrices}


def fields(line):
    tokens = line.strip().split()
    if len(tokens) < 2 or tokens[0] != "HV5":
        return None
    pairs = [token.split("=", 1) for token in tokens[2:]]
    if any(len(pair) != 2 for pair in pairs):
        raise AssertionError("malformed UART user record")
    result = dict(pairs)
    if len(result) != len(pairs):
        raise AssertionError("duplicate UART record field")
    return tokens[1], result


def number(record, key):
    if key not in record:
        raise AssertionError(f"UART record missing {key}")
    value = record[key]
    return int(value, 16 if value.startswith("0x") else 10)


def median(values):
    values = sorted(values)
    return values[15] + ((values[16] - values[15]) >> 1)


def compare_userland(directory):
    records = []
    for line in (directory / "uart-events.txt").read_text().splitlines():
        timestamp, text = line.split(" ", 1)
        parsed = fields(text)
        if parsed:
            records.append((int(timestamp), *parsed))
    counters = [(int(cycle), int(addr, 16), int(value, 16))
                for cycle, addr, value in (
                    line.split() for line in (directory / "counter-reads.txt").read_text().splitlines())]
    models = {seed: expected(seed) for seed in (17, 43, 89)}
    samples, benchmarks, cells, cases, rms_seen, tiles, cache_seen, arithmetic = (
        {}, {}, {}, {}, set(), set(), set(), set())
    contexts = set()
    milestones = {"USER": 0, "FAULTS": 0, "DONE": 0}
    counter_values = {address: [value for _, addr, value in counters if addr == address]
                      for address in range(0xC00, 0xC07)}
    cursors = {address: 0 for address in counter_values}
    numerical = 0
    measured = 0

    def take(address, count):
        offset = cursors[address]
        values = counter_values[address][offset:offset + count]
        if len(values) != count:
            raise AssertionError(f"missing actual hardware CSR 0x{address:x} reads")
        cursors[address] += count
        return values

    def pair_delta(address):
        values = take(address, 2)
        return (values[1] - values[0]) & MASK64

    sample_boundary = {}
    for timestamp, kind, record in records:
        if kind == "FAIL":
            raise AssertionError("genuine user program reported failure")
        if kind == "USER":
            milestones[kind] += 1
            if number(record, "pid") != 1:
                raise AssertionError("console workload is not PID 1 /init")
        elif kind == "FAULTS":
            milestones[kind] += 1
            if (number(record, "successful_vload") != 1 or number(record, "rejected") != 5 or
                    number(record, "state_preserved") != 1):
                raise AssertionError("genuine translated custom fault cases incomplete")
        elif kind == "CONTEXT":
            task = number(record, "task")
            if (task not in (1, 2) or task in contexts or
                    any(number(record, key) != 64 for key in
                        ("yield_requests", "signals", "nested"))):
                raise AssertionError("competing user context/signal matrix incomplete")
            contexts.add(task)
        elif kind == "CASE":
            seed, case = number(record, "seed"), number(record, "id")
            key = seed, case
            if key in cases or seed not in models or not 0 <= case < 12:
                raise AssertionError("invalid/duplicate directed IEEE case")
            value = bf16_dot(number(record, "a"), number(record, "b"))
            if ((number(record, "a"), number(record, "b")) != CASE_OPERANDS[case] or
                    value != number(record, "result") or value != number(record, "expected")):
                raise AssertionError("independent IEEE UART comparison failed")
            cases[key] = value
            numerical += 1
        elif kind == "RMS":
            seed = number(record, "seed")
            if seed in rms_seen or number(record, "lanes") != 256 or (
                    number(record, "scalar_seed") != 0xFFFFFFFFFFFFFF00 or
                    number(record, "result") != models[seed]["rms"]):
                raise AssertionError("independent RMS UART comparison failed")
            if pair_delta(0xC06) != 256:
                raise AssertionError("RMS MAC report not matched by hardware aliases")
            rms_seen.add(seed)
            numerical += 1
        elif kind == "SAMPLE":
            seed, precision, repeat = number(record, "seed"), record["kind"], number(record, "repeat")
            key = seed, precision
            if repeat == 0:
                cycle_reads = take(0xC00, 128)
                intervals = [((cycle_reads[i + 1] - cycle_reads[i]) & MASK64)
                             for i in range(0, 128, 2)]
                sample_boundary[key] = intervals
                if pair_delta(0xC06) != 8192:
                    raise AssertionError("benchmark MAC report not matched by actual aliases")
            if key not in sample_boundary or not 0 <= repeat < 32:
                raise AssertionError("unexpected benchmark sample order")
            scalar = number(record, "scalar_complete_cycles")
            vector = number(record, "vector_complete_cycles")
            observed = sample_boundary[key][2 * repeat:2 * repeat + 2]
            if observed != ([scalar, vector] if repeat % 2 == 0 else [vector, scalar]):
                raise AssertionError("printed timing sample differs from retired hardware reads")
            entries = samples.setdefault(key, {})
            if repeat in entries or not scalar or not vector:
                raise AssertionError("duplicate/empty matched cycle measurement")
            entries[repeat] = scalar, vector
            measured += 1
        elif kind == "BENCH":
            seed, precision = number(record, "seed"), record["kind"]
            key = seed, precision
            entries = samples.get(key, {})
            if key in benchmarks or set(entries) != set(range(32)):
                raise AssertionError("missing/duplicate 32-repetition benchmark")
            scalar, vector = (median([pair[i] for pair in entries.values()]) for i in (0, 1))
            if (number(record, "reduction") != 256 or number(record, "repetitions") != 32 or
                    number(record, "macs") != 8192 or scalar <= vector or
                    number(record, "scalar_complete_cycles") != scalar or
                    number(record, "vector_complete_cycles") != vector or
                    number(record, "speedup_numerator") != scalar or
                    number(record, "speedup_denominator") != vector or
                    number(record, "result") != models[seed][precision]):
                raise AssertionError("required numerical/median hardware speedup comparison failed")
            benchmarks[key] = {"scalar_cycles": scalar, "vector_cycles": vector}
            numerical += 1
        elif kind == "ARITH":
            key = number(record, "seed"), record["kind"]
            if (key in arithmetic or number(record, "excludes_loads") != 1 or
                    pair_delta(0xC00) !=
                    number(record, "vector_arithmetic_cycles")):
                raise AssertionError("arithmetic-only interval does not match hardware counter reads")
            arithmetic.add(key)
        elif kind == "RESULT":
            seed, precision = number(record, "seed"), record["kind"]
            position = number(record, "row"), number(record, "column")
            key = seed, precision, position
            if key in cells or number(record, "result") != models[seed]["matrices"][precision][position]:
                raise AssertionError("independent complete tensor cell comparison failed")
            cells[key] = number(record, "result")
            numerical += 1
        elif kind == "TILE":
            seed = number(record, "seed")
            if seed in tiles or number(record, "committed_macs") != 4608:
                raise AssertionError("tensor tile MAC comparison failed")
            if (pair_delta(0xC06) != 4608 or
                    pair_delta(0xC00) != number(record, "comparison_complete_cycles")):
                raise AssertionError("tensor tile measurements differ from actual hardware aliases")
            for precision, dimension in (("int8", 8), ("bf16", 4)):
                value = 14695981039346656037
                for row in range(dimension):
                    for column in range(dimension):
                        encoded = cells[(seed, precision, (row, column))]
                        for byte in encoded.to_bytes(8, "little"):
                            value = ((value ^ byte) * 1099511628211) & MASK64
                if number(record, precision + "_hash") != value:
                    raise AssertionError("tensor summary differs from independently checked cells")
            tiles.add(seed)
        elif kind == "CACHE":
            seed = number(record, "seed")
            if seed in cache_seen or record["selectors"] != "1,2,3,4":
                raise AssertionError("cache counter configuration mismatch")
            for address, key in ((0xC03, "l1_lookups"), (0xC04, "l1_hits"),
                                 (0xC05, "l2_lookups"), (0xC06, "l2_hits")):
                if pair_delta(address) != number(record, key):
                    raise AssertionError("cache counter report differs from actual user alias reads")
            if any(number(record, hit) > number(record, lookup) for hit, lookup in
                   (("l1_hits", "l1_lookups"), ("l2_hits", "l2_lookups"))):
                raise AssertionError("invalid demand cache hit-rate numerator")
            cache_seen.add(seed)
        elif kind == "DONE":
            milestones[kind] += 1
            if record.get("seeds") != "17,43,89" or any(
                    number(record, key) != 1 for key in
                    ("numerical", "context", "faults", "measured_speed")):
                raise AssertionError("incomplete genuine user completion record")
    expected_pairs = {(seed, precision) for seed in models for precision in ("int8", "bf16")}
    if (set(benchmarks) != expected_pairs or arithmetic != expected_pairs or
            rms_seen != set(models) or tiles != set(models) or cache_seen != set(models) or
            len(cases) != 36 or len(cells) != 240 or contexts != {1, 2} or
            any(count != 1 for count in milestones.values())):
        raise AssertionError("missing required observed user numerical/context records")
    if any(cursors[address] != len(values) for address, values in counter_values.items()):
        raise AssertionError("unexpected/unmatched actual user hardware counter reads")
    bf_compared = 0
    for line in (directory / "bf16-observed.txt").read_text().splitlines():
        a, b, actual = (int(value, 16) for value in line.split())
        if actual != bf16_dot(a, b):
            raise AssertionError("public custom BF16 result disagrees with exact rational reference")
        bf_compared += 1
    if bf_compared == 0:
        raise AssertionError("no public BF16 hardware comparisons")
    pids = [int(line.split()[1]) for line in (directory / "user-pids.txt").read_text().splitlines()]
    transitions = sum(a != b for a, b in zip(pids, pids[1:]))
    if len(set(pids)) < 3 or transitions < 4:
        raise AssertionError("no independently witnessed competing U tasks")
    syscalls = [int(line.split()[1]) for line in (directory / "user-ecalls.txt").read_text().splitlines()]
    if syscalls.count(124) < 128 or syscalls.count(101) < 128 or syscalls.count(139) < 256:
        raise AssertionError("scheduler/timer/signal return execution not independently witnessed")
    observed = json.loads((directory / "boot-observed.json").read_text())
    if not observed["u_custom"] or not observed["high_va_retired"]:
        raise AssertionError("user custom/Sv39 execution missing")
    return {"uart_numerical": numerical, "bf16_public_results": bf_compared,
            "matched_samples": measured, "benchmarks": [
                {"seed": seed, "kind": precision, **record}
                for (seed, precision), record in benchmarks.items()],
            "user_pid_count": len(set(pids)), "pid_transitions": transitions}
