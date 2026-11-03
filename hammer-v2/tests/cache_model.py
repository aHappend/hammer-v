"""Direct-mapped cache transaction oracle using byte memory and public traffic."""

import copy


class CacheOracle:
    def __init__(self, lines, words, readonly):
        self.capacity = lines
        self.readonly = readonly
        self.base = 0 if readonly else 0x10000000
        self.backing = bytearray((i * 37 + 11) & 255
                                 for i in range(words * (4 if readonly else 8)))
        self.lines = {}
        self.counts = {key: 0 for key in (
            "read_hits", "write_hits", "misses", "dirty_evictions", "clean_evictions",
            "refill_beats", "writeback_beats", "errors", "maintenance",
            "reset_outstanding", "responses", "backing_requests", "invalid_requests")}
        self.counts.update({f"command_{command}": 0 for command in range(4)})
        self.pending = None

    def prepare(self, cmd, address, data, strobe, fail_n):
        if self.pending is not None:
            raise AssertionError("oracle received overlapping CPU requests")
        lines = copy.deepcopy(self.lines)
        traffic = []
        result = 0
        error = 0
        hit = False
        deltas = {}

        def count(name):
            deltas[name] = deltas.get(name, 0) + 1

        count(f"command_{cmd}")

        def transfer(write, addr, value=0):
            failed = int(fail_n > 0 and len(traffic) + 1 == fail_n)
            traffic.append((int(write), addr, value, 255 if write else 0, failed))
            return not failed

        def writeback(line):
            for offset in range(0, 32, 8):
                addr = line["base"] + offset
                if addr < self.base + len(self.backing):
                    value = int.from_bytes(line["bytes"][offset:offset + 8], "little")
                    if not transfer(True, addr, value):
                        return False
            line["dirty"] = False
            return True

        if cmd >= 2:
            count("maintenance")
            for index in sorted(lines):
                line = lines[index]
                if line["dirty"] and not writeback(line):
                    error = 1
                    break
                if cmd == 3:
                    lines[index] = None
            lines = {k: v for k, v in lines.items() if v is not None}
        elif not self.base <= address < self.base + len(self.backing) or (
                self.readonly and (cmd == 1 or address & 3)):
            error = 1
            count("invalid_requests")
        else:
            base = address & ~31
            index = (base // 32) % self.capacity
            line = lines.get(index)
            hit = line is not None and line["base"] == base
            if hit:
                count("write_hits" if cmd == 1 else "read_hits")
            else:
                count("misses")
                if line is not None:
                    count("dirty_evictions" if line["dirty"] else "clean_evictions")
                    if line["dirty"] and not writeback(line):
                        error = 1
                if not error:
                    lines.pop(index, None)
                    contents = bytearray(32)
                    for offset in range(0, 32, 8):
                        addr = base + offset
                        if addr < self.base + len(self.backing):
                            if not transfer(False, addr):
                                error = 1
                                break
                            off = addr - self.base
                            beat = self.backing[off:off + 8]
                            contents[offset:offset + len(beat)] = beat
                    if not error:
                        line = {"base": base, "bytes": contents, "dirty": False}
                        lines[index] = line
            if not error:
                off = address - base
                if cmd == 0:
                    off = (off // (4 if self.readonly else 8)) * (4 if self.readonly else 8)
                    result = int.from_bytes(line["bytes"][off:off + (4 if self.readonly else 8)], "little")
                else:
                    beat = (off // 8) * 8
                    for lane in range(8):
                        if strobe & (1 << lane):
                            line["bytes"][beat + lane] = (data >> (8 * lane)) & 255
                    line["dirty"] |= bool(strobe)
        self.pending = {"traffic": traffic, "consumed": 0, "lines": lines,
                        "result": result, "error": error, "hit": hit, "deltas": deltas}

    def backing_request(self, observed):
        pending = self.pending
        if pending is None or pending["consumed"] >= len(pending["traffic"]):
            raise AssertionError(f"unexpected/duplicate backing request: {observed}")
        expected = pending["traffic"][pending["consumed"]]
        if observed != expected:
            raise AssertionError(f"backing expected={expected}, observed={observed}")
        pending["consumed"] += 1
        write, address, data, strobe, error = observed
        self.counts["backing_requests"] += 1
        self.counts["writeback_beats" if write else "refill_beats"] += 1
        if write and not error:
            off = address - self.base
            for lane in range(8):
                if off + lane < len(self.backing) and strobe & (1 << lane):
                    self.backing[off + lane] = (data >> (lane * 8)) & 255

    def response(self, data, error, latency):
        pending = self.pending
        if pending is None:
            raise AssertionError("response without a CPU request")
        if (data, error) != (pending["result"], pending["error"]):
            raise AssertionError(f"CPU response expected={(pending['result'], pending['error'])}, "
                                 f"observed={(data, error)}")
        if pending["consumed"] != len(pending["traffic"]):
            raise AssertionError("CPU response before required backing traffic completed")
        if pending["hit"] and latency != 1:
            raise AssertionError(f"hit latency expected=1, observed={latency}")
        self.lines = pending["lines"]
        for name, value in pending["deltas"].items():
            self.counts[name] += value
        self.counts["responses"] += 1
        self.counts["errors"] += error
        self.pending = None

    def reset(self):
        if self.pending is None:
            raise AssertionError("reset case did not interrupt a transaction")
        self.lines = {}
        self.pending = None
        self.counts["reset_outstanding"] += 1


def compare_cache(path, vectors, lines, words, readonly):
    oracle = CacheOracle(lines, words, readonly)
    tx = 0
    done = False
    with path.open() as stream:
        for raw in stream:
            fields = raw.split()
            kind = fields[0]
            try:
                if kind == "Q":
                    if oracle.pending is not None:
                        raise AssertionError("overlapping transaction")
                    tx += 1
                    actual = (int(fields[2]), int(fields[3], 16), int(fields[4], 16),
                              int(fields[5], 16), int(fields[6]), int(fields[7]))
                    if int(fields[1]) != tx or actual != tuple(vectors[tx - 1]):
                        raise AssertionError(f"stimulus mismatch for transaction {tx}")
                    oracle.prepare(*actual[:5])
                elif kind == "B":
                    if int(fields[1]) != tx:
                        raise AssertionError("backing transaction identity mismatch")
                    oracle.backing_request((int(fields[2]), int(fields[3], 16),
                                            int(fields[4], 16), int(fields[5], 16),
                                            int(fields[6])))
                elif kind == "R":
                    if int(fields[1]) != tx:
                        raise AssertionError("response identity mismatch")
                    oracle.response(int(fields[2], 16), int(fields[3]),
                                    int(fields[5]) - int(fields[4]))
                elif kind == "Z":
                    if int(fields[1]) != tx or not vectors[tx - 1][5]:
                        raise AssertionError("unexpected reset")
                    oracle.reset()
                elif kind == "S":
                    oracle.counts["memory_stalled_edges"] = int(fields[1])
                    oracle.counts["response_stalled_edges"] = int(fields[2])
                    oracle.counts["idle_isolation_edges"] = int(fields[3])
                    if oracle.counts["idle_isolation_edges"] != 3 * len(vectors):
                        raise AssertionError("idle speculative-read isolation checks missing")
                elif kind == "DONE":
                    done = True
                    if int(fields[1]) != len(vectors) or tx != len(vectors) or oracle.pending:
                        raise AssertionError("incomplete transaction conservation")
                else:
                    raise AssertionError(f"unknown cache event: {kind}")
            except AssertionError as error:
                raise AssertionError(f"transaction {tx}, event {raw.strip()}: {error}") from error
    if not done:
        raise AssertionError("missing cache completion record")
    return oracle.counts


def compare_integrated_cache(path, lines, image, readonly):
    word_size = 4 if readonly else 8
    oracle = CacheOracle(lines, len(image) // word_size, readonly)
    oracle.backing[:] = image
    accepted_edge = None
    backing_response = None
    backing_edge = None
    complete = False
    runtime = False
    pending_command = None
    runtime_commands = {f"runtime_command_{command}": 0 for command in range(4)}
    with path.open() as stream:
        for raw in stream:
            parts = raw.split()
            kind, edge = parts[0], int(parts[1])
            if kind not in ("Q", "B", "V", "R", "DONE") or complete:
                raise AssertionError("invalid integrated cache event")
            try:
                if kind == "Q":
                    fields = (int(parts[2]), int(parts[3], 16), int(parts[4], 16),
                              int(parts[5], 16))
                    accepted_edge = edge
                    oracle.prepare(*fields, 0)
                    pending_command = fields[0]
                    runtime |= pending_command < 2
                elif kind == "B":
                    write, address, data, strobe = (int(parts[2]), int(parts[3], 16),
                                                    int(parts[4], 16), int(parts[5], 16))
                    offset = address - oracle.base
                    expected = int.from_bytes(oracle.backing[offset:offset + 8], "little")
                    if backing_response is not None:
                        raise AssertionError("multiple outstanding backing requests")
                    backing_response = (expected, 0)
                    backing_edge = edge
                    oracle.backing_request((write, address, data, strobe, 0))
                elif kind == "V":
                    fields = (int(parts[2], 16), int(parts[3]))
                    if fields != backing_response:
                        raise AssertionError(f"backing response expected={backing_response}, observed={fields}")
                    if edge - backing_edge != 2:
                        raise AssertionError(f"registered backing response acceptance latency "
                                             f"expected=2, observed={edge - backing_edge}")
                    backing_response = None
                    backing_edge = None
                elif kind == "R":
                    data, error, first_response = int(parts[2], 16), int(parts[3]), int(parts[4])
                    if backing_response is not None or accepted_edge is None:
                        raise AssertionError("premature cache response")
                    oracle.response(data, error, first_response - accepted_edge)
                    if runtime:
                        runtime_commands[f"runtime_command_{pending_command}"] += 1
                    pending_command = None
                    accepted_edge = None
                else:
                    if parts[2:] != ["0"] or oracle.pending or backing_response is not None:
                        raise AssertionError("cache channel did not drain before completion")
                    complete = True
            except AssertionError as error:
                raise AssertionError(f"integrated cache edge {edge}, event {kind}: {error}") from error
    if not complete or oracle.counts["responses"] == 0:
        raise AssertionError("missing integrated cache comparisons/completion")
    return {**oracle.counts, **runtime_commands}
