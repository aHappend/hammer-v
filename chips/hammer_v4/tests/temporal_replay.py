#!/usr/bin/env python3
"""Defect sensitivity of read-value and interrupt-timestamp comparisons.

These are directed clock-contract replays, not the full Linux event comparator.
No observed time value or timestamp changes the frozen rules or expectations.
"""

import hashlib
import json


def compare(records, expected):
    interrupts = reads = 0
    previous = -1
    for kind, edge, value in records:
        if not 0 <= edge < expected["bound"] or edge <= previous:
            raise AssertionError("TEMPORAL_REPLAY_ORDER_COMPARISON")
        previous = edge
        if kind == "I":
            deadlines = expected["machine_timer_edges"]
            if interrupts >= len(deadlines) or edge != deadlines[interrupts] or value != 3:
                raise AssertionError("TEMPORAL_REPLAY_INTERRUPT_COMPARISON")
            interrupts += 1
        elif kind == "R":
            # With c=0 at the first released edge, reset mtime=0 and no
            # workload mtime writes, the CSR snapshot is the pre-edge c.
            if value != edge:
                raise AssertionError("TEMPORAL_REPLAY_READ_COMPARISON")
            reads += 1
        else:
            raise AssertionError("TEMPORAL_REPLAY_KIND_COMPARISON")
    if interrupts != len(expected["machine_timer_edges"]) or reads != expected["time_read_count"]:
        raise AssertionError("TEMPORAL_REPLAY_COVERAGE_COMPARISON")
    return {"machine_interrupts": interrupts, "time_reads": reads}


def verify_run(run):
    out = run / "replay"
    out.mkdir(exist_ok=False)
    paths = [run / "expectations.json", run / "expected-uart.bin"]
    hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    expected = json.loads(paths[0].read_text())
    records = []
    for line in (run / "temporal-ledger.txt").read_text().splitlines():
        kind, edge, value = line.split()
        records.append((kind, int(edge), int(value)))
    control = compare(records, expected)
    results = [{"case": "unchanged", "outcome": "compared", **control}]
    for name, kind, field, marker in (
        ("read-value", "R", 2, "TEMPORAL_REPLAY_READ_COMPARISON"),
        ("interrupt-edge", "I", 1, "TEMPORAL_REPLAY_INTERRUPT_COMPARISON"),
    ):
        mutated = list(records)
        index = next(index for index, record in enumerate(mutated) if record[0] == kind)
        changed = list(mutated[index])
        changed[field] += 1
        mutated[index] = tuple(changed)
        (out / f"{name}.txt").write_text(
            "".join(f"{kind} {edge} {value}\n" for kind, edge, value in mutated)
        )
        try:
            compare(mutated, expected)
        except AssertionError as error:
            if str(error) != marker:
                raise AssertionError(f"Replay {name} failed for wrong reason: {error}") from error
            results.append({"case": name, "outcome": "rejected", "assertion": str(error),
                            "record_index": index, "before": records[index],
                            "after": mutated[index]})
        else:
            raise AssertionError(f"Comparator accepted {name} replay corruption")
    if hashes != {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}:
        raise AssertionError("Replay changed immutable expectations")
    (out / "summary.json").write_text(json.dumps({
        "scope": "directed temporal comparator, not full Linux timed acceptance",
        "expected_sha256": hashes, "cases": results,
    }, indent=2) + "\n")
