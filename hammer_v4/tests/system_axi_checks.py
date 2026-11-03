#!/usr/bin/env python3
"""Cross-language checks of seeded AXI stimulus, not RTL boot acceptance."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_oracle import CHANNELS, SEEDS, stall


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    records = []
    commands = [
        ["g++", "-O2", "-std=c++17", "-Wall", "-Wextra", "-Werror",
         "tests/system_axi_probe.cpp", "-o", str(relative / "axi-probe")],
        [str(relative / "axi-probe")],
    ]
    for index, argv in enumerate(commands):
        record = {"argv": argv, "cwd": "."}
        records.append(record)
        with (out / f"{index}.stdout.log").open("wb") as so, (
            out / f"{index}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
        record["exit_code"] = result.returncode
        (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(f"AXI component command {index}: {relative}")
    draws, handshakes, writes, reads, coverage, rejections = {}, {}, {}, {}, {}, set()
    for line in (out / "1.stdout.log").read_text().splitlines():
        kind, *fields = line.split()
        if kind == "D":
            seed, channel, ordinal, beat, value = fields
            key = int(seed), channel, int(ordinal), int(beat)
            if key in draws or int(value) != stall(*key):
                raise AssertionError(f"C++/hashlib draw mismatch/duplicate: {line}")
            draws[key] = int(value)
        elif kind == "T":
            seed, transaction, channel, edge = fields
            key = int(seed), int(transaction), channel
            if key in handshakes:
                raise AssertionError(f"Duplicated handshake: {line}")
            handshakes[key] = int(edge)
        elif kind == "M":
            seed, transaction, edge, value = map(int, fields)
            if (seed, transaction) in writes:
                raise AssertionError(f"Duplicated RAM write: {line}")
            writes[seed, transaction] = edge, value
        elif kind == "V":
            seed, transaction, value = map(int, fields)
            if (seed, transaction) in reads:
                raise AssertionError(f"Duplicated RAM response: {line}")
            reads[seed, transaction] = value
        elif kind == "C":
            seed, *counts = map(int, fields)
            if seed in coverage or not all(counts):
                raise AssertionError(f"Missing AW/W ordering: {line}")
            coverage[seed] = counts
        elif kind == "X":
            if len(fields) != 1 or fields[0] in rejections:
                raise AssertionError(f"Invalid rejection: {line}")
            rejections.add(fields[0])
        else:
            raise AssertionError(f"Unexpected component output: {line}")
    wanted_draws = {
        (seed, channel, ordinal, beat)
        for seed in SEEDS for channel in CHANNELS for ordinal in range(256)
        for beat in (0, 1, 255)
    } | {(seed, channel, ordinal, 0) for seed in SEEDS for channel in CHANNELS
         for ordinal in (4294967295, (1 << 64) - 1)}
    if set(draws) != wanted_draws:
        raise AssertionError("Draw comparison coverage mismatch")

    expected_handshakes, expected_writes, expected_reads = {}, {}, {}
    coincident_reads, held_responses = 0, 0
    for seed in SEEDS:
        first, memory = 0, 0x0706050403020100
        for transaction in range(96):
            aw = first + (16 if transaction % 3 == 1 else 0) + \
                stall(seed, "aw", transaction)
            w = first + (16 if transaction % 3 == 0 else 0) + \
                stall(seed, "w", transaction)
            ar = first + transaction % 4 * 7 + stall(seed, "ar", transaction)
            b_offer = max(aw, w) + stall(seed, "b", transaction) + 1
            r_offer = ar + stall(seed, "r", transaction) + 1
            b = max(b_offer, first + 48 + transaction % 9)
            r = max(r_offer, first + 48 + transaction % 7)
            for channel, edge in (("aw", aw), ("w", w), ("ar", ar),
                                  ("b-offer", b_offer), ("r-offer", r_offer),
                                  ("b", b), ("r", r)):
                expected_handshakes[seed, transaction, channel] = edge
            data = 0xFEDCBA9876543210 ^ transaction << 32
            strobes = (transaction * 37 + 0x55) & 255
            mask = sum(255 << (8 * lane) for lane in range(8) if strobes >> lane & 1)
            updated = memory & ~mask | data & mask
            expected_writes[seed, transaction] = max(aw, w), updated
            expected_reads[seed, transaction] = memory if ar <= max(aw, w) else updated
            memory = updated
            coincident_reads += int(ar == max(aw, w))
            held_responses += int(b > b_offer) + int(r > r_offer)
            first = max(b, r) + 1
    if handshakes != expected_handshakes or writes != expected_writes or reads != expected_reads:
        raise AssertionError("Independent AXI edges, pre-edge RAM snapshots or byte strobes mismatch")
    expected_rejections = {f"{channel}-{field}" for channel in ("aw", "w", "ar")
                           for field in ("valid", "payload")} | {
        "skipped-edge", "bad-write-size", "bad-read-size",
    }
    if rejections != expected_rejections or set(coverage) != set(SEEDS) or \
            not coincident_reads or held_responses != 576:
        raise AssertionError("AXI rejection/simultaneity/backpressure coverage missing")
    (out / "summary.json").write_text(json.dumps({
        "scope": "C++ stimulus versus independent Python rules; no RTL executed",
        "hashlib_draw_comparisons": len(draws),
        "transactions": len(writes) + len(reads),
        "handshake_edge_comparisons": len(handshakes),
        "coincident_read_write_preedge_snapshots": coincident_reads,
        "responses_held_under_backpressure": held_responses,
        "ordering_coverage": coverage, "rejected_protocol_defects": sorted(rejections),
    }, indent=2) + "\n")
    print(f"COMPARED AXI draws={len(draws)} edges={len(handshakes)} "
          f"transactions={len(writes) + len(reads)}; stimulus-only, not an RTL boot")


if __name__ == "__main__":
    main()
