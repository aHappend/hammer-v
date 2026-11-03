#!/usr/bin/env python3
"""Freeze a bounded complete firmware prediction before public-pin comparison.

Every firmware retirement (not a sampled subset), traps, and all serialized UART
bytes must agree. This preparation milestone does not certify Linux execution.
"""

import argparse
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_core import Core
from system_oracle import Clock, MASK, Phase, SEEDS, canonical_json, digest, load_images
from system_protocol import event_line


def prediction(seed, images, out, goal="firmware", prefix_retirements=150000):
    clock = Clock()
    events, transitions, handoff = [], [], []
    milestones = {}

    def retire(edge, ordinal, commit, registers, memory):
        events.append(event_line(
            "R", edge, ordinal, commit.pc, commit.instruction, commit.next_pc,
            commit.privilege, int(bool(commit.rd)), commit.rd,
            commit.value if commit.rd else 0, memory.valid, memory.write, memory.address,
            memory.mask, memory.wdata, memory.rdata,
            registers[10], registers[11], registers[12], registers[17],
        ))
        if commit.instruction == 0x30200073 and commit.next_pc == 0x80200000:
            if commit.privilege != 3 or registers[10:12] != (0, 0x87E00000):
                raise AssertionError("Independent firmware handoff ABI")
            handoff.append(edge)
            if goal in ("firmware", "interactions"):
                core.stopped = True
        if goal == "interactions":
            if commit.instruction & 127 == 0x2F:
                milestones.setdefault("atomics", []).append((commit.instruction >> 27,
                                                             commit.value))
            if commit.instruction == 0x10500073:
                milestones["wfi_next_pc"] = commit.next_pc
        if core.machine.csrs[0x180] >> 60 == 8:
            milestones.setdefault("satp_sv39", edge)
        if commit.instruction & 0xFE007FFF == 0x12000073 and "satp_sv39" in milestones:
            milestones.setdefault("sfence_after_satp", edge)
        if goal == "sv39" and "sfence_after_satp" in milestones and \
                core.platform.transmitter.temt:
            core.stopped = True
            milestones["stop_edge"] = edge
        if goal == "kernel-prefix" and ordinal >= prefix_retirements and \
                core.platform.transmitter.temt:
            core.stopped = True
            milestones["stop_edge"] = edge

    def trap(edge, record, registers):
        pc, cause, tval, target, interrupt = record
        events.append(event_line("T", edge, pc, cause | (int(interrupt) << 63),
                                 tval, target, int(interrupt),
                                 registers[10], registers[11], registers[17]))
        if goal == "interactions":
            milestones.setdefault("traps", []).append(record)

    core = Core(clock, seed, images, retirement=retire, trap=trap,
                wire=lambda edge, level: transitions.append((edge, level)))
    started = time.monotonic()
    limit = 16777216 if goal in ("sv39", "kernel-prefix") else 500000
    heartbeat = time.monotonic()

    def progress(edge):
        nonlocal heartbeat
        if time.monotonic() - heartbeat >= 25:
            print(f"CORE_PREDICTION_ACTIVE seed={seed} edge={edge} "
                  f"retired={core.machine.commits} pc={core.machine.pc:x}", flush=True)
            heartbeat = time.monotonic()
        if not core.stopped and edge + 100000 < limit:
            clock.schedule(edge + 100000, Phase.OBSERVE, lambda: progress(edge + 100000))
    clock.schedule(0, Phase.OBSERVE, lambda: progress(0))
    clock.run(limit - 1)
    if len(handoff) != 1:
        raise AssertionError(f"Firmware prediction did not reach mret: recent={list(core.recent)} "
                             f"queue={list(core.queue)} stages="
                             f"{(core.decode, core.execute, core.mem, core.writeback)}")
    if goal in ("sv39", "kernel-prefix") and "stop_edge" not in milestones:
        raise AssertionError(f"Compact Sv39 prediction not complete: {milestones}; "
                             f"recent={list(core.recent)}")
    if goal == "interactions" and (
        milestones.get("atomics") != [(2, 0), (3, 0), (2, 7), (3, 1)] or
        milestones.get("traps") != [
            (0x80000038, 2, 0x7FF024F3, 3, False),
            (milestones.get("wfi_next_pc"), 7, 0, 3, True)
        ]
    ):
        raise AssertionError(f"Independent LR/SC/CSR/WFI/timer semantics: {milestones}")
    uart = bytearray()
    line, position = 1, 0
    while position < len(transitions):
        edge, line = transitions[position]
        position += 1
        if line:
            continue
        first = edge
        bits = []
        for bit in range(10):
            sample = first + 8 + 16 * bit
            while position < len(transitions) and transitions[position][0] <= sample:
                line = transitions[position][1]
                position += 1
            bits.append(line)
        if bits[0] or not bits[9]:
            raise AssertionError("Independent UART model framing")
        uart.append(sum(bits[bit + 1] << bit for bit in range(8)))
        while position < len(transitions) and transitions[position][0] < first + 160:
            position += 1
    if core.platform.transmitter.active or core.platform.transmitter.queue or \
            not uart and goal != "interactions":
        raise AssertionError("Independent firmware UART did not completely serialize")
    out.mkdir()
    (out / "expected-events.txt").write_text("".join(events), encoding="ascii")
    (out / "expected-uart.bin").write_bytes(uart)
    (out / "counts.txt").write_text(f"{len(events)} {len(uart)}\n", encoding="ascii")
    result = {
        "seed": seed, "scope": f"bounded {goal} only; not Linux acceptance",
        "handoff_edge": handoff[0],
        "final_edge": max(milestones.get("stop_edge", handoff[0]),
                          transitions[-1][0] + 16 if transitions else 0),
        "milestones": milestones,
        "images": {name: {"address": address, "bytes": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()}
                   for name, address, data in images},
        "events": len(events), "uart_bytes": len(uart),
        "callbacks": clock.callbacks, "prediction_seconds": time.monotonic() - started,
        "files": {name: digest(out / name) for name in (
            "expected-events.txt", "expected-uart.bin", "counts.txt")},
    }
    (out / "prediction.json").write_bytes(canonical_json(result))
    return result


def interaction_image():
    """A fixed ISA-encoded fixture, independent of the delivered firmware."""
    def immediate(value, rs1, funct3, rd, opcode=0x13):
        return (value & 4095) << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode

    def csr(address, rs1, funct3=1, rd=0):
        return address << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | 0x73

    def atomic(operation, rs2=0):
        return operation << 27 | rs2 << 20 | 1 << 15 | 3 << 12 | \
            (3 if operation == 2 else 4) << 7 | 0x2F

    words = [
        immediate(1, 0, 0, 1), immediate(31, 1, 1, 1), 0x00001437,
        8 << 20 | 1 << 15 | 1 << 7 | 0x33,
        immediate(7, 0, 0, 2), atomic(2), atomic(3, 2), atomic(2),
        csr(0xC01, 0, 2, 5), atomic(3, 2),
        immediate(1, 0, 0, 8), immediate(31, 8, 1, 8),
        immediate(256, 8, 0, 8), csr(0x305, 8),
        csr(0x7FF, 0, 2, 9),
        0x02004337, csr(0xC01, 0, 2, 7), immediate(1000, 7, 0, 7),
        7 << 20 | 6 << 15 | 3 << 12 | 0x23,
        immediate(128, 0, 0, 8), csr(0x304, 8), csr(0x300, 8, 6), 0x10500073,
        immediate(1, 0, 0, 8), immediate(11, 8, 1, 8), csr(0x300, 8),
        immediate(1, 0, 0, 8), immediate(31, 8, 1, 8), 0x002004B7,
        9 << 20 | 8 << 15 | 8 << 7 | 0x33, csr(0x341, 8), 0x30200073,
    ]
    words += [0x13] * (64 - len(words))
    words += [
        csr(0x342, 0, 2, 20), csr(0x341, 0, 2, 21),
        20 << 15 | 4 << 12 | 6 << 8 | 0x63,
        immediate(4, 21, 0, 21), csr(0x341, 21), csr(0x304, 0), 0x30200073,
    ]
    return struct.pack("<" + "I" * len(words), *words)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--predict-only", action="store_true")
    parser.add_argument("--goal", choices=("firmware", "sv39", "interactions", "kernel-prefix"),
                        default="firmware")
    parser.add_argument("--prefix-retirements", type=int, default=150000)
    parser.add_argument("--seed", type=int, choices=SEEDS, action="append")
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest, images = load_images(ROOT, args.manifest)
    if args.goal == "interactions":
        firmware = out / "interaction.bin"
        firmware.write_bytes(interaction_image())
        manifest["images"]["fw_jump.bin"]["path"] = firmware.relative_to(ROOT).as_posix()
        images = (("fw_jump.bin", 0x80000000, firmware.read_bytes()), *images[1:])
    predictions = []
    if args.prefix_retirements < 150000:
        parser.error("--prefix-retirements must extend beyond the retained Sv39 prefix")
    seeds = args.seed or SEEDS
    for seed in seeds:
        result = prediction(seed, images, out / f"seed-{seed}", args.goal,
                            args.prefix_retirements)
        predictions.append(result)
        print(f"FROZEN {args.goal} seed={seed} events={result['events']} "
              f"edges={result['final_edge']} seconds={result['prediction_seconds']:.3f}", flush=True)
    (out / "summary.json").write_bytes(canonical_json({
        "scope": "firmware preparation, not full-system acceptance",
        "manifest_sha256": digest(ROOT / args.manifest), "predictions": predictions,
        "dut_execution": False,
    }))
    if args.predict_only:
        return
    records = []

    def run(argv, name):
        record = {"argv": argv, "cwd": ".", "started_unix": time.time()}
        records.append(record)
        try:
            with (out / f"{name}.stdout.log").open("wb") as so, (
                out / f"{name}.stderr.log"
            ).open("wb") as se:
                result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
            record["exit_code"] = result.returncode
            if result.returncode:
                raise AssertionError(f"Frozen core {name} failed: {relative}/{name}.stderr.log")
        finally:
            record["ended_unix"] = time.time()
            (out / "commands.json").write_bytes(canonical_json(records))

    obj = relative / "compile-obj"
    try:
        run([
            "verilator", "-O3", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
            "--top-module", "hammer_v4_top", "--Mdir", obj.as_posix(),
            "-CFLAGS", "-O3 -std=c++17",
            *[path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "rtl").glob("*.sv"))],
            str(Path(*([".."] * len(obj.parts))) / "tests/system_core_probe.cpp"),
            "-MAKEFLAGS", "OPT_FAST=-O3",
        ], "compile")
        binary = relative / "core-probe"
        shutil.copyfile(ROOT / obj / "Vhammer_v4_top", ROOT / binary)
        (ROOT / binary).chmod(0o755)
        for result in predictions:
            seed = result["seed"]
            directory = relative / f"seed-{seed}"
            actual = directory / "rtl"
            (ROOT / actual).mkdir()
            run([
                binary.as_posix(),
                *[manifest["images"][name]["path"] for name, _, _ in images],
                directory.as_posix(), actual.as_posix(), str(seed), str(result["final_edge"]),
            ], f"seed-{seed}")
            if any(digest(ROOT / directory / name) != old
                   for name, old in result["files"].items()):
                raise AssertionError("Frozen firmware expectations changed during DUT execution")
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in (ROOT / obj).glob(pattern):
                path.unlink()
    (out / "summary.json").write_bytes(canonical_json({
        "scope": "firmware preparation, not full-system acceptance",
        "manifest_sha256": digest(ROOT / args.manifest), "predictions": predictions,
        "dut_execution": True, "all_comparisons_passed": True,
    }))
    print(f"COMPARED independently frozen {args.goal} retirement/UART streams, seeds {seeds}")


if __name__ == "__main__":
    main()
