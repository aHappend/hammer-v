#!/usr/bin/env python3
"""Exercise the untimed ISA reference on hand-derived cases and actual images."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rv64_reference import ArchitecturalTrap, Machine, ReferencePlatform, install_trampoline


def unit_checks():
    platform = ReferencePlatform()
    comparisons = 0

    def operation(opcode, funct3, funct7, lhs, rhs, expected):
        nonlocal comparisons
        machine = Machine(platform)
        machine.registers[5], machine.registers[6] = lhs, rhs
        instruction = funct7 << 25 | 6 << 20 | 5 << 15 | funct3 << 12 | 7 << 7 | opcode
        struct.pack_into("<I", platform.rom, 0, instruction)
        result = machine.execute()
        if result.value != expected or machine.registers[7] != expected or machine.pc != 4:
            raise AssertionError(f"Reference instruction {instruction:08x}: {result}")
        comparisons += 1

    maximum = (1 << 64) - 1
    for fields in (
        (0x33, 0, 0, maximum, 1, 0), (0x33, 0, 0x20, 0, 1, maximum),
        (0x33, 2, 0, maximum, 0, 1), (0x33, 3, 0, maximum, 0, 0),
        (0x33, 1, 0, 1, 63, 1 << 63), (0x33, 5, 0, 1 << 63, 63, 1),
        (0x33, 5, 0x20, 1 << 63, 63, maximum),
        (0x3B, 0, 0, 0x7FFFFFFF, 1, 0xFFFFFFFF80000000),
        (0x3B, 0, 0x20, 0xFFFFFFFF00000000, 1, maximum),
        (0x3B, 5, 0, maximum, 1, 0x7FFFFFFF),
        (0x3B, 5, 0x20, 0x80000000, 1, 0xFFFFFFFFC0000000),
        (0x33, 0, 1, maximum, 2, maximum - 1),
        (0x33, 1, 1, maximum, 2, maximum),
        (0x33, 2, 1, maximum, maximum, maximum),
        (0x33, 3, 1, maximum, maximum, maximum - 1),
        (0x33, 4, 1, (1 << 64) - 7, 3, (1 << 64) - 2),
        (0x33, 6, 1, (1 << 64) - 7, 3, maximum),
        (0x33, 4, 1, 1 << 63, maximum, 1 << 63),
        (0x33, 6, 1, 1 << 63, maximum, 0),
        (0x33, 4, 1, 7, 0, maximum), (0x33, 6, 1, 7, 0, 7),
        (0x3B, 4, 1, 0x80000000, maximum, 0xFFFFFFFF80000000),
        (0x3B, 5, 1, maximum, 2, 0x7FFFFFFF),
        (0x3B, 7, 1, maximum, 2, 1),
    ):
        operation(*fields)
    for privilege, cause in ((0, 8), (1, 9), (3, 11)):
        machine = Machine(platform)
        machine.privilege = privilege
        struct.pack_into("<I", platform.rom, 0, 0x00000073)
        try:
            machine.execute()
        except ArchitecturalTrap as trap:
            if (trap.cause, trap.tval) != (cause, 0):
                raise AssertionError("Reference ECALL cause/tval") from trap
            comparisons += 1
        else:
            raise AssertionError("Reference ECALL unexpectedly retired")
    for word in (0xFFFFFFFF, 0x00000000, 0x0200103B, 0x40001033):
        machine = Machine(platform)
        struct.pack_into("<I", platform.rom, 0, word)
        try:
            machine.execute()
        except ArchitecturalTrap as trap:
            if (trap.cause, trap.tval) != (2, word):
                raise AssertionError("Reference illegal instruction cause/tval") from trap
            comparisons += 1
        else:
            raise AssertionError(f"Reserved reference instruction accepted: {word:08x}")
    return comparisons


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    units = unit_checks()
    command = [sys.executable, "tests/firmware_checks.py", "--manifest", args.manifest,
               "--out", (relative / "payload").as_posix(), "--generate-only"]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
    (out / "generate.stdout.log").write_bytes(result.stdout)
    (out / "generate.stderr.log").write_bytes(result.stderr)
    if result.returncode:
        raise AssertionError("Reference payload generation failed")
    manifest = json.loads((out / "payload/image-manifest.json").read_text())
    platform = ReferencePlatform()
    install_trampoline(platform)
    for name, address in (("fw_jump.bin", 0x80000000), ("Image", 0x80200000),
                          ("hammer-v4.dtb", 0x87E00000)):
        image = manifest["images"][name]
        path = ROOT / image["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != image["sha256"]:
            raise AssertionError(f"Reference image hash mismatch: {name}")
        platform.load_image(path, address)
    machine = Machine(platform)
    expected_uart = (out / "payload/expected-uart.bin").read_bytes()
    expectations = json.loads((out / "payload/expectations.json").read_text())
    expected_events = expectations["events"]
    events = []
    checked_traps = 0
    complete = False
    try:
        for iteration in range(500000):
            commit = machine.step()
            while checked_traps < len(machine.traps):
                pc, cause, tval, target, interrupt = machine.traps[checked_traps]
                checked_traps += 1
                if not interrupt and cause != 9:
                    events.append({"kind": "fault", "cause": cause, "tval": tval, "target": target})
            if commit and commit.memory:
                kind, address, width, value = commit.memory
                if kind == "store" and address in (0x80310000, 0x4000B000):
                    if width != 8:
                        raise AssertionError("Reference signature store width")
                    events.append({"kind": "signature", "id": value, "address": address})
            if events != expected_events[:len(events)]:
                raise AssertionError(f"Reference architectural event {len(events) - 1}")
            if len(platform.uart) > len(expected_uart) or \
                    platform.uart != expected_uart[:len(platform.uart)]:
                raise AssertionError(f"Reference functional UART byte {len(platform.uart) - 1}")
            if platform.uart == expected_uart:
                if events != expected_events or machine.registers[27] != 12:
                    raise AssertionError("Reference missing directed architectural events")
                complete = True
                break
        if not complete:
            raise AssertionError(
                f"Reference instruction bound, pc={machine.pc:#x}, "
                f"priv={machine.privilege}, last_traps={machine.traps[-4:]}"
            )
    finally:
        (out / "functional-uart.bin").write_bytes(platform.uart)
        (out / "events.json").write_text(json.dumps(events, indent=2) + "\n")
        (out / "last-state.json").write_text(json.dumps({
            "pc": machine.pc, "privilege": machine.privilege,
            "registers": machine.registers, "csrs": machine.csrs,
            "commits": machine.commits, "functional_ticks": platform.ticks,
            "last_traps": machine.traps[-32:],
        }, indent=2) + "\n")
    summary = {
        "unit_comparisons": units, "directed_events": len(events),
        "functional_uart_bytes": len(platform.uart), "commits": machine.commits,
        "functional_ticks": platform.ticks,
        "timed_full_system_oracle": False,
        "scope": "untimed ISA, actual firmware and compact directed payload",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
