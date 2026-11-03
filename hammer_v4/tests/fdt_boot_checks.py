#!/usr/bin/env python3
"""Verify real firmware rejects malformed in-memory FDT before S-mode entry."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from firmware_checks import PREFIX


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
    command = [sys.executable, "tests/firmware_checks.py", "--manifest", args.manifest,
               "--out", (relative / "control").as_posix()]
    with (out / "control.stdout.log").open("wb") as so, (
        out / "control.stderr.log"
    ).open("wb") as se:
        control = subprocess.run(command, cwd=ROOT, stdout=so, stderr=se, check=False)
    if control.returncode:
        raise AssertionError("Malformed FDT suite unchanged control failed")
    manifest = json.loads((ROOT / args.manifest).read_text())
    paths = {name: ROOT / image["path"] for name, image in manifest["images"].items()}
    for name in ("fw_jump.bin", "Image", "hammer-v4.dtb"):
        if hashlib.sha256(paths[name].read_bytes()).hexdigest() != \
                manifest["images"][name]["sha256"]:
            raise AssertionError(f"Original FDT suite image identity: {name}")
    original = paths["hammer-v4.dtb"].read_bytes()
    cases = (
        ("bad-magic", 0, 0, "FDT magic"),
        ("short-header", 4, 39, "FDT bounds/version"),
        ("reserved-overflow", 4, 0x200001, "FDT bounds/version"),
        ("structure-bounds", 8, len(original) + 4, "FDT bounds/version"),
        ("structure-alignment", 8, 41, "FDT bounds/version"),
        ("strings-bounds", 12, len(original) + 1, "FDT bounds/version"),
        ("reservation-alignment", 16, 41, "FDT bounds/version"),
        ("reservation-bounds", 16, len(original) - 8, "FDT bounds/version"),
        ("version", 20, 16, "FDT bounds/version"),
        ("compatible-version", 24, 18, "FDT bounds/version"),
        ("strings-overflow", 32, 0xFFFFFFFF, "FDT bounds/version"),
        ("structure-overflow", 36, 0xFFFFFFFF, "FDT bounds/version"),
    )
    records = [{"name": "unchanged-control", "argv": command, "exit_code": 0}]
    for name, offset, value, error in cases:
        directory = out / name
        directory.mkdir()
        blob = bytearray(original)
        struct.pack_into(">I", blob, offset, value)
        (directory / "malformed.dtb").write_bytes(blob)
        expected = PREFIX.split(b"\r\n", 1)[0] + b"\r\n" + \
            f"HAMMER firmware error: {error}\r\n".encode("ascii")
        (directory / "expected-uart.bin").write_bytes(expected)
        (directory / "expected-events.txt").write_text("")
        argv = [
            str(out / "control/directed-probe"), str(paths["fw_jump.bin"]),
            str(paths["Image"]), str(directory / "malformed.dtb"), str(directory),
            str(directory / "expected-uart.bin"), str(directory / "expected-events.txt"),
            "8388608", "firmware-rejection",
        ]
        with (directory / "stdout.log").open("wb") as so, (
            directory / "stderr.log"
        ).open("wb") as se:
            result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
        records.append({
            "name": name, "argv": argv, "exit_code": result.returncode,
            "mutated_dtb_sha256": hashlib.sha256(blob).hexdigest(),
            "expected_uart_sha256": hashlib.sha256(expected).hexdigest(),
            "actual_uart_sha256": hashlib.sha256((directory / "uart.bin").read_bytes()).hexdigest(),
            "header_offset": offset, "replacement": value,
        })
        (out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode or (directory / "uart.bin").read_bytes() != expected:
            raise AssertionError(f"Malformed FDT firmware rejection failed: {name}")
    print(f"Compared unchanged real-firmware control and {len(cases)} malformed FDT "
          "rejections using serialized UART and M-mode-only retirement")


if __name__ == "__main__":
    main()
