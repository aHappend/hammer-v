#!/usr/bin/env python3
"""Freeze/comparator fixtures and compact real seeded firmware pin smokes.

The structural fixtures contain invented tiny images and minimum count values;
they never enter the product checker, produce a Linux expectation or qualify a
boot. The only RTL scope here is the real delivered firmware prefix and mret.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_oracle import BOUND, IMAGE_LAYOUT, Scenario, canonical_json, digest, load_images
from system_protocol import (
    MIN_COVERAGE, PANIC_END, compare_uart, event_line, freeze_expectations,
    parse_event, unchanged_expectations,
)


def rejected(function, exception, label):
    try:
        function()
    except exception:
        return label
    raise AssertionError(f"Accepted invalid protocol fixture: {label}")


def fixture(directory):
    root = directory / "fixture-project"
    root.mkdir()
    images = {}
    loads = []
    for index, (name, address, _) in enumerate(IMAGE_LAYOUT):
        blob = f"SCHEMA FIXTURE, NOT AN EXECUTABLE {index}\n".encode()
        (root / name).write_bytes(blob)
        images[name] = {"path": name, "bytes": len(blob),
                        "sha256": hashlib.sha256(blob).hexdigest()}
        loads.append({"address": address, "path": name})
    (root / "manifest.json").write_bytes(canonical_json({"images": images, "memory_loads": loads}))
    scenario = Scenario(11, 100000, 2000000,
                        tuple((name, images[name]["sha256"]) for name, _, _ in IMAGE_LAYOUT))
    scenario.freeze(root)
    oracle = root / "oracle"
    oracle.mkdir()
    (oracle / "expected-uart.bin").write_bytes(b"SCHEMA FIXTURE\n" + PANIC_END)
    events = event_line("T", 100010, 0x80200000, 13, 0x400000, 1, 0, 0, 0, 64) + \
        event_line("R", 100020, 1, 0x80200004, 0x12000073, 0x80200008, 1, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    (oracle / "expected-events.txt").write_text(events, encoding="ascii")
    metadata = {
        "schema": 1, "scope": "independent-clocked-complete-linux",
        "scenario_sha256": digest(root / "scenario.json"),
        "manifest_sha256": digest(root / "manifest.json"),
        "images": dict(scenario.image_hashes), "seed": 11, "bound": BOUND,
        "final_edge": 2100000, "coverage": dict(MIN_COVERAGE),
        "watches": [
            {"name": "fdt", "start": 0x87E00000, "end": 0x87E01000},
            {"name": "uart", "start": 0x10010000, "end": 0x10010008},
            {"name": "plic_s", "start": 0x0C201004, "end": 0x0C201008},
        ],
        "uart": {"path": "expected-uart.bin",
                 "bytes": (oracle / "expected-uart.bin").stat().st_size,
                 "sha256": digest(oracle / "expected-uart.bin")},
        "events": {"path": "expected-events.txt",
                   "bytes": (oracle / "expected-events.txt").stat().st_size,
                   "sha256": digest(oracle / "expected-events.txt")},
        "event_count": 2,
    }
    (oracle / "expectations.json").write_bytes(canonical_json(metadata))
    return root, oracle, metadata


def protocol_cases(out):
    root, oracle, metadata = fixture(out)
    seal = freeze_expectations(root, Path("manifest.json"), root / "scenario.json", oracle)
    unchanged_expectations(oracle, seal)
    cases = [rejected(
        lambda: freeze_expectations(root, Path("manifest.json"), root / "scenario.json", oracle),
        FileExistsError, "seal_never_replaced",
    )]
    original = (oracle / "expected-uart.bin").read_bytes()
    (oracle / "expected-uart.bin").write_bytes(original + b"\n")
    cases.append(rejected(lambda: unchanged_expectations(oracle, seal), AssertionError,
                          "post_freeze_uart_change"))
    (oracle / "expected-uart.bin").write_bytes(original)
    unchanged_expectations(oracle, seal)

    alterations = [
        ("untimed_scope", lambda doc: doc.update(scope="untimed-functional")),
        ("wrong_seed", lambda doc: doc.update(seed=29)),
        ("wrong_bound", lambda doc: doc.update(bound=BOUND + 1)),
        ("wrong_scenario_hash", lambda doc: doc.update(scenario_sha256="0" * 64)),
        ("wrong_manifest_hash", lambda doc: doc.update(manifest_sha256="0" * 64)),
        ("wrong_image_hash", lambda doc: doc["images"].update(Image="0" * 64)),
        ("short_final_edge", lambda doc: doc.update(final_edge=2000010)),
        ("missing_timer_coverage", lambda doc: doc["coverage"].update(supervisor_timers=2)),
        ("missing_plic_coverage", lambda doc: doc["coverage"].pop("uart_plic_claims")),
        ("wrong_event_count", lambda doc: doc.update(event_count=3)),
        ("missing_fdt_watch", lambda doc: doc.update(watches=doc["watches"][1:])),
        ("wrong_uart_hash", lambda doc: doc["uart"].update(sha256="0" * 64)),
        ("escaping_artifact_path", lambda doc: doc["uart"].update(path="../expected-uart.bin")),
        ("unknown_field", lambda doc: doc.update(acceptance_evidence=True)),
    ]
    for name, change in alterations:
        target = root / name
        shutil.copytree(oracle, target)
        (target / "control.txt").unlink()
        (target / "launch-seal.json").unlink()
        changed = copy.deepcopy(metadata)
        change(changed)
        (target / "expectations.json").write_bytes(canonical_json(changed))
        cases.append(rejected(
            lambda t=target: freeze_expectations(root, Path("manifest.json"),
                                                root / "scenario.json", t),
            (AssertionError, ValueError), name,
        ))
        if (target / "launch-seal.json").exists():
            raise AssertionError(f"Rejected fixture received a launch seal: {name}")
    target = root / "truncated-panic-line"
    shutil.copytree(oracle, target)
    (target / "control.txt").unlink()
    (target / "launch-seal.json").unlink()
    (target / "expected-uart.bin").write_bytes(original[:-2])
    changed = copy.deepcopy(metadata)
    changed["uart"].update(bytes=len(original) - 2,
                           sha256=digest(target / "expected-uart.bin"))
    (target / "expectations.json").write_bytes(canonical_json(changed))
    cases.append(rejected(
        lambda: freeze_expectations(root, Path("manifest.json"), root / "scenario.json", target),
        AssertionError, "complete_panic_line_includes_crlf",
    ))

    line = (oracle / "expected-events.txt").read_text().splitlines(keepends=True)[0]
    if parse_event(line)[1][0] != 100010:
        raise AssertionError("Canonical event round trip")
    for name, changed in (
        ("noncanonical_decimal", line.replace("100010", "0100010", 1)),
        ("extra_whitespace", line.replace(" ", "  ", 1)),
        ("missing_newline", line.rstrip("\n")),
        ("out_of_bound", line.replace("100010", str(BOUND), 1)),
        ("negative_edge", line.replace("100010", "-1", 1)),
    ):
        cases.append(rejected(lambda text=changed: parse_event(text), ValueError, name))
    comparisons = []
    data = bytes(range(256)) * 300 + PANIC_END
    expected, actual = out / "fixture-expected.bin", out / "fixture-actual.bin"
    expected.write_bytes(data)
    for name, blob, index in (
        ("equal", data, None), ("first_byte", b"\xff" + data[1:], 0),
        ("chunk_boundary", data[:65536] + b"\xff" + data[65537:], 65536),
        ("missing_byte", data[:-1], len(data) - 1),
        ("extra_byte", data + b"\n", len(data)),
    ):
        actual.write_bytes(blob)
        result = compare_uart(expected, actual)
        if index is None and not result["equal"] or index is not None and (
            result["equal"] or result["first_mismatch"] != index
        ):
            raise AssertionError(f"Whole-stream comparator fixture: {name}")
        comparisons.append({"case": name, **result})
    return {"scope": "schema and comparator fixtures only, not a Linux oracle",
            "rejected_cases": cases, "uart_comparisons": comparisons}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    summary = protocol_cases(out)
    manifest, _ = load_images(ROOT, args.manifest)
    fixtures = out / "cpp-fixtures"
    fixtures.mkdir()
    (fixtures / "expected-uart.bin").write_bytes(b"\x5a")
    (fixtures / "expected-events.txt").write_text(
        event_line("T", 10, 0x80200000, 13, 0x400000, 1, 0, 0, 0, 64)
    )
    (fixtures / "firmware").mkdir()
    (fixtures / "firmware/expected-uart.bin").write_bytes(
        b"HAMMER-V4 OpenSBI-compatible fw_jump (SBI v0.2)\r\n"
        b"HAMMER firmware: hart=0 dtb=0x87e00000 next=0x80200000 S-mode\r\n"
    )
    for name in ("control", "corrupt", "short-stop", "event-0", "event-1", "event-2"):
        (fixtures / name).mkdir()
    for seed in (11, 29, 47):
        (out / f"seed-{seed}").mkdir()
    obj = relative / "compile-obj"
    records = []

    def run(argv, name):
        record = {"argv": list(map(str, argv)), "cwd": "."}
        records.append(record)
        with (out / f"{name}.stdout.log").open("wb") as so, (
            out / f"{name}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(record["argv"], cwd=ROOT, stdout=so, stderr=se, check=False)
        record["exit_code"] = result.returncode
        (out / "commands.json").write_bytes(canonical_json(records))
        if result.returncode:
            raise AssertionError(f"System harness {name} failed: {relative}")

    try:
        run([
            "verilator", "-O3", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
            "--top-module", "hammer_v4_top", "--Mdir", obj.as_posix(),
            "-CFLAGS", "-O3 -std=c++17",
            *[path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "rtl").glob("*.sv"))],
            str(Path(*([".."] * len(obj.parts))) / "tests/system_pin_smoke.cpp"),
            "-MAKEFLAGS", "OPT_FAST=-O3",
        ], "compile")
        makefile = (ROOT / obj / "Vhammer_v4_top.mk").read_text()
        match = re.search(r"^VERILATOR_ROOT\s*=\s*(.+)$", makefile, re.MULTILINE)
        if match is None:
            raise AssertionError("Generated makefile did not identify its Verilator installation")
        verilator_root = Path(match.group(1).strip())
        run([
            "g++", "-std=c++17", "-fsyntax-only", "-I" + obj.as_posix(),
            "-I" + str(verilator_root / "include"),
            "-I" + str(verilator_root / "include/vltstd"), "tests/system_probe.cpp",
        ], "production-main-syntax")
        binary = relative / "pin-smoke"
        shutil.copyfile(ROOT / obj / "Vhammer_v4_top", ROOT / binary)
        (ROOT / binary).chmod(0o755)
        run([
            binary.as_posix(),
            *[manifest["images"][name]["path"] for name, _, _ in IMAGE_LAYOUT],
            fixtures.relative_to(ROOT).as_posix(), relative.as_posix(),
        ], "simulate")
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in (ROOT / obj).glob(pattern):
                path.unlink()
    text = (out / "simulate.stdout.log").read_text()
    for seed in (11, 29, 47):
        if f"FIRMWARE_PIN_SMOKE seed={seed} " not in text:
            raise AssertionError(f"Missing real seeded firmware comparison: {seed}")
    if "architectural_mutants_rejected=2" not in text or "wire_mutants_rejected=2" not in text:
        raise AssertionError("Missing compiled comparator defect sensitivity")
    summary.update(
        rtl_scope="three compact seeded firmware prefixes and actual mret ABI; not full Linux",
        compiled_wire_and_architectural_mutants_rejected=4,
        full_linux_boot=False,
    )
    (out / "summary.json").write_bytes(canonical_json(summary))
    print("COMPARED frozen-protocol fixtures, compiled comparators and actual firmware "
          "pins for seeds 11/29/47; no full Linux acceptance")


if __name__ == "__main__":
    main()
