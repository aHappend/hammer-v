#!/usr/bin/env python3
"""Bounded CLI prediction, immutable freeze, and public-pin RTL comparison.

This diagnostic does not launch the mandatory aggregate or qualify a full boot.
It exercises the actual expectation producer entrypoint before DUT execution.
"""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_checks import relative_path
from system_oracle import IMAGE_LAYOUT, SEEDS, Scenario, canonical_json, digest, load_images
from system_protocol import compare_uart, freeze_expectations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--seed", type=int, choices=SEEDS, default=SEEDS[0])
    parser.add_argument("--retirements", type=int, default=150000)
    parser.add_argument("--edge-limit", type=int, default=1 << 26)
    args = parser.parse_args()
    relative = relative_path(ROOT, args.out, output=True)
    manifest_path = relative_path(ROOT, args.manifest)
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest, images = load_images(ROOT, args.manifest)
    scenario = Scenario(args.seed, 100000, (1 << 28) + args.seed * 1000,
                        tuple((name, manifest["images"][name]["sha256"])
                              for name, _, _ in IMAGE_LAYOUT))
    scenario.freeze(out)
    commands = []

    def run(argv, name):
        record = {"argv": argv, "cwd": ".", "started_unix": time.time(),
                  "exit_code": None, "stdout": (relative / f"{name}.stdout.log").as_posix(),
                  "stderr": (relative / f"{name}.stderr.log").as_posix()}
        commands.append(record)
        try:
            with (ROOT / record["stdout"]).open("wb") as so, (
                ROOT / record["stderr"]
            ).open("wb") as se:
                with subprocess.Popen(argv, cwd=ROOT, stdout=so, stderr=se) as child:
                    while True:
                        try:
                            record["exit_code"] = child.wait(timeout=20)
                            break
                        except subprocess.TimeoutExpired:
                            print(f"PREDICTION_CHECK_ACTIVE stage={name} "
                                  f"seconds={time.time() - record['started_unix']:.1f}", flush=True)
            if record["exit_code"]:
                raise AssertionError(f"{name} exited {record['exit_code']}; {record['stderr']}")
        finally:
            record["ended_unix"] = time.time()
            (out / "commands.json").write_bytes(canonical_json(commands))

    oracle = relative / "oracle"
    run([
        "python3", "tests/system_oracle.py", "--manifest", manifest_path.as_posix(),
        "--scenario", (relative / "scenario.json").as_posix(), "--out", oracle.as_posix(),
        "--diagnostic-retirements", str(args.retirements),
        "--diagnostic-edge-limit", str(args.edge_limit),
    ], "prediction")
    metadata = json.loads((ROOT / oracle / "expectations.json").read_text())
    if metadata["scope"] != "independent-clocked-prefix":
        raise AssertionError("Bounded prediction mislabeled as complete-system acceptance")
    try:
        freeze_expectations(ROOT, manifest_path, out / "scenario.json", ROOT / oracle)
    except ValueError as error:
        if str(error) != "Not a complete independently clocked system expectation":
            raise
    else:
        raise AssertionError("An incomplete prefix obtained a full-system launch seal")
    frozen = {name: digest(ROOT / oracle / name) for name in (
        "expectations.json", "expected-uart.bin", "expected-events.txt",
        "control.txt", "counts.txt", "prediction.json",
    )}
    frozen_at = time.time()
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
        binary = relative / "prefix-probe"
        shutil.copyfile(ROOT / obj / "Vhammer_v4_top", ROOT / binary)
        (ROOT / binary).chmod(0o755)
        actual = relative / "rtl"
        (ROOT / actual).mkdir()
        run([
            binary.as_posix(),
            *[manifest["images"][name]["path"] for name, _, _ in images],
            oracle.as_posix(), actual.as_posix(), str(args.seed),
            str(metadata["final_edge"]), "selected",
        ], "comparison")
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in (ROOT / obj).glob(pattern):
                path.unlink()
    if any(digest(ROOT / oracle / name) != old for name, old in frozen.items()):
        raise AssertionError("Pre-DUT CLI expectations changed during RTL execution")
    comparison = compare_uart(ROOT / oracle / "expected-uart.bin", ROOT / actual / "uart.bin")
    if not comparison["equal"]:
        raise AssertionError(f"Exact UART prefix comparison failed: {comparison}")
    load_images(ROOT, args.manifest)
    result = {
        "scope": "bounded CLI prediction/comparison, not complete Linux acceptance",
        "seed": args.seed, "frozen_files": frozen, "frozen_unix": frozen_at,
        "dut_started_unix": commands[-1]["started_unix"],
        "complete_system_seal_rejected": True, "final_edge": metadata["final_edge"],
        "compared_events": metadata["event_count"], "uart": comparison,
        "all_comparisons_passed": True,
    }
    if frozen_at >= result["dut_started_unix"]:
        raise AssertionError("DUT ran before independent expectation freeze")
    (out / "summary.json").write_bytes(canonical_json(result))
    print(f"COMPARED pre-DUT CLI prediction seed={args.seed} "
          f"events={metadata['event_count']} uart_bytes={comparison['bytes']} "
          f"final_edge={metadata['final_edge']}", flush=True)


if __name__ == "__main__":
    main()
