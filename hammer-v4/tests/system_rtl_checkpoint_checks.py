#!/usr/bin/env python3
"""Real compact firmware/kernel-prefix cold-continuation equivalence controls."""

import argparse
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_checks import relative_path
from system_oracle import IMAGE_LAYOUT, Scenario, canonical_json, digest, load_images
from system_rtl_checkpoint import STREAMS, check_record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--retirements", type=int, default=12000)
    parser.add_argument("--seed", type=int, choices=(11, 29, 47), default=11)
    args = parser.parse_args()
    relative = relative_path(ROOT, args.out, output=True)
    manifest_path = relative_path(ROOT, args.manifest)
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest, _ = load_images(ROOT, manifest_path)
    scenario = Scenario(args.seed, 100000, (1 << 28) + args.seed * 1000,
                        tuple((name, manifest["images"][name]["sha256"])
                              for name, _, _ in IMAGE_LAYOUT))
    scenario.freeze(out)
    commands = []

    def run(argv, name):
        record = {"argv": argv, "cwd": ".", "started_unix": time.time(),
                  "exit_code": None}
        commands.append(record)
        try:
            with (out / f"{name}.stdout.log").open("xb") as so, (
                out / f"{name}.stderr.log"
            ).open("xb") as se:
                with subprocess.Popen(argv, cwd=ROOT, stdout=so, stderr=se) as child:
                    while True:
                        try:
                            record["exit_code"] = child.wait(timeout=20)
                            break
                        except subprocess.TimeoutExpired:
                            print(f"CHECKPOINT_CONTROL stage={name} "
                                  f"seconds={time.time() - record['started_unix']:.1f}", flush=True)
            if record["exit_code"]:
                raise AssertionError(f"RTL checkpoint control failed: {name}")
        finally:
            record["ended_unix"] = time.time()
            (out / "commands.json").write_bytes(canonical_json(commands))

    run([
        "python3", "tests/system_oracle.py", "--manifest", manifest_path.as_posix(),
        "--scenario", (relative / "scenario.json").as_posix(),
        "--out", (relative / "oracle").as_posix(),
        "--diagnostic-retirements", str(args.retirements),
        "--diagnostic-edge-limit", "67108864",
    ], "independent-prefix")
    expected = out / "oracle"
    frozen = {name: digest(expected / name) for name in (
        "control.txt", "expected-events.txt", "expected-uart.bin", "expectations.json",
    )}
    frozen_at = time.time()
    metadata = json.loads((expected / "expectations.json").read_text())
    if metadata["scope"] != "independent-clocked-prefix" or metadata["final_edge"] <= 104009:
        raise AssertionError("Compact control did not reach running firmware")
    obj = relative / "compile-obj"
    binary = relative / "system-probe"
    try:
        run([
            "verilator", "-O3", "--cc", "--exe", "--build", "--savable",
            "-j", "4", "-Wno-fatal", "--top-module", "hammer_v4_top",
            "--Mdir", obj.as_posix(), "-CFLAGS",
            "-O3 -std=c++17 -DHAMMER_SYSTEM_CHECKPOINT",
            *[path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "rtl").glob("*.sv"))],
            str(Path(*([".."] * len(obj.parts))) / "tests/system_probe.cpp"),
            "-MAKEFLAGS", "OPT_FAST=-O3",
        ], "compile")
        shutil.copyfile(ROOT / obj / "Vhammer_v4_top", ROOT / binary)
        (ROOT / binary).chmod(0o755)
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in (ROOT / obj).glob(pattern):
                path.unlink()

    def part(label, edge, previous=None, continuous=False):
        checkpoint = relative / "checkpoint-images" / label
        argv = [
            "python3", "tests/system_rtl_checkpoint.py", "--binary", binary.as_posix(),
            "--manifest", manifest_path.as_posix(),
            "--expectations", (relative / "oracle").as_posix(),
            "--out", (relative / ("continuous" if continuous else "resumed")).as_posix(),
            "--through", str(edge), "--checkpoint", checkpoint.as_posix(),
            "--diagnostic-prefix",
        ]
        if previous is not None:
            argv += ["--resume", previous.as_posix()]
        run(argv, label)
        return checkpoint

    boundaries = (100001, 100049, 100127, 100201, 100503, 102510, 104009,
                  metadata["final_edge"])
    previous = None
    records = []
    for index, edge in enumerate(boundaries):
        previous = part(f"resumed-{index:02d}", edge, previous)
        records.append(json.loads((ROOT / previous / "checkpoint.json").read_text()))
    part("continuous", metadata["final_edge"], continuous=True)
    resumed, continuous = out / "resumed", out / "continuous"
    for name in (*STREAMS, "result.json"):
        if digest(resumed / name) != digest(continuous / name):
            raise AssertionError(f"Continuous versus cold-resumed RTL differs: {name}")
    result = json.loads((resumed / "result.json").read_text())
    if not result["retired"] or not result["compared_events"] or not result["uart_bytes"] or \
            not result["reads"] or not result["writes"]:
        raise AssertionError("RTL continuation controls performed no real comparisons")
    if any(digest(expected / name) != value for name, value in frozen.items()):
        raise AssertionError("RTL continuation changed frozen independent expectations")
    if frozen_at >= commands[2]["started_unix"]:
        raise AssertionError("Independent expectations were not sealed before DUT execution")

    valid = ROOT / previous
    record = records[-1]
    check_record(valid, record["binding"], resumed)
    rejections = []
    for name, marker in (
        ("payload", "RTL checkpoint payload identity differs"),
        ("source", "RTL checkpoint source/input/binary binding differs"),
        ("binary", "RTL checkpoint source/input/binary binding differs"),
        ("parent", "RTL checkpoint parent identity differs"),
        ("output", "RTL checkpoint output prefix differs: uart.bin"),
    ):
        target = out / "checkpoint-images" / f"corrupt-{name}"
        target.mkdir()
        altered = copy.deepcopy(record)
        shutil.copyfile(valid / "machine.dat.z", target / "machine.dat.z")
        if name == "payload":
            with (target / "machine.dat.z").open("r+b") as stream:
                first = stream.read(1)
                stream.seek(0)
                stream.write(bytes((first[0] ^ 1,)))
        elif name == "source":
            altered["source_sha256"]["tests/system_probe.cpp"] = "0" * 64
        elif name == "binary":
            altered["binding"]["binary_sha256"] = "0" * 64
        elif name == "parent":
            altered["parent"]["sha256"] = "0" * 64
        else:
            altered["streams"]["uart.bin"]["sha256"] = "0" * 64
        (target / "checkpoint.json").write_bytes(canonical_json(altered))
        try:
            check_record(target, record["binding"], resumed)
        except ValueError as error:
            if str(error) != marker:
                raise
            rejections.append(name)
        else:
            raise AssertionError(f"RTL checkpoint corruption accepted: {name}")
    (out / "summary.json").write_bytes(canonical_json({
        "scope": "compact real RTL cold-continuation controls, not Linux acceptance",
        "fresh_process_parts": len(boundaries), "boundaries": list(boundaries),
        "continuous_and_resumed_equal": True, "rejected_corruptions": rejections,
        "frozen_before_dut_unix": frozen_at,
        "streams": {name: digest(resumed / name) for name in (*STREAMS, "result.json")},
        "observations": result,
        "peripheral_aliases": json.loads((expected / "prediction.json").read_text())
                              ["peripheral_aliases"],
        "part_seconds": [record["ended_unix"] - record["started_unix"]
                         for record in commands if record["argv"][1:2] ==
                         ["tests/system_rtl_checkpoint.py"]],
    }))
    print(f"COMPARED cold RTL parts={len(boundaries)} "
          f"retired={result['retired']} events={result['compared_events']} "
          f"uart_bytes={result['uart_bytes']}; five corruptions rejected", flush=True)


if __name__ == "__main__":
    main()
