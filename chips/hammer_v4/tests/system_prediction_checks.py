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
from system_protocol import compare_uart, event_summary, freeze_expectations
from preparation import source_hashes


def retained_failed_prefix(receipt_path, manifest_path, scenario, oracle):
    """Compare a retained forecast prefix without accepting its failed goal."""
    relative = relative_path(ROOT, receipt_path)
    if relative.parts[:2] != ("evidence", "preparation") or relative.name != "receipt.json":
        raise ValueError("A retained advisory preparation receipt is required")
    receipt = json.loads((ROOT / relative).read_text())
    argv = receipt["argv"]
    if receipt["exit_code"] != 1 or receipt.get("timed_out") or \
            not receipt["sources_unchanged"] or argv[:2] != [
                "python3", "tests/system_prediction_checks.py"
            ] or "--uart-bytes" not in argv:
        raise AssertionError("Not a settled incomplete UART-target prediction")
    if argv[argv.index("--manifest") + 1] != manifest_path.as_posix():
        raise AssertionError("Retained forecast used a different software manifest")
    current = source_hashes()
    generator = (
        "tests/system_oracle.py", "tests/system_prediction.py", "tests/system_core.py",
        "tests/system_memory.py", "tests/system_platform.py", "tests/system_execution.py",
        "tests/rv64_reference.py", "tests/architecture.py", "tests/system_protocol.py",
    )
    bound_sources = set(generator) | {
        name for name in current
        if name.startswith(("rtl/", "software/", "design/", "hammer_v3_reference/"))
    }
    if any(receipt["source_sha256"].get(name) != current[name] for name in bound_sources):
        raise AssertionError("Independent prediction or protected product sources changed")
    original = ROOT / relative_path(ROOT, argv[argv.index("--out") + 1], output=True)
    if Scenario.read(original / "scenario.json") != scenario:
        raise AssertionError("Retained forecast has different immutable stimulus")
    commands = json.loads((original / "commands.json").read_text())
    if len(commands) != 1 or commands[0]["exit_code"] != 1 or \
            commands[0]["argv"][:2] != ["python3", "tests/system_oracle.py"] or \
            commands[0]["ended_unix"] > receipt["ended_unix"]:
        raise AssertionError("Expected prediction failure before any DUT compilation/launch")
    failed = json.loads((original / "oracle/prediction.json").read_text())
    limit = int(argv[argv.index("--edge-limit") + 1])
    if failed["completed"] or failed["scope"] != "incomplete-independent-prediction" or \
            failed["last_edge"] != limit - 1 or \
            failed["failure"]["type"] != "AssertionError" or \
            not failed["failure"]["message"].startswith(
                f"Independent workload not complete at edge {limit - 1};"
            ):
        raise AssertionError("Retained failure is not the explicit diagnostic edge boundary")
    oracle.mkdir()
    for name in ("expected-events.txt", "expected-uart.bin", "prediction.json"):
        shutil.copyfile(original / "oracle" / name, oracle / name)
    ranges = [
        {"name": "fdt", "start": 0x87E00000, "end": 0x87E00000 + len(
            load_images(ROOT, manifest_path)[1][2][2])},
        {"name": "uart", "start": 0x10010000, "end": 0x10010008},
        {"name": "plic_m", "start": 0x0C200004, "end": 0x0C200008},
        {"name": "plic_s", "start": 0x0C201004, "end": 0x0C201008},
    ]
    count, _ = event_summary(oracle / "expected-events.txt", scenario.start_edge,
                             failed["last_edge"], ranges)
    if count != failed["events"] or (oracle / "expected-uart.bin").stat().st_size != \
            failed["uart_bytes"]:
        raise AssertionError("Retained forecast output lengths differ from its failure record")
    metadata = {
        "schema": 1, "scope": "independent-clocked-prefix",
        "scenario_sha256": digest(original / "scenario.json"),
        "manifest_sha256": digest(ROOT / manifest_path), "images": dict(scenario.image_hashes),
        "seed": scenario.seed, "bound": failed["bound"], "final_edge": failed["last_edge"],
        "coverage": failed["coverage"], "watches": ranges, "event_count": count,
    }
    for key, name in (("uart", "expected-uart.bin"), ("events", "expected-events.txt")):
        metadata[key] = {"path": name, "bytes": (oracle / name).stat().st_size,
                         "sha256": digest(oracle / name)}
    (oracle / "expectations.json").write_bytes(canonical_json(metadata))
    control = [scenario.seed, scenario.start_edge, scenario.rx_first_edge,
               scenario.rx_spacing, failed["last_edge"], count, failed["uart_bytes"], len(ranges)]
    (oracle / "control.txt").write_text(
        " ".join(map(str, control)) + "\n" + "".join(
            f"{item['name']} {item['start']} {item['end']}\n" for item in ranges),
        encoding="ascii")
    (oracle / "counts.txt").write_text(f"{count} {failed['uart_bytes']}\n", encoding="ascii")
    return {"receipt": relative.as_posix(), "sha256": digest(ROOT / relative),
            "original_goal_still_failed": True, "source_bindings": sorted(bound_sources)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--seed", type=int, choices=SEEDS, default=SEEDS[0])
    parser.add_argument("--retirements", type=int, default=150000)
    parser.add_argument("--uart-bytes", type=int)
    parser.add_argument("--edge-limit", type=int, default=1 << 26)
    parser.add_argument("--failed-prefix-receipt")
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
    origin = None
    if args.failed_prefix_receipt:
        origin = retained_failed_prefix(args.failed_prefix_receipt, manifest_path, scenario,
                                         ROOT / oracle)
    else:
        run([
            "python3", "tests/system_oracle.py", "--manifest", manifest_path.as_posix(),
            "--scenario", (relative / "scenario.json").as_posix(), "--out", oracle.as_posix(),
            "--diagnostic-uart-bytes" if args.uart_bytes is not None else "--diagnostic-retirements",
            str(args.uart_bytes if args.uart_bytes is not None else args.retirements),
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
    prefix_seal = {"scope": "diagnostic-only-not-complete-system",
                   "files": frozen, "frozen_unix": frozen_at, "origin": origin}
    with (ROOT / oracle / "prefix-seal.json").open("xb") as stream:
        stream.write(canonical_json(prefix_seal))
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
    if json.loads((ROOT / oracle / "prefix-seal.json").read_text()) != prefix_seal:
        raise AssertionError("The pre-DUT diagnostic prefix seal changed")
    comparison = compare_uart(ROOT / oracle / "expected-uart.bin", ROOT / actual / "uart.bin")
    if not comparison["equal"]:
        raise AssertionError(f"Exact UART prefix comparison failed: {comparison}")
    observed = json.loads((ROOT / actual / "prefix-result.json").read_text())
    if observed["coverage"] != metadata["coverage"]:
        raise AssertionError(
            f"Independent and public-pin prefix coverage differ: "
            f"expected={metadata['coverage']}, actual={observed['coverage']}"
        )
    load_images(ROOT, args.manifest)
    result = {
        "scope": "bounded CLI prediction/comparison, not complete Linux acceptance",
        "seed": args.seed, "frozen_files": frozen, "frozen_unix": frozen_at,
        "dut_started_unix": commands[-1]["started_unix"],
        "complete_system_seal_rejected": True, "final_edge": metadata["final_edge"],
        "compared_coverage": observed["coverage"],
        "compared_events": metadata["event_count"], "uart": comparison,
        "all_comparisons_passed": True,
        "origin": origin, "prefix_seal_sha256": digest(ROOT / oracle / "prefix-seal.json"),
    }
    if comparison["bytes"] > 2527:
        with (ROOT / oracle / "expected-uart.bin").open("rb") as stream:
            stream.seek(2511)
            result["byte_2527_comparison"] = {
                "equal": True, "context_first_offset": 2511,
                "expected_and_actual_context_hex": stream.read(33).hex(),
                "normalization": False,
            }
    if frozen_at >= result["dut_started_unix"]:
        raise AssertionError("DUT ran before independent expectation freeze")
    (out / "summary.json").write_bytes(canonical_json(result))
    print(f"COMPARED pre-DUT CLI prediction seed={args.seed} "
          f"events={metadata['event_count']} uart_bytes={comparison['bytes']} "
          f"final_edge={metadata['final_edge']}", flush=True)


if __name__ == "__main__":
    main()
