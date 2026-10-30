#!/usr/bin/env python3
"""Full seeded Linux comparison and clean RTL reproduction.

No transcript-only, old-receipt or untimed-model fallback exists. The independent
oracle must finish and all expected files must be sealed before DUT execution.
Until the scheduler can generate those complete expectations this check fails
at oracle generation, before compiling or launching an expensive boot.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from reproduction_checks import PATTERNS
from system_oracle import IMAGE_LAYOUT, SEEDS, Scenario, canonical_json, digest, load_images
from system_protocol import (
    compare_uart, coverage_counts, freeze_expectations, unchanged_expectations,
)


def inventory(root):
    return {path.relative_to(root).as_posix(): digest(path)
            for pattern in PATTERNS for path in sorted(root.glob(pattern))
            if path.is_file()}


def relative_path(root, value, *, output=False):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or any(
        name in (".git", ".vulcan", ".tooling", "VULCAN") for name in path.parts
    ) or output and path.parts[:1] != ("build",):
        raise ValueError(f"Not an allowed project-relative path: {value}")
    if not (root / path).resolve().is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes the project: {value}")
    if output and any((root / Path(*path.parts[:index])).is_symlink()
                      for index in range(1, len(path.parts) + 1)):
        raise ValueError(f"Output path contains a symlink: {value}")
    return path


class Execution:
    def __init__(self, out, argv):
        self.out = out
        self.tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + \
            "-" + uuid.uuid4().hex[:8]
        self.evidence = ROOT / "evidence" / f"system-linux-validation-{self.tag}"
        self.evidence.mkdir(parents=True, exist_ok=False)
        self.receipt = {
            "schema": 1, "argv": argv, "cwd": ".",
            "started_unix": time.time(), "ended_unix": None,
            "source_sha256": inventory(ROOT), "status": "running",
            "commands": [], "required_seeds": list(SEEDS),
            "runs": [{"seed": seed, "clean": False, "status": "not_run"} for seed in SEEDS] +
                    [{"seed": SEEDS[0], "clean": True, "status": "not_run"}],
            "tool_versions": {},
        }
        self.save()

    def save(self):
        (self.evidence / "receipt.json").write_bytes(canonical_json(self.receipt))

    def fail(self, error):
        failure = {"type": type(error).__name__, "message": str(error)}
        self.receipt.update(status="failed", exit_code=1, failure=failure)
        for record in self.receipt["runs"]:
            if record["status"] in ("generating_expectations", "simulating"):
                record.update(status="failed", ended_unix=time.time(), failure=failure)
        self.save()

    def run(self, root, argv, name):
        record = {
            "argv": list(map(str, argv)), "cwd": root.relative_to(ROOT).as_posix(),
            "started_unix": time.time(), "exit_code": None,
            "stdout": (self.evidence / f"{len(self.receipt['commands']):02d}-{name}.stdout.log")
                      .relative_to(ROOT).as_posix(),
            "stderr": (self.evidence / f"{len(self.receipt['commands']):02d}-{name}.stderr.log")
                      .relative_to(ROOT).as_posix(),
        }
        self.receipt["commands"].append(record)
        self.save()
        try:
            with (ROOT / record["stdout"]).open("wb") as so, (
                ROOT / record["stderr"]
            ).open("wb") as se:
                with subprocess.Popen(record["argv"], cwd=root, stdout=so, stderr=se) as child:
                    while True:
                        try:
                            record["exit_code"] = child.wait(timeout=20)
                            break
                        except subprocess.TimeoutExpired:
                            print(f"SYSTEM_ACTIVE stage={name} "
                                  f"seconds={time.time() - record['started_unix']:.1f} "
                                  f"stdout_bytes={so.tell()} stderr_bytes={se.tell()}", flush=True)
            if record["exit_code"]:
                raise RuntimeError(f"{name} exited {record['exit_code']}; see {record['stderr']}")
            return record
        finally:
            record["ended_unix"] = time.time()
            self.save()

    def prepare(self, root, manifest_relative, out_relative, record):
        seed = record["seed"]
        record.update(status="generating_expectations", started_unix=time.time())
        self.save()
        manifest, images = load_images(root, manifest_relative)
        directory = root / out_relative
        directory.mkdir(parents=True, exist_ok=False)
        # Fixed released-edge stimuli, independent of all DUT observations.
        scenario = Scenario(seed, 100000, (1 << 28) + seed * 1000,
                            tuple((name, manifest["images"][name]["sha256"])
                                  for name, _, _ in IMAGE_LAYOUT))
        record["scenario_sha256"] = scenario.freeze(directory)
        record["images"] = {name: digest(root / manifest["images"][name]["path"])
                            for name, _, _ in images}
        oracle_relative = out_relative / "oracle"
        oracle_start = self.run(root, [
            "python3", "tests/system_oracle.py", "--manifest", manifest_relative.as_posix(),
            "--scenario", (out_relative / "scenario.json").as_posix(),
            "--out", oracle_relative.as_posix(),
        ], f"seed-{seed}-{'clean-' if record['clean'] else ''}oracle")
        oracle = root / oracle_relative
        seal = freeze_expectations(root, manifest_relative, directory / "scenario.json", oracle)
        record.update(status="expectations_frozen", seal=seal,
                      expectations_frozen_unix=time.time(),
                      oracle_command_finished_unix=oracle_start["ended_unix"],
                      directory=directory.relative_to(ROOT).as_posix())
        self.save()
        return root, manifest_relative, out_relative, seal, record

    def compile(self, root, out_relative):
        obj_relative = out_relative / "compile-obj"
        binary_relative = out_relative / "system-probe"
        try:
            self.run(root, [
                "verilator", "-O3", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
                "--top-module", "hammer_v4_top", "--Mdir", obj_relative.as_posix(),
                "-CFLAGS", "-O3 -std=c++17",
                *[path.relative_to(root).as_posix()
                  for path in sorted((root / "rtl").glob("*.sv"))],
                # Verilator's make runs in Mdir, so its C++ prerequisite is
                # expressed relative to that directory, without a host path.
                str(Path(*([".."] * len(obj_relative.parts))) / "tests/system_probe.cpp"),
                "-MAKEFLAGS", "OPT_FAST=-O3",
            ], "compile-clean" if root != ROOT else "compile-seeds")
            executable = root / binary_relative
            shutil.copyfile(root / obj_relative / "Vhammer_v4_top", executable)
            executable.chmod(0o755)
            return binary_relative
        finally:
            for pattern in ("*.o", "*.a", "*.gch"):
                for path in (root / obj_relative).glob(pattern):
                    path.unlink()

    def simulate(self, prepared, executable):
        root, manifest_relative, out_relative, seal, record = prepared
        directory = root / out_relative
        oracle = directory / "oracle"
        actual_relative = out_relative / "rtl"
        actual = root / actual_relative
        actual.mkdir()
        unchanged_expectations(oracle, seal)
        if digest(directory / "scenario.json") != seal["scenario_sha256"] or \
                digest(root / manifest_relative) != seal["manifest_sha256"]:
            raise AssertionError("Frozen scenario/manifest changed before DUT launch")
        manifest, _ = load_images(root, manifest_relative)
        record.update(status="simulating", dut_started_unix=time.time())
        self.save()
        self.run(root, [
            executable.as_posix(),
            *[manifest["images"][name]["path"] for name, _, _ in IMAGE_LAYOUT],
            (out_relative / "oracle").as_posix(), actual_relative.as_posix(),
        ], f"seed-{record['seed']}-{'clean-' if record['clean'] else ''}rtl")
        unchanged_expectations(oracle, seal)
        if digest(directory / "scenario.json") != seal["scenario_sha256"] or \
                digest(root / manifest_relative) != seal["manifest_sha256"]:
            raise AssertionError("Scenario/manifest changed during DUT execution")
        load_images(root, manifest_relative)
        metadata = json.loads((oracle / "expectations.json").read_text())
        result = json.loads((actual / "result.json").read_text())
        comparison = compare_uart(oracle / "expected-uart.bin", actual / "uart.bin")
        (actual / "uart-comparison.json").write_bytes(canonical_json(comparison))
        if not comparison["equal"]:
            raise AssertionError(f"Full UART mismatch: {comparison}")
        if coverage_counts(result["coverage"]) != metadata["coverage"] or \
                result["seed"] != record["seed"] or \
                result["final_edge"] != metadata["final_edge"] or \
                result["compared_events"] != metadata["event_count"] or \
                result["uart_bytes"] != metadata["uart"]["bytes"]:
            raise AssertionError("Actual full-system events/coverage differ from the timed oracle")
        if record["expectations_frozen_unix"] >= record["dut_started_unix"]:
            raise AssertionError("Expectations were not frozen before DUT launch")
        archive = self.evidence / f"seed-{record['seed']}-{'clean-' if record['clean'] else ''}{self.tag}"
        archive.mkdir()
        for source in (directory / "scenario.json", *(oracle / name for name in (
            "expectations.json", "expected-uart.bin", "expected-events.txt",
            "control.txt", "launch-seal.json",
        )), *(actual / name for name in (
            "uart.bin", "result.json", "uart-comparison.json", "milestones.log",
        ))):
            shutil.copyfile(source, archive / source.name)
        record.update(status="compared", ended_unix=time.time(), result=result,
                      evidence=archive.relative_to(ROOT).as_posix(),
                      actual_uart_sha256=digest(actual / "uart.bin"))
        self.save()

    def execute(self, manifest_relative):
        for tool in ("python3", "g++", "verilator"):
            record = self.run(ROOT, [tool, "--version"], "version")
            self.receipt["tool_versions"][tool] = record
        out_relative = self.out.relative_to(ROOT)
        self.run(ROOT, [
            "python3", "tests/system_axi_checks.py",
            "--out", (out_relative / "axi-components").as_posix(),
        ], "axi-stimulus-checks")
        self.run(ROOT, [
            "python3", "tests/system_harness_checks.py", "--manifest", manifest_relative.as_posix(),
            "--out", (out_relative / "harness-components").as_posix(),
        ], "harness-components")
        self.run(ROOT, [
            "python3", "tests/system_execution_checks.py",
            "--out", (out_relative / "architectural-memory").as_posix(),
        ], "architectural-memory-integration")
        self.run(ROOT, [
            "python3", "tests/system_memory_rtl_checks.py",
            "--out", (out_relative / "memory-rtl").as_posix(),
        ], "memory-path-rtl-integration")
        prepared = [
            self.prepare(ROOT, manifest_relative, out_relative / f"seed-{seed}", record)
            for seed, record in zip(SEEDS, self.receipt["runs"])
        ]
        binary = self.compile(ROOT, out_relative)
        for run in prepared:
            self.simulate(run, binary)
        clean_relative = out_relative / "clean-reproduction"
        self.run(ROOT, [
            "python3", "tests/reproduction_checks.py", "--out", clean_relative.as_posix(),
            "--compare-manifest", manifest_relative.as_posix(),
        ], "clean-source-rebuild")
        clean_root = ROOT / clean_relative / "project"
        clean_inputs = inventory(clean_root)
        if clean_inputs != self.receipt["source_sha256"]:
            raise AssertionError("Clean reproduction declared inputs differ from this run")
        clean_out = Path("build/system-validation")
        clean = self.prepare(clean_root, Path("build/software/image-manifest.json"),
                             clean_out, self.receipt["runs"][-1])
        self.simulate(clean, self.compile(clean_root, clean_out))
        if inventory(clean_root) != clean_inputs:
            raise AssertionError("Clean reproduction changed its declared inputs")
        if inventory(ROOT) != self.receipt["source_sha256"]:
            raise AssertionError("System validation changed its declared inputs")
        # Publish only a fully compared actual wire capture, after immutable
        # per-run copies of all four required boots have been retained.
        first = ROOT / self.receipt["runs"][0]["evidence"] / "uart.bin"
        canonical = ROOT / "evidence/uart_linux_boot.log"
        shutil.copyfile(first, canonical)
        self.receipt.update(status="passed", exit_code=0,
                            canonical_uart_sha256=digest(canonical))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    relative = relative_path(ROOT, args.out, output=True)
    manifest = relative_path(ROOT, args.manifest)
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    execution = Execution(out, ["python3", "tests/system_checks.py",
                                "--out", args.out, "--manifest", args.manifest])
    try:
        execution.execute(manifest)
    except Exception as error:
        execution.fail(error)
        print(f"SYSTEM_FAILED {error}", file=sys.stderr, flush=True)
    finally:
        execution.receipt["ended_unix"] = time.time()
        execution.receipt["sources_unchanged"] = \
            inventory(ROOT) == execution.receipt["source_sha256"]
        execution.save()
        print((execution.evidence / "receipt.json").relative_to(ROOT).as_posix(), flush=True)
    raise SystemExit(execution.receipt["exit_code"])


if __name__ == "__main__":
    main()
