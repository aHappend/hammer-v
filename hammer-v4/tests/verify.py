#!/usr/bin/env python3
"""Mandatory portable L1 entrypoint; component results cannot qualify a boot.

Every invocation uses fresh output directories and executes its prerequisites.
In particular, no old preparation receipt or DUT transcript is a passing cache.
The full-system checker must supply the independently timed, complete-stream
seed runs and clean RTL reproduction before this command can succeed.
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
from preparation import collect_tool_version, source_hashes


TOOLS = (
    "python3", "iverilog", "vvp", "verilator", "yosys", "make", "gcc", "g++",
    "dtc", "cpio", "tar", "xz", "bash", "bc", "bison", "flex", "perl",
    "/usr/bin/riscv64-unknown-elf-gcc",
    "/usr/bin/riscv64-unknown-elf-objcopy",
    "/usr/bin/riscv64-linux-gnu-gcc",
    "/usr/bin/riscv64-linux-gnu-objcopy",
)

REQUIREMENTS = {
    "software-build": "actual firmware, DTB, upstream Linux 6.6.1 and static /init",
    "assets": "ELF/ISA, FDT, layout, source/build hashes and compiler invocations",
    "parameters": "legal boundaries, illegal rejection, reset, host/start/halt and retirement",
    "arithmetic": "independent M-extension numerical comparisons",
    "sv39-leaf": "canonicality, leaf sizes, alignment, permissions and software A/D faults",
    "mmu": "real walks, PTE bus errors, MPRV, scoped/global fences, stalls and cancellation",
    "timer": "clock-exact CLINT/CSR values, wrap, strobes, errors and backpressure",
    "firmware": "real SBI, delegation, timer delivery, nested contexts and translated U execution",
    "fdt-boot": "real firmware/kernel rejection of malformed FDT",
    "smode": "actual kernel S-mode misalignment emulation, nofault and trap context",
    "reference": "independent ISA reference on hand-derived cases and actual firmware",
    "compatibility": "parent-compatible host/AXI/accelerator coherence and LR/SC",
    "temporal": "pre-frozen timer edges and read/timestamp comparator defect sensitivity",
    "mutations": "unchanged controls and compiled functional/temporal disposable defects",
    "synthesis": "real full-default Yosys hierarchy/connectivity, state, RAM and zero latches",
    "build-paths": "protected, symlink and occupied output-path rejection",
    "software-reproduction": "clean source build/audit and all nine exact image comparisons",
    "timed-system": (
        "independent pre-frozen full UART oracle; real seeds 11/29/47; architectural "
        "milestones, page-fault retries, syscalls, timers and UART PLIC claim/complete; "
        "clean default-seed full RTL reproduction"
    ),
}


def stages(build):
    """Keep the original complete check mandatory; there is no subset selector."""
    manifest = (build / "software/image-manifest.json").as_posix()

    def command(script, directory, *arguments):
        return [
            "python3", script, "--out", (build / directory).as_posix(),
            *map(str, arguments),
        ]

    return [
        ("software-build", command("software/build.py", "software", "--jobs", "4")),
        ("assets", command("tests/asset_checks.py", "assets", "--manifest", manifest)),
        ("parameters", command("tests/parameters.py", "parameters")),
        ("arithmetic", command("tests/arithmetic_checks.py", "arithmetic")),
        ("sv39-leaf", command("tests/leaf_checks.py", "sv39-leaf")),
        ("mmu", command("tests/mmu_checks.py", "mmu")),
        ("timer", command("tests/timer_checks.py", "timer")),
        ("firmware", command("tests/firmware_checks.py", "firmware", "--manifest", manifest)),
        ("fdt-boot", command("tests/fdt_boot_checks.py", "fdt-boot", "--manifest", manifest)),
        ("smode", command("tests/smode_checks.py", "smode",
                          "--software", build / "software")),
        ("reference", command("tests/reference_checks.py", "reference",
                              "--manifest", manifest)),
        ("compatibility", command("tests/compatibility_checks.py", "compatibility")),
        ("temporal", command("tests/temporal_checks.py", "temporal",
                             "--manifest", manifest)),
        ("mutations", command("tests/mutation_checks.py", "mutations",
                              "--manifest", manifest)),
        ("synthesis", command("tests/synthesis.py", "synthesis")),
        ("build-paths", command("tests/build_path_checks.py", "build-paths",
                               "--occupied", build / "software")),
        ("software-reproduction", command("tests/reproduction_checks.py",
                                          "software-reproduction",
                                          "--compare-manifest", manifest)),
        ("timed-system", command("tests/system_checks.py", "timed-system",
                                 "--manifest", manifest)),
    ]


def prerequisites(commands, root=ROOT, which=shutil.which):
    missing_sources = sorted({argv[1] for _, argv in commands
                              if not (root / argv[1]).is_file()})
    # The architectural interpreter alone is explicitly untimed and is not a
    # substitute for this separately required expectation-generation entrypoint.
    if not (root / "tests/system_oracle.py").is_file():
        missing_sources.append("tests/system_oracle.py")
    missing_tools = [name for name in TOOLS if which(name) is None]
    return {"missing_sources": missing_sources, "missing_tools": missing_tools}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--describe", action="store_true",
                        help="print the complete command/requirement mapping without executing it")
    args = parser.parse_args()
    tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    build = Path("build") / f"l1-system-validation-{tag}"
    commands = stages(build)
    if [name for name, _ in commands] != list(REQUIREMENTS):
        raise AssertionError("L1 command/requirement mapping is incomplete")
    if args.describe:
        print(json.dumps({
            "scope": "description only, no verification executed",
            "stages": [{"id": name, "argv": argv, "requires": REQUIREMENTS[name]}
                       for name, argv in commands],
            "prerequisites": prerequisites(commands),
        }, indent=2))
        return

    relative = Path("evidence") / f"l1-system-validation-{tag}"
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema": 1, "argv": ["python3", "tests/verify.py"], "cwd": ".",
        "started_unix": time.time(), "ended_unix": None,
        "status": "running", "exit_code": None,
        "source_sha256": source_hashes(), "build": build.as_posix(),
        "requirements": REQUIREMENTS,
        "stages": [{"id": name, "argv": argv, "cwd": ".", "status": "not_run"}
                   for name, argv in commands],
        "tool_versions": {},
    }

    def save():
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")

    save()
    try:
        missing = prerequisites(commands)
        receipt["prerequisites"] = missing
        if any(missing.values()):
            raise RuntimeError(
                "Incomplete mandatory L1 prerequisites: " + json.dumps(missing, sort_keys=True)
            )
        for index, tool in enumerate(TOOLS):
            collect_tool_version(
                tool, relative / f"tool-{index:02d}.log", receipt["tool_versions"],
                root=ROOT,
            )
            save()
        (ROOT / build).mkdir(parents=True, exist_ok=False)
        for index, record in enumerate(receipt["stages"]):
            name = record["id"]
            record.update(status="running", started_unix=time.time())
            record["stdout"] = (relative / f"{index:02d}-{name}.stdout.log").as_posix()
            record["stderr"] = (relative / f"{index:02d}-{name}.stderr.log").as_posix()
            save()
            print(f"L1_STAGE_START id={name}", flush=True)
            with (ROOT / record["stdout"]).open("wb") as so, (
                ROOT / record["stderr"]
            ).open("wb") as se:
                with subprocess.Popen(record["argv"], cwd=ROOT, stdout=so, stderr=se) as child:
                    while True:
                        try:
                            result = child.wait(timeout=20)
                            break
                        except subprocess.TimeoutExpired:
                            print(
                                f"L1_STAGE_ACTIVE id={name} "
                                f"elapsed_s={time.time() - record['started_unix']:.1f} "
                                f"stdout_bytes={so.tell()} stderr_bytes={se.tell()}",
                                flush=True,
                            )
            record.update(ended_unix=time.time(), exit_code=result,
                          status="passed" if result == 0 else "failed")
            save()
            if result:
                raise RuntimeError(f"Mandatory L1 stage failed: {name}; see {record['stderr']}")
            print(f"L1_STAGE_COMPLETE id={name}", flush=True)
        if receipt["source_sha256"] != source_hashes():
            raise RuntimeError("Verification sources changed during mandatory L1 execution")
        receipt.update(status="passed", exit_code=0)
    except Exception as error:
        receipt.update(status="failed", exit_code=1,
                       failure={"type": type(error).__name__, "message": str(error)})
        print(f"L1_FAILED {error}", file=sys.stderr, flush=True)
    finally:
        receipt["ended_unix"] = time.time()
        receipt["sources_unchanged"] = receipt["source_sha256"] == source_hashes()
        save()
        print((relative / "receipt.json").as_posix(), flush=True)
    raise SystemExit(receipt["exit_code"])


if __name__ == "__main__":
    main()
