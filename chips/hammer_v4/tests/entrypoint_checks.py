#!/usr/bin/env python3
"""Bounded negative checks for the L1 runner; never execute its full suite."""

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify import REQUIREMENTS, TOOLS, prerequisites, stages
import preparation
import verify
from preparation import TOOL_VERSION_ARGS, collect_tool_version


def version_checks(out):
    expected = {
        "python3": "--version", "iverilog": "-V", "vvp": "-V",
        "verilator": "--version", "yosys": "-V", "make": "--version",
        "gcc": "--version", "g++": "--version", "dtc": "--version",
        "cpio": "--version", "tar": "--version", "xz": "--version",
        "bash": "--version", "bc": "--version", "bison": "--version",
        "flex": "--version", "perl": "-v",
        "/usr/bin/riscv64-unknown-elf-gcc": "--version",
        "/usr/bin/riscv64-unknown-elf-objcopy": "--version",
        "/usr/bin/riscv64-linux-gnu-gcc": "--version",
        "/usr/bin/riscv64-linux-gnu-objcopy": "--version",
    }
    if set(expected) != set(TOOLS) or \
            TOOL_VERSION_ARGS != {tool: (flag,) for tool, flag in expected.items()}:
        raise AssertionError("Tool-version dispatch differs from audited command set")
    records = {}
    for index, (tool, flag) in enumerate(expected.items()):
        raw = (out / f"version-{index:02d}.log").relative_to(ROOT)
        collect_tool_version(tool, raw, records)
        if records[tool]["argv"] != [tool, flag] or records[tool]["exit_code"] != 0 or \
                not (ROOT / raw).stat().st_size:
            raise AssertionError(f"Actual supported version command failed: {tool}")
    (out / "tool-versions.json").write_text(json.dumps(records, indent=2) + "\n")

    def failed(argv, **kwargs):
        if argv != ["iverilog", "-V"]:
            raise AssertionError(f"Wrong version dispatch: {argv}")
        kwargs["stdout"].write(b"deliberate version-command failure\n")
        return subprocess.CompletedProcess(argv, 23)

    rejections = []
    for module in (verify, preparation):
        with tempfile.TemporaryDirectory(prefix=f"{module.__name__}-failure-", dir=out) as name:
            fixture = Path(name)
            arguments = ["fixture"] if module is verify else [
                "fixture", "--stem", "version-rejection", "--tool", "iverilog",
                "--", "never-execute-stage",
            ]
            with patch.object(module, "ROOT", fixture), \
                    patch.object(module, "source_hashes", return_value={}), \
                    patch.object(sys, "argv", arguments), \
                    patch.object(preparation.shutil, "which", return_value="/fixture"), \
                    patch.object(preparation.subprocess, "run", side_effect=failed) as run, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                # Resolve the fixture root at the call site for preparation,
                # whose helper's ordinary default intentionally is immutable.
                def collect(tool, raw, versions, **kwargs):
                    return collect_tool_version(tool, raw, versions, root=fixture)
                patches = [patch.object(module, "collect_tool_version", side_effect=collect)]
                if module is verify:
                    patches.append(patch.object(
                        verify, "prerequisites",
                        return_value={"missing_sources": [], "missing_tools": []},
                    ))
                with patches[0]:
                    if len(patches) == 2:
                        with patches[1], patch.object(verify, "TOOLS", ("iverilog",)):
                            try:
                                module.main()
                            except SystemExit as error:
                                if error.code != 1:
                                    raise AssertionError("L1 failed version did not exit 1")
                            else:
                                raise AssertionError("L1 version failure was accepted")
                    else:
                        try:
                            module.main()
                        except RuntimeError as error:
                            if "Cannot establish tool version" not in str(error):
                                raise
                        else:
                            raise AssertionError("Preparation version failure was accepted")
                if run.call_count != 1:
                    raise AssertionError("A design/stage command ran after failed version")
            receipts = list((fixture / "evidence").glob("**/receipt.json"))
            if len(receipts) != 1:
                raise AssertionError("Failed entrypoint did not retain exactly one receipt")
            receipt = json.loads(receipts[0].read_text())
            version = receipt["tool_versions"]["iverilog"]
            if receipt["exit_code"] != 1 or version["exit_code"] != 23 or \
                    version["argv"] != ["iverilog", "-V"] or \
                    (fixture / version["raw"]).read_bytes() != \
                    b"deliberate version-command failure\n" or \
                    any(record["status"] != "not_run" for record in receipt.get("stages", [])):
                raise AssertionError("Version failure lost its raw record or executed a stage")
            (out / f"{module.__name__}-failed-version-receipt.json").write_text(
                json.dumps(receipt, indent=2) + "\n")
            (out / f"{module.__name__}-failed-version.log").write_bytes(
                (fixture / version["raw"]).read_bytes())
            rejections.append(module.__name__)
    return {"actual_commands": len(records), "failed_entrypoints_rejected": rejections}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    versions = version_checks(out)
    commands = stages(Path("build/fixture-not-executed"))
    if [name for name, _ in commands] != list(REQUIREMENTS):
        raise AssertionError("Requirement/command ordering differs")
    command_map = dict(commands)
    required = {
        "parameters", "arithmetic", "sv39-leaf", "mmu", "timer", "firmware",
        "fdt-boot", "smode", "reference", "compatibility", "temporal", "mutations",
        "synthesis", "build-paths", "software-reproduction", "timed-system",
        "software-build", "assets",
    }
    if set(command_map) != required:
        raise AssertionError("Missing or unexpected mandatory L1 stage")
    for name in ("mutations", "compatibility", "timer", "mmu"):
        if any(flag in command_map[name] for flag in (
            "--case", "--v4-only", "--generate-only", "--skip", "--only"
        )):
            raise AssertionError(f"Mandatory {name} has a reduced default")
    if any(token in " ".join(argv) for _, argv in commands
           for token in (".vulcan/", ".tooling/", "VULCAN/", ".git/")):
        raise AssertionError("Runtime metadata used by L1")
    for _, argv in commands:
        if argv[0] != "python3" or Path(argv[1]).is_absolute():
            raise AssertionError("L1 command is not project-relative")

    cases = []
    with tempfile.TemporaryDirectory(prefix="prerequisites-", dir=out) as name:
        fixture = Path(name)
        exists = lambda tool: "/fixture-only/never-executed"
        missing = prerequisites(commands, root=fixture, which=exists)
        expected = sorted({argv[1] for _, argv in commands} | {"tests/system_oracle.py"})
        if sorted(missing["missing_sources"]) != expected or missing["missing_tools"]:
            raise AssertionError("Empty fixture missing-source detection")
        cases.append({"case": "all_sources_absent", "missing_sources": expected})
        for path in expected:
            target = fixture / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# Existence-only fixture; never imported or executed.\n")
        if any(prerequisites(commands, root=fixture, which=exists).values()):
            raise AssertionError("Complete existence fixture rejected")
        for absent in ("tests/system_oracle.py", "tests/system_checks.py",
                       "tests/synthesis.py"):
            (fixture / absent).unlink()
            missing = prerequisites(commands, root=fixture, which=exists)
            if missing != {"missing_sources": [absent], "missing_tools": []}:
                raise AssertionError(f"Mandatory source silently omitted: {absent}")
            cases.append({"case": "mandatory_source_absent", "source": absent})
            (fixture / absent).write_text("# Existence-only fixture.\n")
        for absent in ("yosys", "verilator", "/usr/bin/riscv64-linux-gnu-gcc"):
            missing = prerequisites(
                commands, root=fixture, which=lambda tool: None if tool == absent else exists(tool)
            )
            if missing != {"missing_sources": [], "missing_tools": [absent]}:
                raise AssertionError(f"Missing tool silently omitted: {absent}")
            cases.append({"case": "mandatory_tool_absent", "tool": absent})

    records = []
    for arguments in (["--describe"], ["--skip-timed-system"], ["--only", "arithmetic"]):
        argv = ["python3", "tests/verify.py", *arguments]
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
        index = len(records)
        (out / f"{index}.stdout.log").write_bytes(result.stdout)
        (out / f"{index}.stderr.log").write_bytes(result.stderr)
        records.append({"argv": argv, "cwd": ".", "exit_code": result.returncode})
        (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if arguments == ["--describe"]:
            described = json.loads(result.stdout)
            if result.returncode or described["scope"] != \
                    "description only, no verification executed":
                raise AssertionError("L1 description incorrectly implies execution")
            if {stage["id"] for stage in described["stages"]} != required:
                raise AssertionError("L1 description omits mandatory stages")
        elif result.returncode != 2 or b"unrecognized arguments" not in result.stderr:
            raise AssertionError("L1 accepted an unsupported partial-suite option")
    (out / "summary.json").write_text(json.dumps({
        "scope": "runner source/CLI negative tests only; no L1 design acceptance",
        "stages": len(commands), "declared_tools": len(TOOLS),
        "prerequisite_cases": cases, "reduced_suite_options_rejected": 2,
        "actual_project_prerequisites": prerequisites(commands),
        "tool_versions": versions,
    }, indent=2) + "\n")
    print(f"COMPARED L1 stages={len(commands)} prerequisite_cases={len(cases)} "
          "reduced_suite_options_rejected=2; no full suite executed")


if __name__ == "__main__":
    main()
