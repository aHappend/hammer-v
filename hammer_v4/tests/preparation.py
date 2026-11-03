#!/usr/bin/env python3
"""Retain source-bound, advisory diagnostic execution without replacing L1."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("rtl", "software", "design", "tests", "hammer_v3_reference/rtl")
TOOL_VERSION_ARGS = {
    "python3": ("--version",),
    "iverilog": ("-V",),
    "vvp": ("-V",),
    "verilator": ("--version",),
    "yosys": ("-V",),
    "make": ("--version",),
    "gcc": ("--version",),
    "g++": ("--version",),
    "dtc": ("--version",),
    "cpio": ("--version",),
    "tar": ("--version",),
    "xz": ("--version",),
    "bash": ("--version",),
    "bc": ("--version",),
    "bison": ("--version",),
    "flex": ("--version",),
    "perl": ("-v",),
    "/usr/bin/riscv64-unknown-elf-gcc": ("--version",),
    "/usr/bin/riscv64-unknown-elf-objcopy": ("--version",),
    "/usr/bin/riscv64-linux-gnu-gcc": ("--version",),
    "/usr/bin/riscv64-linux-gnu-objcopy": ("--version",),
}


def collect_tool_version(tool, raw, records, *, root=ROOT, timeout=3600):
    """Keep the failed command record too; never guess an unknown tool's CLI."""
    record = records[tool] = {
        "started_unix": time.time(), "ended_unix": None,
        "exit_code": None, "timeout_s": timeout, "timed_out": False,
        "cwd": ".", "raw": raw.as_posix(),
    }
    try:
        if tool not in TOOL_VERSION_ARGS:
            raise ValueError(f"No audited version command for tool: {tool}")
        argv = [tool, *TOOL_VERSION_ARGS[tool]]
        record["argv"] = argv
        record["available"] = shutil.which(tool) is not None
        if not record["available"]:
            raise RuntimeError(f"Cannot establish tool version; unavailable: {tool}")
        with (root / raw).open("wb") as stream:
            result = subprocess.run(
                argv, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                timeout=timeout, check=False,
            )
        record["exit_code"] = result.returncode
        if result.returncode:
            raise RuntimeError(f"Cannot establish tool version: {tool}")
    except subprocess.TimeoutExpired:
        record["timed_out"] = True
        raise
    finally:
        record["ended_unix"] = time.time()


def source_hashes():
    result = {}
    for directory in SOURCE_DIRS:
        for path in sorted((ROOT / directory).glob("*")):
            if not path.is_file():
                continue
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result[path.relative_to(ROOT).as_posix()] = digest.hexdigest()
    return result


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def retain_file(relative, directory):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or any(
        name in (".git", ".vulcan", ".tooling", "VULCAN") for name in path.parts
    ):
        raise ValueError(f"Not a deliverable-relative retained file: {relative}")
    source = ROOT / path
    resolved = source.resolve(strict=True)
    if source.is_symlink() or not resolved.is_relative_to(ROOT) or \
            not source.is_file():
        raise ValueError(f"Retained input is not a project regular file: {relative}")
    if any(name in (".git", ".vulcan", ".tooling", "VULCAN")
           for name in resolved.relative_to(ROOT).parts):
        raise ValueError(f"Retained input resolves into runtime metadata: {relative}")
    target = directory / "artifacts" / path
    target.parent.mkdir(parents=True, exist_ok=True)
    expected = file_hash(source)
    with source.open("rb") as src, target.open("xb") as dst:
        shutil.copyfileobj(src, dst)
    actual = file_hash(target)
    if actual != expected:
        raise RuntimeError(f"Retained input changed while copying: {relative}")
    return {"input": path.as_posix(), "path": target.relative_to(ROOT).as_posix(),
            "bytes": target.stat().st_size, "sha256": actual}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stem", required=True)
    parser.add_argument("--tool", action="append", default=[])
    parser.add_argument("--repair-of")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--retain-file", action="append", default=[],
                        help="copy an exact advisory artifact into this fresh receipt directory")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or not args.stem or any(
        c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in args.stem
    ):
        parser.error("provide a lowercase alphanumeric/hyphen stem and a command")
    if args.timeout < 3600:
        parser.error("diagnostic settlement timeout must be at least 3600 seconds")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "evidence/preparation" / (
        f"{args.stem}-{stamp}-{uuid.uuid4().hex[:8]}"
    )
    out.mkdir(parents=True, exist_ok=False)
    relative = out.relative_to(ROOT)
    receipt = {
        "schema": 1,
        "acceptance_evidence": False,
        "argv": command,
        "cwd": ".",
        "source_sha256": source_hashes(),
        "started_unix": time.time(),
        "timeout_s": args.timeout,
        "timed_out": False,
        "exit_code": None,
        "stdout": (relative / "stdout.log").as_posix(),
        "stderr": (relative / "stderr.log").as_posix(),
        "tool_versions": {},
        "retained_files": [],
    }
    if args.repair_of:
        previous = ROOT / args.repair_of
        if not previous.resolve().is_relative_to(ROOT / "evidence") or \
                previous.name != "receipt.json":
            parser.error("--repair-of must identify a project evidence receipt")
        if not previous.is_file():
            parser.error("--repair-of receipt does not exist")
        receipt["repair_of"] = args.repair_of
    def save():
        (out / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )

    save()
    try:
        for index, tool in enumerate(args.tool):
            collect_tool_version(
                tool, relative / f"tool-{index:02d}.log",
                receipt["tool_versions"], root=ROOT, timeout=args.timeout,
            )
            save()
        with (out / "stdout.log").open("wb") as stdout, (
            out / "stderr.log"
        ).open("wb") as stderr:
            result = subprocess.run(
                command, cwd=ROOT, stdout=stdout, stderr=stderr,
                timeout=args.timeout, check=False,
            )
            receipt["exit_code"] = result.returncode
    except subprocess.TimeoutExpired:
        receipt["timed_out"] = True
        receipt["exit_code"] = 1
        raise
    except OSError as error:
        receipt["launch_error"] = str(error)
        receipt["exit_code"] = 1
        raise
    except (RuntimeError, ValueError) as error:
        receipt["exit_code"] = 1
        receipt["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        try:
            for path in args.retain_file:
                receipt["retained_files"].append(retain_file(path, out))
        except (OSError, ValueError, RuntimeError) as error:
            receipt["retention_failure"] = {"type": type(error).__name__, "message": str(error)}
            receipt["exit_code"] = 1
            print(f"PREPARATION_RETENTION_FAILED {error}", file=sys.stderr, flush=True)
        receipt["ended_unix"] = time.time()
        receipt["sources_unchanged"] = receipt["source_sha256"] == source_hashes()
        save()
        print((relative / "receipt.json").as_posix(), flush=True)
    raise SystemExit(receipt["exit_code"])


if __name__ == "__main__":
    main()
