#!/usr/bin/env python3
"""Retain source-bound, advisory diagnostic execution without replacing L1."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid


ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("rtl", "software", "design", "tests", "hammer_v3_reference/rtl")


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stem", required=True)
    parser.add_argument("--tool", action="append", default=[])
    parser.add_argument("--repair-of")
    parser.add_argument("--timeout", type=int, default=3600)
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
    }
    if args.repair_of:
        previous = ROOT / args.repair_of
        if not previous.resolve().is_relative_to(ROOT / "evidence/preparation"):
            parser.error("--repair-of must identify a project preparation receipt")
        if not previous.is_file():
            parser.error("--repair-of receipt does not exist")
        receipt["repair_of"] = args.repair_of
    for index, tool in enumerate(args.tool):
        executable = shutil.which(tool)
        if executable is None:
            receipt["tool_versions"][tool] = {"available": False}
            continue
        version_file = out / f"tool-{index:02d}.log"
        with version_file.open("wb") as stream:
            result = subprocess.run(
                [tool, "--version"], cwd=ROOT, stdout=stream,
                stderr=subprocess.STDOUT, timeout=args.timeout, check=False,
            )
        receipt["tool_versions"][tool] = {
            "available": True, "argv": [tool, "--version"],
            "exit_code": result.returncode,
            "raw": version_file.relative_to(ROOT).as_posix(),
        }

    def save():
        (out / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )

    save()
    try:
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
        raise
    except OSError as error:
        receipt["launch_error"] = str(error)
        raise
    finally:
        receipt["ended_unix"] = time.time()
        receipt["sources_unchanged"] = receipt["source_sha256"] == source_hashes()
        save()
        print((relative / "receipt.json").as_posix(), flush=True)
    raise SystemExit(receipt["exit_code"])


if __name__ == "__main__":
    main()
