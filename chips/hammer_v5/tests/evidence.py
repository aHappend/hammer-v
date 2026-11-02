#!/usr/bin/env python3
"""Retained, source-bound preparation execution; not runtime acceptance records."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Evidence:
    def __init__(self, name, selectors, repair_of=None):
        self.directory = ROOT / "evidence" / "preparation" / f"{name}-{stamp()}"
        self.directory.mkdir(parents=True, exist_ok=False)
        self.record = {
            "schema": 1, "kind": "verifier-preparation", "start": stamp(),
            "cwd": ".", "sources_sha256": {}, "commands": [], "tools": {},
            "exit": None,
        }
        if repair_of is not None:
            prior = ROOT / repair_of
            self.record["repair_of"] = {
                "path": repair_of, "sha256": digest(prior),
            }
        for selector in selectors:
            files = sorted(ROOT.glob(selector))
            if not files:
                raise FileNotFoundError(f"source selector has no matches: {selector}")
            for source in files:
                if source.is_file():
                    relative = source.relative_to(ROOT)
                    destination = self.directory / "sources" / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
                    self.record["sources_sha256"][relative.as_posix()] = digest(source)
        self.save()

    def relative(self, path):
        return path.resolve().relative_to(ROOT).as_posix()

    def save(self):
        (self.directory / "receipt.json").write_text(
            json.dumps(self.record, indent=2) + "\n")

    def run(self, argv, label, cwd=ROOT, timeout_s=3600, expected_exit=0):
        stdout = self.directory / f"{label}.stdout.txt"
        stderr = self.directory / f"{label}.stderr.txt"
        command = {
            "argv": [str(arg) for arg in argv], "cwd": self.relative(cwd),
            "start": stamp(), "timeout_s": timeout_s, "timed_out": False,
            "exit": None, "stdout": self.relative(stdout),
            "stderr": self.relative(stderr),
        }
        self.record["commands"].append(command)
        self.save()
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with stdout.open("wb") as out, stderr.open("wb") as err:
            try:
                process = subprocess.Popen(
                    command["argv"], cwd=cwd, env=environment, stdout=out, stderr=err)
                started = datetime.now(timezone.utc)
                while True:
                    try:
                        command["exit"] = process.wait(timeout=30)
                        break
                    except subprocess.TimeoutExpired:
                        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
                        print(f"PROGRESS {label}: tool executing, elapsed={int(elapsed)}s",
                              flush=True)
                        if timeout_s is not None and elapsed >= timeout_s:
                            command["timed_out"] = True
                            process.terminate()
                            try:
                                command["exit"] = process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                process.kill()
                                command["exit"] = process.wait()
                            break
            except OSError as error:
                err.write((str(error) + "\n").encode())
                command["launch_error"] = str(error)
            finally:
                command["end"] = stamp()
                self.save()
        permitted = (expected_exit,) if isinstance(expected_exit, int) else tuple(expected_exit)
        if command["timed_out"] or command["exit"] not in permitted:
            raise RuntimeError(
                f"{label}: exit={command['exit']} timeout={command['timed_out']}; "
                f"see {command['stderr']} and {command['stdout']}")
        return stdout.read_text(errors="replace")

    def version(self, tool, arguments=("--version",)):
        text = self.run([tool, *arguments], f"version-{tool}")
        self.record["tools"][tool] = {"argv": [tool, *arguments], "version": text}
        self.save()

    def finish(self, exit_code, error=None):
        self.record.update(end=stamp(), exit=exit_code)
        if error is not None:
            self.record["error"] = str(error)
        self.save()
        return self.relative(self.directory / "receipt.json")
