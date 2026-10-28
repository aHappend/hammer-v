"""Fresh, source-bound command receipts shared by portable suites and probes."""

from datetime import datetime, timezone
import errno
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def sources(root=ROOT):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for pattern in ("rtl/*.sv", "design/*.md", "tests/*")
            for p in sorted(root.glob(pattern)) if p.is_file()}


def fresh(parent, label):
    path = parent / (label + "-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True, exist_ok=False)
    return path


def timestamp():
    return datetime.now(timezone.utc).isoformat()


class ToolFailure(RuntimeError):
    pass


class Evidence:
    def __init__(self, suite, preparation=False):
        self.directory = fresh(ROOT / "evidence" / ("preparation" if preparation else "runs"), suite)
        self.commands = []
        self.hashes = sources()
        self.start = timestamp()
        self.tool_versions = {}
        self.version("python3")

    def version(self, tool):
        if tool not in self.tool_versions:
            if (Path(tool).name not in ("iverilog", "vvp", "yosys", "verilator", "make", "g++", "python3")
                    and not Path(tool).name.startswith(("clang", "riscv64-"))):
                return "project-built executable; see source-bound build receipt"
            flag = "-V" if tool in ("iverilog", "vvp", "yosys") else "--version"
            folder = fresh(self.directory, "version-" + Path(tool).name)
            record = {"argv": [tool, flag], "cwd": ".", "source_sha256": self.hashes,
                      "start_time": timestamp(), "timeout_s": 60, "timed_out": False,
                      "exit_code": None, "stdout": str((folder / "stdout.log").relative_to(ROOT)),
                      "stderr": str((folder / "stderr.log").relative_to(ROOT))}
            with (folder / "stdout.log").open("wb") as out, (folder / "stderr.log").open("wb") as err:
                try:
                    result = subprocess.run([tool, flag], cwd=ROOT, stdout=out, stderr=err, timeout=60)
                    record["exit_code"] = result.returncode
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
            self.tool_versions[tool] = ((folder / "stdout.log").read_text() +
                                        (folder / "stderr.log").read_text()).strip()
            record["end_time"] = timestamp()
            record["tool_version"] = self.tool_versions[tool]
            (folder / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
            self.commands.append(str((folder / "receipt.json").relative_to(ROOT)))
            if record["timed_out"] or record["exit_code"] != 0:
                raise ToolFailure(f"tool version query failed: {self.commands[-1]}")
        return self.tool_versions[tool]

    def command(self, argv, cwd=ROOT, timeout=3600, expect_failure=False):
        folder = fresh(self.directory, f"command-{len(self.commands):04d}")
        cwd = Path(cwd)
        record = {"argv": [str(v) for v in argv], "cwd": str(cwd.relative_to(ROOT)),
                  "source_sha256": self.hashes, "start_time": timestamp(),
                  "timeout_s": timeout, "timed_out": False, "exit_code": None,
                  "tool_version": self.version(str(argv[0])),
                  "stdout": str((folder / "stdout.log").relative_to(ROOT)),
                  "stderr": str((folder / "stderr.log").relative_to(ROOT)),
                  "expected_negative": expect_failure}
        record["additional_source_sha256"] = {}
        for argument in argv:
            relative = str(argument).removeprefix("+input=")
            candidate = cwd / relative
            try:
                is_file = candidate.is_file()
            except OSError as error:
                if error.errno != errno.ENAMETOOLONG:
                    raise
                is_file = False
            if is_file:
                record["additional_source_sha256"][relative] = hashlib.sha256(candidate.read_bytes()).hexdigest()
        start = time.monotonic()
        try:
            with (folder / "stdout.log").open("wb") as out, (folder / "stderr.log").open("wb") as err:
                process = subprocess.run([str(v) for v in argv], cwd=cwd, stdout=out, stderr=err, timeout=timeout)
                record["exit_code"] = process.returncode
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
        finally:
            record["end_time"] = timestamp()
            record["duration_s"] = time.monotonic() - start
            (folder / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
            self.commands.append(str((folder / "receipt.json").relative_to(ROOT)))
        if record["timed_out"] or (record["exit_code"] != 0 and not expect_failure):
            raise ToolFailure(f"tool execution failed: {self.commands[-1]}")
        return folder, record

    def finish(self, status, **fields):
        record = {"argv": __import__("sys").orig_argv, "cwd": ".", "source_sha256": self.hashes,
                  "start_time": self.start, "end_time": timestamp(),
                  "timeout_s": 2700, "exit_code": 0 if status == "passed" else 1,
                  "timed_out": False, "tool_version": self.tool_versions,
                  "commands": self.commands, "status": status, **fields}
        commands = [json.loads((ROOT / path).read_text()) for path in self.commands]
        record["stdout"] = [command["stdout"] for command in commands]
        record["stderr"] = [command["stderr"] for command in commands]
        (self.directory / "receipt.json").write_text(json.dumps(record, indent=2) + "\n")
        return str((self.directory / "receipt.json").relative_to(ROOT))


def require(*tools):
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        raise ToolFailure("PREREQUISITE_MISSING: " + ", ".join(missing))
