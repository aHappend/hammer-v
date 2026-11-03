#!/usr/bin/env python3
"""Retained, source-bound preparation execution; not runtime acceptance records."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
DEADLINE_ENV = "HAMMER_V5_CHECK_DEADLINE"
_deadline = None


def invocation_deadline():
    global _deadline
    if _deadline is None:
        inherited = float(os.environ.get(DEADLINE_ENV, "inf"))
        _deadline = min(inherited, time.time() + 2700)
        if not 0 < _deadline < float("inf"):
            raise ValueError("invalid inherited verification deadline")
        os.environ[DEADLINE_ENV] = str(_deadline)
    return _deadline


def remaining_seconds():
    remaining = invocation_deadline() - time.time()
    if remaining <= 0:
        raise RuntimeError("absolute verification invocation deadline exhausted")
    return remaining


def process_identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[1]), fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def cancel_owned_process(process, identity):
    """Signal only the launched process and descendants with rechecked identities."""
    root = process.pid
    if identity is None or process_identity(root) != identity:
        return []
    owned = {root: identity}
    pending = [root]
    while pending:
        parent = pending.pop()
        try:
            tasks = list(Path(f"/proc/{parent}/task").iterdir())
            for task in tasks:
                children = (task / "children").read_text().split()
                for child in children:
                    pid = int(child)
                    token = process_identity(pid)
                    if token is not None and token[0] == parent and pid not in owned:
                        owned[pid] = token
                        pending.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
    signaled = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, token in reversed(list(owned.items())):
            current = process_identity(pid)
            # A descendant may be reparented after its parent exits.
            if current is not None and current[1] == token[1]:
                try:
                    os.kill(pid, sig)
                    signaled.append({"pid": pid, "start_ticks": token[1],
                                     "signal": sig.name})
                except ProcessLookupError:
                    pass
        if sig == signal.SIGTERM:
            time.sleep(1)
    process.wait()
    return signaled


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Evidence:
    def __init__(self, name, selectors, repair_of=None, preparation=True):
        remaining_seconds()
        base = ROOT / "evidence"
        if preparation:
            base = base / "preparation"
        self.directory = base / f"{name}-{stamp()}"
        self.directory.mkdir(parents=True, exist_ok=False)
        self.record = {
            "schema": 1,
            "kind": "verifier-preparation" if preparation else "l1-verification",
            "start": stamp(),
            "cwd": ".", "sources_sha256": {}, "commands": [], "tools": {},
            "exit": None,
            "absolute_deadline_unix": invocation_deadline(),
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
                remaining_seconds()
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
        budget = remaining_seconds()
        interpreted = Path(str(argv[0])).name == "vvp"
        requested_timeout = timeout_s
        timeout_s = min(budget, timeout_s if timeout_s is not None else budget,
                        600 if interpreted else budget)
        stdout = self.directory / f"{label}.stdout.txt"
        stderr = self.directory / f"{label}.stderr.txt"
        serial = 1
        while stdout.exists() or stderr.exists():
            serial += 1
            stdout = self.directory / f"{label}-{serial}.stdout.txt"
            stderr = self.directory / f"{label}-{serial}.stderr.txt"
        command = {
            "argv": [str(arg) for arg in argv], "cwd": self.relative(cwd),
            "start": stamp(), "timeout_s": timeout_s, "timed_out": False,
            "requested_timeout_s": requested_timeout,
            "absolute_deadline_unix": invocation_deadline(),
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
                identity = process_identity(process.pid)
                command["process"] = {"pid": process.pid,
                                      "identity": identity}
                self.save()
                started = time.monotonic()
                while True:
                    try:
                        elapsed = time.monotonic() - started
                        wait = min(30, max(0, timeout_s - elapsed),
                                   max(0, invocation_deadline() - time.time()))
                        command["exit"] = process.wait(timeout=wait)
                        break
                    except subprocess.TimeoutExpired:
                        elapsed = time.monotonic() - started
                        print(f"PROGRESS {label}: tool executing, elapsed={int(elapsed)}s",
                              flush=True)
                        if elapsed >= timeout_s or time.time() >= invocation_deadline():
                            command["timed_out"] = True
                            command["cancellation"] = cancel_owned_process(process, identity)
                            command["exit"] = process.returncode
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
