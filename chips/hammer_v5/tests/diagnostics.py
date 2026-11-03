#!/usr/bin/env python3
"""Bounded verifier-owned deadline tests and public architectural boot profiling."""
import argparse
import bisect
import json
import os
from pathlib import Path
import sys
import time

from evidence import Evidence, ROOT, digest


WORKER = r"""
import os, subprocess, sys
from evidence import Evidence
ev=Evidence("deadline-child", ("tests/evidence.py",))
try:
    if sys.argv[1]=="nested":
        ev.run([sys.executable, "-c", sys.argv[2], "leaf"], "nested",
               timeout_s=None)
    else:
        ev.run([sys.executable, "-c",
                "import subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
                "print(p.pid,flush=True); time.sleep(60)"], "sleeper",
               timeout_s=86400)
except RuntimeError as error:
    print(ev.finish(1,error),flush=True)
    sys.exit(1)
sys.exit("deadline unexpectedly permitted completion")
"""


def deadline_probe(ev):
    worker = ev.directory / "deadline_worker.py"
    worker.write_text(WORKER)
    ev.record["generated_sha256"] = {ev.relative(worker): digest(worker)}
    old = os.environ.get("HAMMER_V5_CHECK_DEADLINE")
    deadline = time.time() + 4
    try:
        os.environ["HAMMER_V5_CHECK_DEADLINE"] = str(deadline)
        ev.run([sys.executable, ev.relative(worker), "nested", WORKER],
               "nested-deadline", expected_exit=(1, -15, -9), timeout_s=None)
    except RuntimeError as error:
        if not ev.record["commands"][-1]["timed_out"]:
            raise
        ev.record["expected_timeout"] = str(error)
    finally:
        if old is None:
            os.environ.pop("HAMMER_V5_CHECK_DEADLINE", None)
        else:
            os.environ["HAMMER_V5_CHECK_DEADLINE"] = old
    command = ev.record["commands"][-1]
    if not command["timed_out"] or command["exit"] == 0:
        raise AssertionError("nested deadline did not reject unfinished execution")
    if not command.get("cancellation"):
        raise AssertionError("deadline did not record owned process cancellation")
    # Killed descendants may be zombies until the host reaps them, but cannot run.
    for token in command["cancellation"]:
        path = Path(f"/proc/{token['pid']}/stat")
        if path.exists():
            fields = path.read_text().rsplit(")", 1)[1].split()
            if fields[19] == token["start_ticks"] and fields[0] != "Z":
                raise AssertionError("owned process still executing after timeout")
    ev.record["observed"] = {"nested_timeout": True, "descendants_stopped": True}


def boot_profile(ev, images, cycles, prefetch):
    from boot import boot_probe, checked_images
    directory, _ = checked_images(ev, images)
    kernel = directory / "vmlinux"
    ev.record["kernel_sha256"] = digest(kernel)
    ev.version("riscv64-linux-gnu-nm")
    symbols = ev.run(["riscv64-linux-gnu-nm", "-n", ev.relative(kernel)],
                     "kernel-symbols")
    functions = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in ("t", "T"):
            functions.append((int(fields[0], 16), fields[2]))
    functions.sort()
    addresses = [address for address, _ in functions]
    error = None
    try:
        boot_probe(ev, images, cycles, "userland", prefetch)
    except RuntimeError as failure:
        error = str(failure)
    samples = ev.directory / "pc-samples.txt"
    if not samples.exists():
        raise RuntimeError(error or "boot profile samples missing")
    histogram = {}
    for line in samples.read_text().splitlines():
        pc, count = line.split()
        index = bisect.bisect_right(addresses, int(pc, 16)) - 1
        name = functions[index][1] if index >= 0 else "firmware-or-unmapped"
        histogram[name] = histogram.get(name, 0) + int(count)
    ev.record["profile"] = {
        "kernel_sha256": digest(kernel),
        "metrics": json.loads((ev.directory / "boot-profile.json").read_text()),
        "cycle_weighted_functions": sorted(histogram.items(),
                                          key=lambda item: -item[1])[:40],
        "boot_error": error,
    }
    ev.save()
    if error is not None:
        raise RuntimeError(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", choices=("deadlines", "boot-profile"), required=True)
    parser.add_argument("--images")
    parser.add_argument("--cycles", type=int, default=500000000)
    parser.add_argument("--prefetch", type=int, choices=(0, 1), default=1)
    args = parser.parse_args()
    ev = Evidence("v5-" + args.probe,
                  ("rtl/*.sv", "tests/*.py", "software/*", "design/*.md"))
    ev.record["argv"] = ["python3", "tests/diagnostics.py", *sys.argv[1:]]
    error = None
    try:
        ev.version("python3")
        if args.probe == "deadlines":
            deadline_probe(ev)
        else:
            if not args.images or args.cycles <= 0:
                raise ValueError("boot profile requires local images and positive cycles")
            boot_profile(ev, args.images, args.cycles, args.prefetch)
    except (OSError, ValueError, RuntimeError, AssertionError) as failure:
        error = str(failure)
    path = ev.finish(0 if error is None else 1, error)
    print(json.dumps({"receipt": path, "error": error, "exit": ev.record["exit"]}))
    return ev.record["exit"]


if __name__ == "__main__":
    sys.exit(main())
