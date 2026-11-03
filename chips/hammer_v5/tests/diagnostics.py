#!/usr/bin/env python3
"""Bounded verifier-owned deadline tests and public architectural boot profiling."""
import argparse
import bisect
import difflib
import json
import os
from pathlib import Path
import shutil
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence import Evidence, ROOT, digest, stamp


WORKER = r"""
import os, subprocess, sys, time
sys.path.insert(0,"tests")
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
    if time.time()<ev.record["absolute_deadline_unix"]:
        raise
    before=len(ev.record["commands"])
    try:
        ev.run([sys.executable,"-c","print('unexpected scheduling')"],"after-expiry")
    except RuntimeError:
        if len(ev.record["commands"])!=before:
            raise AssertionError("scheduled work after expiry")
        ev.record["stopped_scheduling"]=True
    else:
        raise AssertionError("deadline reset allowed new work")
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
        output = ev.run([sys.executable, ev.relative(worker), "nested", WORKER],
                        "nested-deadline", expected_exit=1, timeout_s=None)
    finally:
        if old is None:
            os.environ.pop("HAMMER_V5_CHECK_DEADLINE", None)
        else:
            os.environ["HAMMER_V5_CHECK_DEADLINE"] = old
    child_path = ROOT / output.strip().splitlines()[-1]
    child = json.loads(child_path.read_text())
    command = child["commands"][-1]
    ev.record["child_receipt"] = {"path": ev.relative(child_path),
                                "sha256": digest(child_path)}
    if not command["timed_out"] or command["exit"] == 0:
        raise AssertionError("nested deadline did not reject unfinished execution")
    if child["absolute_deadline_unix"] != deadline or not child.get("stopped_scheduling"):
        raise AssertionError("nested execution reset deadline or scheduled after expiry")
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
    from concurrent.futures import ThreadPoolExecutor
    from verify import component
    ev.record["suite"] = "execution-probe"

    def execute(index):
        def child_run(child):
            output = child.run([sys.executable, "-c",
                                f"import time; time.sleep(1); print({index})"],
                               "parallel-command")
            if output.strip() != str(index):
                raise AssertionError("parallel child output crossed configurations")
        component(ev, str(index), child_run, ("tests/*.py",))

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(execute, (0, 1)))
    saved = json.loads((ev.directory / "receipt.json").read_text())
    if {item["name"] for item in saved["components"]} != {"0", "1"}:
        raise AssertionError("concurrent receipt update lost a configuration")
    commands = []
    for item in saved["components"]:
        child = json.loads((ROOT / item["receipt"]).read_text())
        if item["exit"] != 0 or digest(ROOT / item["receipt"]) != item["sha256"]:
            raise AssertionError("parallel child failed or receipt corrupted")
        if child["absolute_deadline_unix"] != ev.record["absolute_deadline_unix"]:
            raise AssertionError("parallel child reset invocation deadline")
        commands.append(child["commands"][-1])
    if max(item["start"] for item in commands) >= min(item["end"] for item in commands):
        raise AssertionError("configuration commands did not actually overlap")
    ev.record["observed"]["parallel_configurations"] = 2


def diagnostic_boot_images(ev, images, baud, legacy_ptys):
    from boot import checked_images
    directory, _ = checked_images(ev, images)
    if baud not in (115200, 6250000):
        raise ValueError("diagnostic baud must use the original or divisor-one rate")
    destination = ev.directory / ("official-image-baud-" + stamp())
    destination.mkdir()
    parent = json.loads((directory / "receipt.json").read_text())
    copied = {}
    for name in parent["outputs"]:
        source = ROOT / name
        target = destination / source.name
        shutil.copyfile(source, target)
        copied[ev.relative(target)] = digest(target)
    source = destination / "diagnostic.dts"
    text = (ROOT / "software/hammer_v5.dts").read_text()
    if text.count("115200") != 3:
        raise AssertionError("diagnostic UART baud substitution anchors changed")
    source.write_text(text.replace("115200", str(baud)))
    if legacy_ptys is not None:
        text = source.read_text()
        if text.count('rdinit=/init";') != 1:
            raise AssertionError("diagnostic PTY boot-argument anchor changed")
        source.write_text(text.replace('rdinit=/init";',
                                       f'rdinit=/init pty.legacy_count={legacy_ptys}";'))
    ev.record.setdefault("generated_sha256", {})[ev.relative(source)] = digest(source)
    dtc = directory / "linux-build/scripts/dtc/dtc"
    ev.record["diagnostic_dtc"] = {"path": ev.relative(dtc), "sha256": digest(dtc)}
    version = ev.run([ev.relative(dtc), "-v"], "diagnostic-dtc-version")
    ev.record["diagnostic_dtc"]["version"] = version
    ev.run([ev.relative(dtc), "-I", "dts", "-O", "dtb", "-p", "4096",
            "-o", ev.relative(destination / "hammer_v5.dtb"), ev.relative(source)],
           "diagnostic-dtb")
    manifest_path = destination / "images.json"
    manifest = json.loads(manifest_path.read_text())
    for image in manifest["images"]:
        image["sha256"] = digest(destination / image["file"])
        image["bytes"] = (destination / image["file"]).stat().st_size
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    copied = {name: digest(ROOT / name) for name in copied}
    derivation = {
        "kind": "diagnostic-image-derivation", "start": ev.record["start"], "end": stamp(),
        "parent_receipt": {"path": ev.relative(directory / "receipt.json"),
                           "sha256": digest(directory / "receipt.json")},
        "inputs": {**parent["inputs"], ev.relative(source): digest(source),
                   ev.relative(dtc): digest(dtc)},
        "outputs": copied, "exit": 0,
        "commands": ev.record["commands"][-2:],
        "diagnostic_only": True, "baud": baud,
        "legacy_ptys": legacy_ptys,
        "change": "DTB UART/optional PTY count only; unchanged firmware, kernel and timebase",
    }
    (destination / "receipt.json").write_text(json.dumps(derivation, indent=2) + "\n")
    ev.record["diagnostic_image_derivation"] = derivation
    ev.save()
    return ev.relative(destination)


def boot_profile(ev, images, cycles, prefetch, baud=None, legacy_ptys=None):
    from boot import boot_probe, checked_images
    if baud is not None or legacy_ptys is not None:
        images = diagnostic_boot_images(ev, images, baud or 115200, legacy_ptys)
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
    phases = {}
    for line in (ev.directory / "boot-phase-samples.txt").read_text().splitlines():
        phase, pc, count = line.split()
        index = bisect.bisect_right(addresses, int(pc, 16)) - 1
        name = functions[index][1] if index >= 0 else "firmware-or-unmapped"
        histogram = phases.setdefault(phase, {})
        histogram[name] = histogram.get(name, 0) + int(count)
    ev.record["profile"]["phases_50m_cycles"] = {
        phase: sorted(histogram.items(), key=lambda item: -item[1])[:12]
        for phase, histogram in phases.items()
    }
    ev.save()
    if error is not None:
        raise RuntimeError(error)


def audit_evidence(ev, receipt):
    prior = ROOT / receipt
    prior.resolve().relative_to(ROOT)
    record = json.loads(prior.read_text())
    ev.record["prior_receipt"] = {"path": receipt, "sha256": digest(prior)}
    differences = {}
    for name, expected in record["sources_sha256"].items():
        snapshot = prior.parent / "sources" / name
        if digest(snapshot) != expected:
            raise AssertionError(f"prior source snapshot corrupt: {name}")
        current = digest(ROOT / name)
        if current != expected:
            if not name.startswith("tests/"):
                raise AssertionError(f"design/software source changed: {name}")
            differences[name] = {"prior": expected, "current": current}
            target = ev.directory / (Path(name).name + ".diff")
            target.write_text("".join(difflib.unified_diff(
                snapshot.read_text().splitlines(True),
                (ROOT / name).read_text().splitlines(True),
                fromfile="prior/" + name, tofile="current/" + name)))
    for name in ev.record["sources_sha256"].keys() - record["sources_sha256"].keys():
        if not name.startswith("tests/"):
            raise AssertionError(f"unbound added design/software input: {name}")
        differences[name] = {"prior": None, "current": digest(ROOT / name)}
    ev.record["checker_revision"] = differences
    pending = [(prior, record)]
    checked = []
    while pending:
        path, item = pending.pop()
        if item["exit"] != 0:
            raise AssertionError(f"prior check unsuccessful: {path}")
        for component in item.get("components", []):
            child = ROOT / component["receipt"]
            if digest(child) != component["sha256"]:
                raise AssertionError(f"component receipt changed: {child}")
            pending.append((child, json.loads(child.read_text())))
        for name, expected in item.get("outputs_sha256", {}).items():
            if digest(ROOT / name) != expected:
                raise AssertionError(f"retained output changed: {name}")
        if "retained_state" in item.get("observed", {}):
            from structure import assert_structure
            observed = assert_structure(path.parent / "netlist.json")
            if observed != item["observed"]:
                raise AssertionError("current structural checker differs on retained netlist")
        checked.append({"receipt": ev.relative(path), "sha256": digest(path),
                        "output_count": len(item.get("outputs_sha256", {}))})
    ev.record["observed"] = {
        "validated_prior_runs": checked, "design_software_unchanged": True,
        "checker_differences": differences,
        "scope": "retention/source rebind only; not fresh simulation or synthesis",
    }


def throughput_probe(ev, images):
    from boot import boot_probe
    results = []
    for name, parameters in (("default", {}), ("compact", {"IMEM_WORDS": 32, "DMEM_WORDS": 1})):
        child = Evidence("v5-throughput-" + name, ("rtl/*.sv", "tests/*.py", "software/*"))
        child.record["invoked_by"] = ev.relative(ev.directory / "receipt.json")
        try:
            try:
                boot_probe(child, images, 10000000, "userland", 1, parameters)
            except RuntimeError:
                observed = json.loads((child.directory / "boot-observed.json").read_text())
                metrics = json.loads((child.directory / "boot-profile.json").read_text())
                error = (child.directory / "boot-run.stderr.txt").read_text()
                if (observed["cycles"] != 10000000 or observed["goal_reached"]
                        or not observed["integer_checks"]
                        or "bounded RTL boot goal not reached" not in error):
                    raise AssertionError("throughput probe failed before its exact diagnostic bound")
                results.append({"name": name, "parameters": parameters,
                                "observed": observed, "metrics": metrics})
                child.record["observed"] = results[-1]
                child.record["scope"] = "bounded throughput diagnostic; not boot acceptance"
            else:
                raise AssertionError("unexpected full userland goal within startup diagnostic")
        except (OSError, RuntimeError, ValueError, AssertionError) as failure:
            path = child.finish(1, failure)
            ev.record.setdefault("components", []).append({"receipt": path, "exit": 1})
            raise
        path = child.finish(0)
        ev.record.setdefault("components", []).append({
            "receipt": path, "sha256": digest(ROOT / path), "exit": 0})
        ev.save()
    if results[0]["observed"] != results[1]["observed"]:
        raise AssertionError("compact local-memory geometry changed public startup results")
    ev.record["observed"] = results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", choices=("deadlines", "boot-profile", "audit", "reproduce",
                                           "throughput"),
                        required=True)
    parser.add_argument("--receipt")
    parser.add_argument("--repair-of")
    parser.add_argument("--images")
    parser.add_argument("--cycles", type=int, default=500000000)
    parser.add_argument("--prefetch", type=int, choices=(0, 1), default=1)
    parser.add_argument("--baud", type=int, choices=(115200, 6250000),
                        help="derived diagnostic DTB only; never edits shipped software")
    parser.add_argument("--legacy-ptys", type=int, choices=(0, 256),
                        help="derived diagnostic DTB legacy PTY count, not a Linux replacement")
    args = parser.parse_args()
    ev = Evidence("v5-" + args.probe,
                  ("rtl/*.sv", "tests/*.py", "software/*", "design/*.md",
                   "hammer_v4_reference/rtl/hammer_v4_top.sv"), args.repair_of)
    ev.record["argv"] = ["python3", "tests/diagnostics.py", *sys.argv[1:]]
    error = None
    try:
        ev.version("python3")
        if args.probe == "deadlines":
            deadline_probe(ev)
        elif args.probe == "audit":
            if not args.receipt:
                raise ValueError("audit requires a retained project-relative receipt")
            audit_evidence(ev, args.receipt)
        elif args.probe == "reproduce":
            from verify import bind_outputs, reproduce
            reproduce(ev)
            bind_outputs(ev)
        elif args.probe == "throughput":
            if not args.images:
                raise ValueError("throughput diagnostic requires source-matched images")
            throughput_probe(ev, args.images)
        else:
            if not args.images or args.cycles <= 0:
                raise ValueError("boot profile requires local images and positive cycles")
            boot_profile(ev, args.images, args.cycles, args.prefetch,
                         args.baud, args.legacy_ptys)
    except (OSError, ValueError, RuntimeError, AssertionError) as failure:
        error = str(failure)
    path = ev.finish(0 if error is None else 1, error)
    print(json.dumps({"receipt": path, "error": error, "exit": ev.record["exit"]}))
    return ev.record["exit"]


if __name__ == "__main__":
    sys.exit(main())
