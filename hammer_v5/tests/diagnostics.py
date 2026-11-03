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
import tarfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence import Evidence, ROOT, digest, remaining_seconds, stamp


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
    original = (ROOT / images).resolve()
    dtc_source = original / "dtc"
    if not dtc_source.is_file():
        dtc_source = original / "linux-build/scripts/dtc/dtc"
    directory, _ = checked_images(ev, images)
    if baud not in (115200, 6250000):
        raise ValueError("diagnostic baud must use the original or divisor-one rate")
    destination = ev.directory / ("boot-images-baud-" + stamp())
    destination.mkdir()
    parent = json.loads((directory / "receipt.json").read_text())
    copied = {}
    for name in parent["outputs"]:
        source = ROOT / name
        target = destination / source.name
        shutil.copy2(source, target)
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
    dtc = destination / "dtc"
    if not dtc.exists():
        shutil.copy2(dtc_source, dtc)
        copied[ev.relative(dtc)] = digest(dtc)
    if digest(dtc) != digest(dtc_source):
        raise AssertionError("diagnostic device-tree compiler snapshot mismatch")
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


def diagnostic_console_images(ev):
    project = ev.directory / ("boot-diagnostic-project-" + stamp())
    (project / "software").mkdir(parents=True)
    for path in (ROOT / "software").iterdir():
        if path.is_file():
            shutil.copyfile(path, project / "software" / path.name)
    config = project / "software/linux.config"
    config.write_text(config.read_text() + "\nCONFIG_VT=n\nCONFIG_LEGACY_PTYS=n\n")
    ev.record["diagnostic_software_inputs"] = {
        ev.relative(path): digest(path) for path in (project / "software").iterdir()
        if path.is_file()}
    build = Path("evidence") / ("software-build-" + stamp())
    ev.run(["python3", "software/build.py", "--output", build.as_posix(), "--jobs", "2"],
           "diagnostic-console-build", cwd=project, timeout_s=None)
    directory = project / build
    parent_path = directory / "receipt.json"
    parent = json.loads(parent_path.read_text())
    if parent["exit"] != 0:
        raise AssertionError("diagnostic console software build unsuccessful")
    configuration = (directory / "linux.config").read_text()
    if any(f"# CONFIG_{name} is not set\n" not in configuration
           for name in ("VT", "LEGACY_PTYS")):
        raise AssertionError("diagnostic kernel retained unwanted eager console devices")
    destination = ev.directory / ("boot-images-console-" + stamp())
    destination.mkdir()
    outputs = {}
    for name, expected in parent["outputs"].items():
        source = project / name
        if digest(source) != expected:
            raise AssertionError("diagnostic build artifact checksum mismatch")
        target = destination / source.name
        shutil.copyfile(source, target)
        outputs[ev.relative(target)] = digest(target)
    dtc = directory / "linux-build/scripts/dtc/dtc"
    shutil.copy2(dtc, destination / "dtc")
    outputs[ev.relative(destination / "dtc")] = digest(dtc)
    derivation = {
        "kind": "diagnostic-image-derivation", "start": ev.record["start"], "end": stamp(),
        "parent_receipt": {"path": ev.relative(parent_path), "sha256": digest(parent_path),
                           "cwd": ev.relative(project)},
        "inputs": {ev.relative(project / name): value for name, value in parent["inputs"].items()},
        "outputs": outputs, "exit": 0, "diagnostic_only": True,
        "change": "CONFIG_VT=n and CONFIG_LEGACY_PTYS=n only; genuine Linux, preemption, "
                  "serial console, userland, memory and timebase requirements unchanged",
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
    kernel_sha256 = digest(kernel)
    ev.record["kernel_sha256"] = kernel_sha256
    ev.version("riscv64-linux-gnu-nm")
    ev.run(["riscv64-linux-gnu-nm", "-n", ev.relative(kernel)], "kernel-symbols")
    error = None
    try:
        boot_probe(ev, ev.relative(directory), cycles, "userland", prefetch)
    except RuntimeError as failure:
        error = str(failure)
    ev.record["profile"] = summarize_boot_samples(ev.directory, kernel_sha256, error)
    ev.save()
    if error is not None:
        raise RuntimeError(error)


def summarize_boot_samples(directory, kernel_sha256, error):
    functions = []
    for line in (directory / "kernel-symbols.stdout.txt").read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in ("t", "T"):
            functions.append((int(fields[0], 16), fields[2]))
    functions.sort()
    if not functions:
        raise AssertionError("retained kernel symbol table contains no functions")
    addresses = [address for address, _ in functions]
    samples = directory / "pc-samples.txt"
    if not samples.exists():
        raise RuntimeError(error or "boot profile samples missing")
    histogram = {}
    for line in samples.read_text().splitlines():
        pc, count = line.split()
        index = bisect.bisect_right(addresses, int(pc, 16)) - 1
        name = functions[index][1] if index >= 0 else "firmware-or-unmapped"
        histogram[name] = histogram.get(name, 0) + int(count)
    profile = {
        "kernel_sha256": kernel_sha256,
        "metrics": json.loads((directory / "boot-profile.json").read_text()),
        "cycle_weighted_functions": sorted(histogram.items(),
                                          key=lambda item: -item[1])[:40],
        "function_samples": dict(sorted(histogram.items())),
        "boot_error": error,
    }
    phases = {}
    for line in (directory / "boot-phase-samples.txt").read_text().splitlines():
        phase, pc, count = line.split()
        index = bisect.bisect_right(addresses, int(pc, 16)) - 1
        name = functions[index][1] if index >= 0 else "firmware-or-unmapped"
        histogram = phases.setdefault(phase, {})
        histogram[name] = histogram.get(name, 0) + int(count)
    profile["phases_50m_cycles"] = {
        phase: sorted(histogram.items(), key=lambda item: -item[1])[:12]
        for phase, histogram in phases.items()
    }
    profile["phase_sample_totals"] = {
        phase: sum(histogram.values()) for phase, histogram in phases.items()
    }
    return profile


def analyze_saved_boot(ev, receipt, linux_source=None, configuration=None):
    prior = (ROOT / receipt).resolve()
    prior.relative_to(ROOT)
    record = json.loads(prior.read_text())
    destination = ev.directory / ("retained-boot-samples-" + stamp())
    destination.mkdir()
    names = ("receipt.json", "kernel-symbols.stdout.txt", "kernel-symbols.stderr.txt",
             "version-riscv64-linux-gnu-nm.stdout.txt",
             "version-riscv64-linux-gnu-nm.stderr.txt",
             "pc-samples.txt", "boot-phase-samples.txt", "boot-profile.json",
             "boot-observed.json", "boot-run.stdout.txt", "boot-run.stderr.txt",
             "uart.txt", "retirement-tail.txt", "boot.cpp")
    consumed = {}
    for name in names:
        remaining_seconds()
        source = prior.parent / name
        expected = digest(source)
        shutil.copyfile(source, destination / name)
        if digest(destination / name) != expected:
            raise AssertionError("retained boot analysis snapshot mismatch")
        consumed[ev.relative(destination / name)] = expected
    generated = record["generated_sha256"][ev.relative(prior.parent / "boot.cpp")]
    if digest(destination / "boot.cpp") != generated:
        raise AssertionError("retained boot harness differs from its producer receipt")
    observed = json.loads((destination / "boot-observed.json").read_text())
    if observed != record["observed"]:
        raise AssertionError("retained boot observations differ from producer receipt")
    ev.record["analysis_inputs_sha256"] = consumed
    ev.record["retained_run"] = {
        "receipt": ev.relative(prior), "sha256": digest(prior),
        "exit": record["exit"], "error": record.get("error"),
        "observed": observed,
        "scope": "offline retained-data analysis only; not a new simulation or Linux pass",
    }
    ev.record["profile"] = summarize_boot_samples(
        destination, record["kernel_sha256"], record.get("error"))
    if linux_source is not None:
        source = (ROOT / linux_source).resolve()
        source.relative_to(ROOT)
        manifest = json.loads((ROOT / "software/boot_manifest.json").read_text())
        specification = next(item for item in manifest["sources"]
                             if item["root"].startswith("linux-"))
        archive = ROOT / "software" / specification["file"]
        if digest(archive) != specification["sha256"]:
            raise AssertionError("Linux archive differs from its pinned provenance")
        wanted = {"lib/crypto/blake2s.c", "lib/crypto/blake2s-selftest.c",
                  "lib/crypto/Kconfig", "crypto/Kconfig", "init/Kconfig"}
        captured = ev.directory / ("linux-source-" + stamp())
        captured.mkdir()
        hashes = {}
        with tarfile.open(archive, "r|xz") as stream:
            for member in stream:
                remaining_seconds()
                relative = Path(member.name).relative_to(specification["root"]).as_posix()
                if relative not in wanted:
                    continue
                data = stream.extractfile(member).read()
                original = source / relative
                if original.read_bytes() != data:
                    raise AssertionError(f"diagnostic Linux source differs from pin: {relative}")
                target = captured / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                hashes[ev.relative(target)] = digest(target)
                wanted.remove(relative)
                if not wanted:
                    break
        if wanted:
            raise AssertionError(f"missing diagnostic Linux source members: {sorted(wanted)}")
        ev.record["linux_source_provenance"] = {
            "archive": ev.relative(archive), "sha256": specification["sha256"],
            "members_sha256": hashes,
        }
    if configuration is not None:
        source = (ROOT / configuration).resolve()
        source.relative_to(ROOT)
        target = destination / "baseline-linux.config"
        shutil.copyfile(source, target)
        ev.record["baseline_configuration"] = {
            "path": ev.relative(target), "sha256": digest(target),
            "scope": "supplied baseline configuration; not the reclaimed diagnostic variant",
        }


def boot_input_probe(ev, images):
    from boot import checked_images
    directory, _ = checked_images(ev, images)
    if not directory.is_relative_to(ev.directory):
        raise AssertionError("boot inputs were not retained inside the active run")
    retained = json.loads((directory / "receipt.json").read_text())
    for name, expected in {**retained["inputs"], **retained["outputs"]}.items():
        path = ROOT / name
        if not path.is_relative_to(ev.directory) or digest(path) != expected:
            raise AssertionError("boot snapshot still depends on another run")
    again, _ = checked_images(ev, ev.relative(directory))
    if again != directory:
        raise AssertionError("validating retained inputs made a redundant snapshot")
    derived = diagnostic_boot_images(ev, images, 115200, None)
    derived_directory, _ = checked_images(ev, derived)
    dtc = derived_directory / "dtc"
    if not os.access(dtc, os.X_OK):
        raise AssertionError("retained diagnostic compiler lost executable permissions")
    try:
        boot_profile(ev, ev.relative(directory), 1000000, 1)
    except RuntimeError:
        observed = json.loads((ev.directory / "boot-observed.json").read_text())
        error = (ev.directory / "boot-run.stderr.txt").read_text()
        if (observed["cycles"] != 1000000 or observed["goal_reached"]
                or not observed["integer_checks"]
                or "bounded RTL boot goal not reached" not in error):
            raise AssertionError("boot retention smoke failed before its diagnostic bound")
        outcome = "expected diagnostic bound; unfinished userland correctly rejected"
    else:
        observed = json.loads((ev.directory / "boot-observed.json").read_text())
        if not observed["goal_reached"] or not 0 < observed["cycles"] <= 1000000:
            raise AssertionError("boot diagnostic accepted incomplete userland")
        outcome = "validated early userland completion"
    ev.record["observed"] = {
        "self_contained_boot_snapshot": ev.relative(directory),
        "revalidation_without_resnapshot": True,
        "diagnostic_dtb": ev.relative(derived_directory / "hammer_v5.dtb"),
        "startup_observed": observed, "startup_outcome": outcome,
        "scope": "input/ELF/DTB retention and bounded RTL startup; not Linux acceptance",
    }


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
                outcome = "diagnostic bound reached"
            else:
                observed = json.loads((child.directory / "boot-observed.json").read_text())
                metrics = json.loads((child.directory / "boot-profile.json").read_text())
                if (not observed["goal_reached"] or not observed["integer_checks"]
                        or not 0 < observed["cycles"] <= 10000000):
                    raise AssertionError("invalid early userland completion in throughput probe")
                outcome = "validated early userland completion"
            results.append({"name": name, "parameters": parameters,
                            "observed": observed, "metrics": metrics, "outcome": outcome})
            child.record["observed"] = results[-1]
            child.record["scope"] = "bounded throughput diagnostic; not boot acceptance"
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
                                           "throughput", "analyze-boot", "boot-inputs"),
                        required=True)
    parser.add_argument("--receipt")
    parser.add_argument("--repair-of")
    parser.add_argument("--images")
    parser.add_argument("--linux-source",
                        help="project-local extracted Linux source for pinned offline analysis")
    parser.add_argument("--config",
                        help="project-local baseline resolved Linux configuration")
    parser.add_argument("--cycles", type=int, default=500000000)
    parser.add_argument("--prefetch", type=int, choices=(0, 1), default=1)
    parser.add_argument("--baud", type=int, choices=(115200, 6250000),
                        help="derived diagnostic DTB only; never edits shipped software")
    parser.add_argument("--legacy-ptys", type=int, choices=(0, 256),
                        help="derived diagnostic DTB legacy PTY count, not a Linux replacement")
    parser.add_argument("--minimal-console", action="store_true",
                        help="fresh diagnostic kernel without unused eager VT/legacy PTYs")
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
        elif args.probe == "analyze-boot":
            if not args.receipt:
                raise ValueError("offline boot analysis requires a retained receipt")
            analyze_saved_boot(ev, args.receipt, args.linux_source, args.config)
        elif args.probe == "boot-inputs":
            if not args.images:
                raise ValueError("boot input retention check requires local images")
            boot_input_probe(ev, args.images)
        else:
            images = diagnostic_console_images(ev) if args.minimal_console else args.images
            if not images or args.cycles <= 0:
                raise ValueError("boot profile requires local images and positive cycles")
            boot_profile(ev, images, args.cycles, args.prefetch,
                         args.baud, args.legacy_ptys)
    except (OSError, ValueError, RuntimeError, AssertionError) as failure:
        error = str(failure)
    path = ev.finish(0 if error is None else 1, error)
    print(json.dumps({"receipt": path, "error": error, "exit": ev.record["exit"]}))
    return ev.record["exit"]


if __name__ == "__main__":
    sys.exit(main())
