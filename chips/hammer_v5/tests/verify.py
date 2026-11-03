#!/usr/bin/env python3
"""Portable independent L1 execution; native timing/STA/HIL remain runtime gates."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shutil
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parent))

from evidence import Evidence, ROOT, digest, remaining_seconds, stamp
from probe import compressed, numerical
from architectural import architectural_probe
from boot import boot_probe
from counters import counter_probe
from coherence import coherence_probe
from defects import remaining_mutations
from fetch import fetch_probe
from fabric import fabric_probe
from integration import top_smoke
from local import local_probe
from memory import l2_probe
from mmu import mmu_probe
from mutations import numerical_mutations
from parameters import parameter_probe
from parser_check import parser_probe
from plic import plic_probe
from prefetch import prefetch_probe
from structure import synthesis_probe
from tlb import tlb_probe
from vector import vector_probe


SOURCE_SELECTORS = (
    "rtl/*.sv", "tests/*.py", "software/*", "design/*.md",
    "hammer_v4_reference/rtl/hammer_v4_top.sv",
)
MINIMUM = {
    "IMEM_WORDS": 1, "DMEM_WORDS": 1, "PRED_MODE": 0, "BTB_ENTRIES": 1,
    "ICACHE_LINES": 1, "DCACHE_LINES": 1, "ITLB_ENTRIES": 1,
    "DTLB_ENTRIES": 1, "BOOT_ENABLE": 0, "L2_SETS": 1,
}
ERRORS = (OSError, RuntimeError, AssertionError, ValueError)


def bind_outputs(ev):
    for name, expected in ev.record["sources_sha256"].items():
        remaining_seconds()
        if digest(ROOT / name) != expected:
            raise AssertionError(f"source changed during verification: {name}")
    outputs = {}
    archived = [ROOT / tree for tree in ev.record.get("archived_trees", {})]
    for path in sorted(ev.directory.rglob("*")):
        remaining_seconds()
        if any(path.is_relative_to(tree) for tree in archived):
            continue
        if (path.is_file() and path != ev.directory / "receipt.json"
                and "sources" not in path.relative_to(ev.directory).parts):
            outputs[ev.relative(path)] = digest(path)
    ev.record["outputs_sha256"] = outputs
    ev.save()


def component(parent, name, execute, selectors=("rtl/*.sv", "tests/*.py")):
    remaining_seconds()
    child = Evidence("v5-" + parent.record["suite"] + "-" + name,
                     selectors,
                     preparation=parent.record["kind"] == "verifier-preparation")
    child.record["invoked_by"] = parent.relative(parent.directory / "receipt.json")
    child.record["component"] = name
    result, error = None, None
    try:
        child.version("python3")
        result = execute(child)
        bind_outputs(child)
    except ERRORS as failure:
        error = str(failure)
    receipt = child.finish(0 if error is None else 1, error)
    with parent.lock:
        parent.record.setdefault("components", []).append({
            "name": name, "receipt": receipt,
            "sha256": digest(ROOT / receipt), "exit": child.record["exit"],
            "error": error,
        })
        parent.save()
    print(json.dumps({"component": name, "exit": child.record["exit"],
                      "receipt": receipt}), flush=True)
    return result


def arithmetic_and_defects(ev):
    numerical(ev)
    numerical_mutations(ev)


def architecture_defects(ev):
    top_smoke(ev)
    l2_probe(ev)
    vector_probe(ev)
    counter_probe(ev)
    remaining_mutations(ev)


def behavior(ev):
    checks = (
        ("compressed-exhaustive", compressed),
        ("numerical-and-mutants", arithmetic_and_defects),
        ("parameters", parameter_probe),
        ("top-smoke", top_smoke),
        ("isa-matrix", architectural_probe),
        ("vector-seeds", lambda child: vector_probe(child, 1000, (17, 43, 89))),
        ("memory-seeds", lambda child: l2_probe(child, 2000, (17, 43, 89))),
        ("counters", counter_probe),
        ("fetch", fetch_probe),
        ("prefetch-coherence", prefetch_probe),
        ("sv39-ptw", mmu_probe),
        ("tlb", tlb_probe),
        ("local-memory", local_probe),
        ("fabric-arbitration", fabric_probe),
        ("integrated-ownership-fences", coherence_probe),
        ("plic", plic_probe),
        ("architectural-mutants", architecture_defects),
        ("uart-parser-sensitivity", parser_probe),
    )
    for name, execute in checks:
        remaining_seconds()
        selectors = ("rtl/*.sv", "tests/*.py")
        if name in ("top-smoke", "architectural-mutants"):
            selectors += ("hammer_v4_reference/rtl/hammer_v4_top.sv",)
        component(ev, name, execute, selectors)


def synthesis(ev):
    for name, parameters in (("default", {}), ("minimum", MINIMUM)):
        component(ev, name,
                  lambda child, parameters=parameters: synthesis_probe(
                      child, sorted((ROOT / "rtl").glob("*.sv")), parameters))


def build_software(ev):
    directory = ev.directory / ("boot-build-" + stamp())
    ev.run(["python3", "software/build.py", "--output", ev.relative(directory),
            "--jobs", "2"], "offline-software", timeout_s=None)
    removed = 0
    for build in (directory / "linux-build", directory / "opensbi-build"):
        for path in build.rglob("*"):
            remaining_seconds()
            if (path.is_file() and not path.is_symlink()
                    and path.suffix in (".o", ".a", ".gch", ".d")):
                path.unlink()
                removed += 1
    ev.record["pruned_build_intermediates"] = removed
    ev.save()
    return ev.relative(directory)


def linux(ev, cycles):
    images = component(ev, "offline-software", build_software, SOURCE_SELECTORS)
    def configuration(prefetch):
        def execute(child, prefetch=prefetch):
            if images is None:
                raise RuntimeError("required fresh source-matched software build unsuccessful")
            boot_probe(child, images, cycles, "userland", prefetch)
        component(ev, f"userland-prefetch-{prefetch}", execute, SOURCE_SELECTORS)
    remaining_seconds()
    ev.record["linux_parallel_configurations"] = 2
    ev.save()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(configuration, prefetch) for prefetch in (0, 1)]
        for future in futures:
            future.result()


def reproduce_worker(ev):
    component(ev, "icarus-top-smoke", top_smoke,
              ("rtl/*.sv", "tests/*.py", "hammer_v4_reference/rtl/hammer_v4_top.sv"))
    component(ev, "compiled-custom", lambda child: architectural_probe(
        child, count=16, seeds=(17,), compact_only=True))
    component(ev, "coherence", prefetch_probe)
    component(ev, "integrated-ownership-fences", coherence_probe)
    component(ev, "local-host-maintenance", local_probe)
    component(ev, "synthesis", lambda child: synthesis_probe(
        child, sorted((ROOT / "rtl").glob("*.sv")), MINIMUM))


def reproduce(ev):
    directory = ev.directory / ("clean-project-" + stamp())
    directory.mkdir(exist_ok=False)
    for name, expected in ev.record["sources_sha256"].items():
        destination = directory / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
        if digest(destination) != expected:
            raise AssertionError(f"fresh-directory source hash mismatch: {name}")
    ev.record["clean_project"] = ev.relative(directory)
    ev.save()
    ev.run(["python3", "tests/verify.py", "--suite", "reproduce",
            "--reproduce-worker"], "clean-directory-execution",
           cwd=directory, timeout_s=None)
    results = list((directory / "evidence").glob("v5-reproduce-*/receipt.json"))
    suites = [(path, json.loads(path.read_text())) for path in results]
    suites = [(path, record) for path, record in suites
              if record.get("suite") == "reproduce" and record.get("reproduce_worker")]
    if len(suites) != 1 or suites[0][1]["exit"] != 0:
        raise AssertionError("fresh-directory simulation/synthesis receipt absent or unsuccessful")
    path, record = suites[0]
    if record["sources_sha256"] != ev.record["sources_sha256"]:
        raise AssertionError("fresh-directory execution consumed different source inputs")
    ev.record["reproduction"] = {"receipt": ev.relative(path), "sha256": digest(path),
                                 "component_count": len(record["components"])}
    archive = ev.directory / (directory.name + ".tar.gz")
    members = {}
    for item in sorted(directory.rglob("*")):
        remaining_seconds()
        if item.is_file():
            members[item.relative_to(directory).as_posix()] = digest(item)
    with tarfile.open(archive, "x:gz") as stream:
        for name in members:
            remaining_seconds()
            stream.add(directory / name, arcname=name, recursive=False)
    import hashlib
    with tarfile.open(archive, "r:gz") as stream:
        actual = set()
        for member in stream:
            remaining_seconds()
            if not member.isfile() or member.name not in members or member.name in actual:
                raise AssertionError("invalid or duplicate reproduction archive member")
            source = stream.extractfile(member)
            if hashlib.file_digest(source, "sha256").hexdigest() != members[member.name]:
                raise AssertionError("reproduction archive round-trip hash mismatch")
            actual.add(member.name)
    if actual != set(members):
        raise AssertionError("incomplete reproduction archive")
    ev.record["archived_trees"] = {
        ev.relative(directory): {
            "archive": ev.relative(archive), "sha256": digest(archive),
            "members_sha256": members,
            "receipt_member": path.relative_to(directory).as_posix(),
            "round_trip_verified": True,
        },
    }
    ev.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", choices=("behavior", "synthesis", "linux", "reproduce"),
                        required=True)
    parser.add_argument("--cycles", type=int, default=10000000000,
                        help="RTL Linux diagnostic cycle bound, not an acceptance threshold")
    parser.add_argument("--repair-of", help="retained prior failure receipt, project-relative")
    parser.add_argument("--reproduce-worker", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.cycles < 1 or (args.reproduce_worker and args.suite != "reproduce"):
        parser.error("positive cycle bound and reproduce-only worker flag required")
    ev = Evidence("v5-" + args.suite, SOURCE_SELECTORS, args.repair_of, preparation=False)
    ev.record.update(suite=args.suite, reproduce_worker=args.reproduce_worker,
                     argv=["python3", "tests/verify.py", *sys.argv[1:]],
                     native_gates="shared runtime: timing lint, Quartus STA, PCIe HIL",
                     final_report="not an engineering-verification prerequisite")
    error = None
    try:
        ev.version("python3")
        if args.suite == "behavior":
            behavior(ev)
        elif args.suite == "synthesis":
            synthesis(ev)
        elif args.suite == "linux":
            linux(ev, args.cycles)
        elif args.reproduce_worker:
            reproduce_worker(ev)
        else:
            reproduce(ev)
        failures = [item for item in ev.record.get("components", []) if item["exit"] != 0]
        if failures:
            raise AssertionError("mandatory component failures: " +
                                 ", ".join(item["name"] for item in failures))
        bind_outputs(ev)
    except ERRORS as failure:
        error = str(failure)
    receipt = ev.finish(0 if error is None else 1, error)
    print(json.dumps({"suite": args.suite, "exit": ev.record["exit"],
                      "receipt": receipt, "error": error}))
    return ev.record["exit"]


if __name__ == "__main__":
    sys.exit(main())
