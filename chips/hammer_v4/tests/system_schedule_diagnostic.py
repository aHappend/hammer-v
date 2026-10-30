#!/usr/bin/env python3
"""Bounded public retirement/AXI observations; never a full-boot expectation.

Run prediction first, preserving its unmodified selected stream, then compare
RTL. Detailed observations are restricted to an explicitly declared edge
window. Oracle resource snapshots explain scheduling but are not DUT inputs.
"""

import argparse
from dataclasses import asdict
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_checks import relative_path
from system_oracle import BOUND, IMAGE_LAYOUT, Phase, Scenario, canonical_json, digest, load_images
from system_prediction import Prediction


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--first-edge", type=int, default=142490000)
    parser.add_argument("--last-edge", type=int, default=142550000)
    parser.add_argument("--retirements", type=int, default=4104300)
    parser.add_argument("--edge-limit", type=int, default=150000000)
    args = parser.parse_args()
    if not 0 <= args.first_edge <= args.last_edge < args.edge_limit <= BOUND or \
            args.last_edge - args.first_edge > 1000000:
        parser.error("Provide a bounded observation window of at most 1000001 edges")
    relative = relative_path(ROOT, args.out, output=True)
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest, images = load_images(ROOT, args.manifest)
    scenario = Scenario(11, 100000, (1 << 28) + 11000,
                        tuple((name, manifest["images"][name]["sha256"])
                              for name, _, _ in IMAGE_LAYOUT))
    scenario.freeze(out)
    oracle = out / "oracle"
    oracle.mkdir()
    prediction = Prediction(scenario, images, oracle,
                            diagnostic_retirements=args.retirements)
    core, clock = prediction.core, prediction.clock
    began = time.monotonic()
    commands = []

    def run(argv, name):
        record = {"argv": argv, "cwd": ".", "started_unix": time.time(),
                  "exit_code": None}
        commands.append(record)
        try:
            with (out / f"{name}.stdout.log").open("xb") as so, (
                out / f"{name}.stderr.log"
            ).open("xb") as se:
                result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
            record["exit_code"] = result.returncode
            if result.returncode:
                raise AssertionError(f"{name} exited {result.returncode}; {relative}")
        finally:
            record["ended_unix"] = time.time()
            (out / "commands.json").write_bytes(canonical_json(commands))

    with (oracle / "window-retirements.txt").open("x") as detail, (
        oracle / "window-axi.txt"
    ).open("x") as axi, (oracle / "window-resources.jsonl").open("x") as resources:
        def inside(edge):
            return args.first_edge <= edge <= args.last_edge

        original_retire = prediction.retire

        def retire(edge, ordinal, commit, registers, memory):
            original_retire(edge, ordinal, commit, registers, memory)
            if not inside(edge):
                return
            from system_protocol import event_line
            detail.write(event_line(
                "R", edge, ordinal, commit.pc, commit.instruction, commit.next_pc,
                commit.privilege, int(bool(commit.rd)), commit.rd,
                commit.value if commit.rd else 0, memory.valid, memory.write,
                memory.address, memory.mask, memory.wdata, memory.rdata,
                registers[10], registers[11], registers[12], registers[17]))
            def job(item):
                return None if item is None else {
                    "pc": item.fetched.pc, "word": item.word, "issued": item.issued,
                    "ready_edge": item.ready_edge, "fence_edge": item.fence_edge}
            paths = core.memory
            resources.write(canonical_json({
                "edge": edge, "ordinal": ordinal,
                "stages": [job(item) for item in
                           (core.decode, core.execute, core.mem, core.writeback)],
                "queue": [asdict(item) for item in core.queue],
                "fetch_pc": core.fetch_pc, "fetching": core.fetching, "killed": core.killed,
                "releasing": core.releasing, "interrupt": core._interrupt(),
                "cache": {"i": [paths.icache.hits, paths.icache.misses],
                          "d": [paths.dcache.hits, paths.dcache.misses]},
                "translation": [paths.translation.hits, paths.translation.walks],
                "ports": {
                    name: [(e, owner, repr(request)) for e, owner, request in port.recent]
                    for name, port in (
                        ("i", paths.ports[0]), ("d", paths.ports[1]),
                        ("itlb", paths.translation.ports[0]),
                        ("dtlb", paths.translation.ports[1]),
                        ("ptw", paths.translation.walker),
                        ("icache", paths.icache.port), ("dcache", paths.dcache.port),
                        ("fabric", paths.backing.port))},
            }).decode())
        core.retirement = retire
        ram = core.memory.backing.ram
        original_read, original_write = ram.read, ram.write

        def read(address, request_edge, receive):
            def received(receipt, data):
                if inside(receipt.response_edge):
                    axi.write(f"D {receipt.response_edge} {receipt.ordinal} {data}\n")
                receive(receipt, data)
            receipt = original_read(address, request_edge, received)
            if inside(receipt.address_edge):
                clock.schedule(receipt.address_edge, Phase.OBSERVE, lambda:
                    axi.write(f"A {receipt.address_edge} {receipt.ordinal} {address}\n"))
            return receipt

        def write(address, address_edge, data_edge, data, strobes, receive):
            def received(receipt):
                if inside(receipt.response_edge):
                    axi.write(f"B {receipt.response_edge} {receipt.ordinal}\n")
                receive(receipt)
            receipt = original_write(address, address_edge, data_edge, data, strobes, received)
            for kind, edge, values in (
                ("W", receipt.address_edge, (address,)),
                ("V", receipt.data_edge, (data, strobes)),
            ):
                if inside(edge):
                    clock.schedule(edge, Phase.OBSERVE,
                        lambda k=kind, e=edge, v=values:
                            axi.write(f"{k} {e} {receipt.ordinal} " +
                                      " ".join(map(str, v)) + "\n"))
            return receipt
        ram.read, ram.write = read, write
        result = prediction.execute(args.edge_limit)
    result["scope"] = "bounded-scheduling-diagnostic-not-linux-acceptance"
    (oracle / "prediction.json").write_bytes(canonical_json(result))
    controls = [scenario.seed, scenario.start_edge, scenario.rx_first_edge,
                scenario.rx_spacing, prediction.final_edge, prediction.events,
                prediction.uart_bytes, len(prediction.ranges)]
    (oracle / "control.txt").write_text(" ".join(map(str, controls)) + "\n" + "".join(
        f"{item['name']} {item['start']} {item['end']}\n" for item in prediction.ranges))
    (oracle / "counts.txt").write_text(f"{prediction.events} {prediction.uart_bytes}\n")
    frozen = {path.name: digest(path) for path in oracle.iterdir()}
    (out / "prefix-seal.json").write_bytes(canonical_json({
        "scope": result["scope"], "files": frozen, "frozen_unix": time.time()}))
    obj = relative / "compile-obj"
    try:
        run([
            "verilator", "-O3", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
            "--top-module", "hammer_v4_top", "--Mdir", obj.as_posix(),
            "-CFLAGS", "-O3 -std=c++17",
            *[path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "rtl").glob("*.sv"))],
            str(Path(*([".."] * len(obj.parts))) / "tests/system_core_probe.cpp"),
            "-MAKEFLAGS", "OPT_FAST=-O3",
        ], "compile")
        binary = relative / "window-probe"
        shutil.copyfile(ROOT / obj / "Vhammer_v4_top", ROOT / binary)
        (ROOT / binary).chmod(0o755)
        actual = relative / "rtl"
        (ROOT / actual).mkdir()
        run([binary.as_posix(),
             *[manifest["images"][name]["path"] for name, _, _ in IMAGE_LAYOUT],
             (relative / "oracle").as_posix(), actual.as_posix(), "11",
             str(prediction.final_edge), "selected",
             str(args.first_edge), str(args.last_edge)], "comparison")
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in (ROOT / obj).glob(pattern):
                path.unlink()
        if any(digest(oracle / name) != old for name, old in frozen.items()):
            raise AssertionError("Pre-DUT diagnostic outputs changed")
        (out / "elapsed.json").write_bytes(canonical_json({
            "seconds": time.monotonic() - began, "scope": result["scope"]}))


if __name__ == "__main__":
    main()
