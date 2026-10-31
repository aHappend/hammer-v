#!/usr/bin/env python3
"""Bounded cold UART-loss diagnosis, never a full-system acceptance result."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_checkpoint import MAX_PART_EDGES, read_checkpoint
from system_checks import relative_path
from system_oracle import BOUND, IMAGE_LAYOUT, Scenario, canonical_json, digest, load_images


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--through", required=True, type=int)
    parser.add_argument("--seed", type=int, choices=(11, 29, 47), default=11)
    args = parser.parse_args()
    if not 0 <= args.through < BOUND:
        parser.error("--through must retain the continuous edge bound")
    relative = relative_path(ROOT, args.out, output=True)
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest_path = relative_path(ROOT, args.manifest)
    manifest, _ = load_images(ROOT, manifest_path)
    scenario = Scenario(args.seed, 100000, (1 << 28) + args.seed * 1000,
                        tuple((name, manifest["images"][name]["sha256"])
                              for name, _, _ in IMAGE_LAYOUT))
    scenario.freeze(out)
    binding = {
        "out": (relative / "oracle").as_posix(),
        "manifest_sha256": digest(ROOT / manifest_path),
        "scenario_sha256": digest(out / "scenario.json"),
        "images": dict(scenario.image_hashes),
        "diagnostic_uart_bytes": None, "bound": BOUND,
    }
    boundaries = set(range(MAX_PART_EDGES - 1, args.through, MAX_PART_EDGES))
    boundaries.add(args.through)
    for edge in (scenario.rx_first_edge - 1, *(
        scenario.rx_first_edge + index * scenario.rx_spacing + 200 for index in range(3)
    )):
        if 0 <= edge <= args.through:
            boundaries.add(edge)
    previous = None
    commands, snapshots = [], []
    for index, edge in enumerate(sorted(boundaries)):
        checkpoint = relative / "checkpoint-images" / f"part-{index:02d}"
        argv = [
            "python3", "tests/system_checkpoint.py", "--manifest", manifest_path.as_posix(),
            "--scenario", (relative / "scenario.json").as_posix(), "--out", binding["out"],
            "--through", str(edge), "--checkpoint", checkpoint.as_posix(),
        ]
        if previous is not None:
            argv += ["--resume", previous.as_posix()]
        record = {"argv": argv, "cwd": ".", "started_unix": time.time()}
        commands.append(record)
        with (out / f"part-{index:02d}.stdout.log").open("xb") as so, (
            out / f"part-{index:02d}.stderr.log"
        ).open("xb") as se:
            with subprocess.Popen(argv, cwd=ROOT, stdout=so, stderr=se) as child:
                while True:
                    try:
                        record["exit_code"] = child.wait(timeout=20)
                        break
                    except subprocess.TimeoutExpired:
                        print(f"UART_DIAGNOSTIC part={index} through={edge} "
                              f"seconds={time.time() - record['started_unix']:.1f}", flush=True)
        record["ended_unix"] = time.time()
        (out / "commands.json").write_bytes(canonical_json(commands))
        if record["exit_code"]:
            raise AssertionError(f"UART checkpoint failed: {checkpoint}")
        prediction, receipt = read_checkpoint(ROOT / checkpoint, binding)
        platform = prediction.core.platform
        snapshots.append({
            "edge": prediction.clock.edge, "retired": prediction.core.machine.commits,
            "uart_bytes": prediction.uart_bytes, "coverage": prediction.coverage.counts.copy(),
            "rx": list(platform.rx), "overrun": platform.overrun,
            "fifo": platform.fifo, "trigger": platform.trigger, "ier": platform.ier,
            "iir": platform.iir(), "lcr": platform.lcr, "mcr": platform.mcr,
            "plic_pending": platform.plic.pending,
            "plic_enable": platform.plic.enable, "plic_irq": platform.plic.irq,
            "rx_history": list(platform.rx_history),
            "uart_context": list(platform.uart_transactions),
            "uart_modes": list(platform.uart_modes),
            "peripheral_aliases": prediction.peripheral_aliases,
            "checkpoint": (checkpoint / "checkpoint.json").as_posix(),
            "checkpoint_sha256": digest(ROOT / checkpoint / "checkpoint.json"),
        })
        (out / "snapshots.json").write_bytes(canonical_json({
            "scope": "bounded original-stimulus diagnosis, not Linux acceptance",
            "scenario_sha256": binding["scenario_sha256"], "snapshots": snapshots,
        }))
        print(f"UART_SNAPSHOT edge={edge} rx={list(platform.rx)} "
              f"overrun={platform.overrun} fifo={platform.fifo} ier={platform.ier} "
              f"history={list(platform.rx_history)[-4:]}", flush=True)
        del prediction
        previous = checkpoint


if __name__ == "__main__":
    main()
