#!/usr/bin/env python3
"""Compact fresh-process checkpoint controls; never complete Linux acceptance."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_checkpoint import (
    STREAMS, decode, encode, read_checkpoint, write_checkpoint,
)
from system_checks import relative_path
from system_oracle import IMAGE_LAYOUT, Scenario, canonical_json, digest, load_images
from system_prediction import Prediction


def rejected(function, message):
    try:
        function()
    except ValueError as error:
        if str(error) != message:
            raise
    else:
        raise AssertionError(f"Checkpoint corruption was accepted: {message}")


def state(prediction):
    machine = prediction.core.machine
    return {
        "edge": prediction.clock.edge, "callbacks": prediction.clock.callbacks,
        "pending_events": len(prediction.clock._events),
        "pc": machine.pc, "registers": machine.registers, "csrs": machine.csrs,
        "privilege": machine.privilege, "retired": machine.commits,
        "coverage": prediction.coverage.counts,
        "events": prediction.events, "uart_bytes": prediction.uart_bytes,
        "active_uart_frame": prediction.active, "wire_level": prediction.line,
        "final_edge": prediction.final_edge,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    relative = relative_path(ROOT, args.out, output=True)
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    manifest_path = relative_path(ROOT, args.manifest)
    manifest, images = load_images(ROOT, manifest_path)
    scenario = Scenario(11, 100000, (1 << 28) + 11000,
                        tuple((name, manifest["images"][name]["sha256"])
                              for name, _, _ in IMAGE_LAYOUT))
    scenario.freeze(out)
    binding = {
        "out": (relative / "resumed").as_posix(),
        "manifest_sha256": digest(ROOT / manifest_path),
        "scenario_sha256": digest(out / "scenario.json"),
        "images": dict(scenario.image_hashes),
        "diagnostic_uart_bytes": None, "bound": 4294967296,
    }
    # Split across initial launch, outstanding AXI/cache work, UART frames and
    # running firmware. The callbacks and shared closure cells are all real
    # independent-model operations, not a surrogate checkpoint-only machine.
    boundaries = (100001, 100049, 100127, 100201, 100503, 104009, 200003, 800011)
    commands, records = [], []
    previous = None
    for index, edge in enumerate(boundaries):
        directory = relative / f"part-{index:02d}"
        argv = [
            "python3", "tests/system_checkpoint.py",
            "--manifest", manifest_path.as_posix(),
            "--scenario", (relative / "scenario.json").as_posix(),
            "--out", binding["out"], "--through", str(edge),
            "--checkpoint", directory.as_posix(),
        ]
        if previous is not None:
            argv += ["--resume", previous.as_posix()]
        record = {"argv": argv, "cwd": ".", "started_unix": time.time(),
                  "exit_code": None}
        commands.append(record)
        try:
            with (out / f"part-{index:02d}.stdout.log").open("xb") as so, (
                out / f"part-{index:02d}.stderr.log"
            ).open("xb") as se:
                result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
            record["exit_code"] = result.returncode
            if result.returncode:
                raise AssertionError(f"Fresh-process checkpoint part failed: {directory}")
        finally:
            record["ended_unix"] = time.time()
            (out / "commands.json").write_bytes(canonical_json(commands))
        checkpoint = json.loads((ROOT / directory / "checkpoint.json").read_text())
        if checkpoint["edge"] != edge or checkpoint["phase"] != 4 or \
                checkpoint["parent"] != (None if previous is None else {
                    "path": (previous / "checkpoint.json").as_posix(),
                    "sha256": digest(ROOT / previous / "checkpoint.json"),
                    "edge": boundaries[index - 1],
                }):
            raise AssertionError("Absolute checkpoint time or hash chain differs")
        records.append(checkpoint)
        previous = directory

    resumed, _ = read_checkpoint(ROOT / previous, binding)
    control_out = out / "continuous"
    control_out.mkdir()
    control = Prediction(scenario, images, control_out)
    control.advance(boundaries[-1])
    if state(control) != state(resumed):
        raise AssertionError("Fresh-process versus continuous machine state differs")
    for name in STREAMS:
        if digest(control_out / name) != digest(resumed.out / name):
            raise AssertionError(f"Fresh-process versus continuous prefix differs: {name}")
    # Continue both after the final checkpoint to expose damaged pending
    # callbacks, resource ownership or nonlocal single-delivery flags.
    followup = 1200019
    control.advance(followup, resume=True)
    resumed.advance(followup, resume=True)
    if state(control) != state(resumed):
        raise AssertionError("Resumed continuation machine state differs")
    for name in STREAMS:
        if digest(control_out / name) != digest(resumed.out / name):
            raise AssertionError(f"Resumed continuation stream differs: {name}")
    if not control.core.machine.commits or not control.events or not control.uart_bytes:
        raise AssertionError("Checkpoint control performed no architectural/UART comparisons")

    # Re-seal the advanced prefix into a new checkpoint, preserving all prior
    # receipts. Each rejection is a disposable copy, never an edited original.
    valid = out / "advanced"
    write_checkpoint(resumed, valid, binding, {
        "path": (previous / "checkpoint.json").as_posix(),
        "sha256": digest(ROOT / previous / "checkpoint.json"),
        "edge": boundaries[-1],
    })
    corrupt = out / "corrupt-payload"
    shutil.copytree(valid, corrupt)
    payload = corrupt / "machine.pickle.z"
    with payload.open("r+b") as stream:
        first = stream.read(1)
        stream.seek(0)
        stream.write(bytes((first[0] ^ 1,)))
    rejected(lambda: read_checkpoint(corrupt, binding),
             "Checkpoint payload identity differs")
    wrong_binding = {**binding, "scenario_sha256": "0" * 64}
    rejected(lambda: read_checkpoint(valid, wrong_binding),
             "Checkpoint interpreter/source/input binding differs")
    wrong_source = out / "corrupt-source-binding"
    shutil.copytree(valid, wrong_source)
    receipt = json.loads((wrong_source / "checkpoint.json").read_text())
    receipt["source_sha256"]["tests/system_core.py"] = "0" * 64
    (wrong_source / "checkpoint.json").write_bytes(canonical_json(receipt))
    rejected(lambda: read_checkpoint(wrong_source, binding),
             "Checkpoint interpreter/source/input binding differs")
    wrong_parent = out / "corrupt-parent-binding"
    shutil.copytree(valid, wrong_parent)
    receipt = json.loads((wrong_parent / "checkpoint.json").read_text())
    receipt["parent"]["sha256"] = "0" * 64
    (wrong_parent / "checkpoint.json").write_bytes(canonical_json(receipt))
    rejected(lambda: read_checkpoint(wrong_parent, binding),
             "Checkpoint parent hash chain differs")
    # A stream appended since checkpointing cannot be resumed from an earlier
    # image. This checks rollback/duplicate-output protection without altering
    # either already compared stream.
    rejected(lambda: read_checkpoint(ROOT / previous, binding),
             "Checkpoint output prefix differs: expected-events.txt")
    roundtrip = decode(encode(resumed))
    if state(roundtrip) != state(resumed) or \
            roundtrip.core.retirement.__self__ is not roundtrip or \
            roundtrip.core.machine.platform is not roundtrip.core.platform:
        raise AssertionError("Checkpoint callback graph lost owner identity")
    summary = {
        "scope": "compact independent checkpoint controls, not Linux acceptance",
        "fresh_process_parts": len(boundaries), "boundaries": list(boundaries),
        "continuous_and_resumed_equal": True, "followup_edge": followup,
        "state": state(control),
        "streams": {name: digest(control_out / name) for name in STREAMS},
        "rejected_corruptions": ["payload", "scenario", "source", "parent", "advanced-output"],
        "preserved_graph_identity": True,
        "checkpoints": [record["payload"] for record in records],
    }
    (out / "summary.json").write_bytes(canonical_json(summary))
    print(f"COMPARED lossless checkpoints parts={len(boundaries)} "
          f"through={followup} retired={control.core.machine.commits} "
          f"uart_bytes={control.uart_bytes}; five corruption cases rejected", flush=True)


if __name__ == "__main__":
    main()
