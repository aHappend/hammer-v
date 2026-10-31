#!/usr/bin/env python3
"""Source/input/binary-bound, lossless cold continuation of the RTL comparator.

The generated model, external RAM, AXI ownership, architectural scoreboard,
comparison cursors and partial UART frame travel together. A bounded part is
not a completed boot. No checkpoint is accepted after any bound input changes.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
import zlib


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from preparation import source_hashes
from system_checks import relative_path
from system_oracle import BOUND, IMAGE_LAYOUT, canonical_json, digest, load_images


MAX_PART_EDGES = 67108864
STREAMS = ("uart.bin", "milestones.log", "first-mismatch.txt", "uart-first-mismatch.txt")
EXPECTED = ("control.txt", "expected-events.txt", "expected-uart.bin", "expectations.json")


def describe(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Checkpoint artifact is not a regular file: {path.name}")
    return {"bytes": path.stat().st_size, "sha256": digest(path)}


def check_record(directory, binding, out):
    path = directory / "checkpoint.json"
    if path.is_symlink():
        raise ValueError("RTL checkpoint receipt is a symlink")
    record = json.loads(path.read_text())
    if record["schema"] != 1 or record["binding"] != binding or \
            record["source_sha256"] != source_hashes() or \
            record["scope"] != "lossless-rtl-comparator-checkpoint":
        raise ValueError("RTL checkpoint source/input/binary binding differs")
    previous_edge, parent = record["edge"], record["parent"]
    if not 0 <= previous_edge < BOUND:
        raise ValueError("RTL checkpoint absolute time differs")
    while parent is not None:
        previous = ROOT / relative_path(ROOT, parent["path"], output=True)
        if previous.name != "checkpoint.json" or previous.is_symlink() or \
                digest(previous) != parent["sha256"]:
            raise ValueError("RTL checkpoint parent identity differs")
        older = json.loads(previous.read_text())
        if older["binding"] != binding or older["source_sha256"] != record["source_sha256"] or \
                older["edge"] != parent["edge"] or not 0 <= older["edge"] < previous_edge:
            raise ValueError("RTL checkpoint parent time/input chain differs")
        previous_edge, parent = older["edge"], older["parent"]
    if describe(directory / "machine.dat.z") != record["payload"]["compressed"]:
        raise ValueError("RTL checkpoint payload identity differs")
    for name in STREAMS:
        if describe(out / name) != record["streams"][name]:
            raise ValueError(f"RTL checkpoint output prefix differs: {name}")
    return record


def pack(source, target):
    compressor = zlib.compressobj(level=1)
    with source.open("rb") as src, target.open("xb") as dst:
        for data in iter(lambda: src.read(1024 * 1024), b""):
            dst.write(compressor.compress(data))
        dst.write(compressor.flush())


def unpack(source, target, expected):
    decoder = zlib.decompressobj()
    size = 0
    with source.open("rb") as src, target.open("xb") as dst:
        for data in iter(lambda: src.read(65536), b""):
            # The compressed artifact is hashed before decoding, and the raw
            # extent is capped independently of any serialized model state.
            raw = decoder.decompress(data)
            size += len(raw)
            if size > expected["bytes"]:
                raise ValueError("RTL checkpoint uncompressed extent differs")
            dst.write(raw)
        dst.write(decoder.flush())
    if not decoder.eof or decoder.unused_data or describe(target) != expected:
        raise ValueError("RTL checkpoint uncompressed identity differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--expectations", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--through", required=True, type=int)
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--resume")
    parser.add_argument("--diagnostic-prefix", action="store_true")
    args = parser.parse_args()
    binary = ROOT / relative_path(ROOT, args.binary, output=True)
    manifest_path = relative_path(ROOT, args.manifest)
    expected = ROOT / relative_path(ROOT, args.expectations, output=True)
    out = ROOT / relative_path(ROOT, args.out, output=True)
    directory = ROOT / relative_path(ROOT, args.checkpoint, output=True)
    manifest, _ = load_images(ROOT, manifest_path)
    metadata = json.loads((expected / "expectations.json").read_text())
    scope = "independent-clocked-prefix" if args.diagnostic_prefix else \
        "independent-clocked-complete-linux"
    if metadata["scope"] != scope or metadata["bound"] != BOUND:
        raise ValueError("Wrong expectation scope or continuous bound")
    if not args.diagnostic_prefix:
        from system_protocol import unchanged_expectations
        seal = json.loads((expected / "launch-seal.json").read_text())
        unchanged_expectations(expected, seal)
        if seal["manifest_sha256"] != digest(ROOT / manifest_path):
            raise ValueError("RTL launch manifest differs from sealed expectations")
    if not 0 <= args.through <= metadata["final_edge"] < BOUND:
        raise ValueError("RTL checkpoint part exceeds frozen absolute completion")
    binding = {
        "binary_sha256": digest(binary), "manifest_sha256": digest(ROOT / manifest_path),
        "images": {name: manifest["images"][name]["sha256"] for name, _, _ in IMAGE_LAYOUT},
        "expectations": {name: describe(expected / name) for name in EXPECTED},
        "out": out.relative_to(ROOT).as_posix(), "bound": BOUND,
        "scope": scope, "final_edge": metadata["final_edge"],
    }
    directory.mkdir(parents=True, exist_ok=False)
    receipt = {"schema": 1, "scope": "lossless-rtl-comparator-checkpoint",
               "binding": binding, "source_sha256": source_hashes(),
               "parent": None, "started_unix": time.time(), "exit_code": None,
               "timeout_s": None, "timed_out": False}
    resume = directory / "resume-image"
    began = time.monotonic()
    try:
        first = 0
        if args.resume:
            previous = ROOT / relative_path(ROOT, args.resume, output=True)
            old = check_record(previous, binding, out)
            first = old["edge"] + 1
            receipt["parent"] = {
                "path": (previous / "checkpoint.json").relative_to(ROOT).as_posix(),
                "sha256": digest(previous / "checkpoint.json"), "edge": old["edge"],
            }
            if not 0 < old["payload"]["raw"]["bytes"] <= 256 * 1024 * 1024:
                raise ValueError("RTL checkpoint raw extent outside platform bound")
            resume.mkdir()
            unpack(previous / "machine.dat.z", resume / "machine.dat", old["payload"]["raw"])
        else:
            out.mkdir(parents=True, exist_ok=False)
        if not first <= args.through < first + MAX_PART_EDGES:
            raise ValueError("RTL checkpoint part does not advance bounded absolute time")
        argv = [
            binary.relative_to(ROOT).as_posix(),
            *[manifest["images"][name]["path"] for name, _, _ in IMAGE_LAYOUT],
            expected.relative_to(ROOT).as_posix(), out.relative_to(ROOT).as_posix(),
            "--prefix-part" if args.diagnostic_prefix else "--part", str(args.through),
            directory.relative_to(ROOT).as_posix(),
            resume.relative_to(ROOT).as_posix() if args.resume else "-",
        ]
        receipt.update(argv=argv, cwd=".")
        with subprocess.Popen(argv, cwd=ROOT) as child:
            while True:
                try:
                    receipt["exit_code"] = child.wait(timeout=20)
                    break
                except subprocess.TimeoutExpired:
                    print(f"RTL_PART_ACTIVE first={first} through={args.through} "
                          f"seconds={time.monotonic() - began:.1f}", flush=True)
        if receipt["exit_code"]:
            raise RuntimeError(f"RTL comparator part exited {receipt['exit_code']}")
        status = json.loads((directory / "part.json").read_text())
        if status["edge"] != args.through:
            raise AssertionError("RTL part stopped at the wrong absolute edge")
        raw = describe(directory / "machine.dat")
        pack(directory / "machine.dat", directory / "machine.dat.z")
        receipt.update(
            edge=args.through, first_edge=first, observations=status,
            payload={"raw": raw, "compressed": describe(directory / "machine.dat.z")},
            streams={name: describe(out / name) for name in STREAMS},
        )
        if source_hashes() != receipt["source_sha256"] or \
                digest(binary) != binding["binary_sha256"] or \
                digest(ROOT / manifest_path) != binding["manifest_sha256"] or any(
                    describe(expected / name) != binding["expectations"][name]
                    for name in EXPECTED):
            raise AssertionError("RTL checkpoint inputs changed during execution")
        (directory / "machine.dat").unlink()
        with (directory / "checkpoint.json").open("xb") as stream:
            stream.write(canonical_json({**receipt, "ended_unix": time.time()}))
        print(f"RTL_CHECKPOINT first={first} edge={args.through} "
              f"retired={status['retired']} events={status['events']} "
              f"uart_bytes={status['uart_bytes']} seconds={time.monotonic() - began:.3f}",
              flush=True)
    except Exception as error:
        receipt.update(failure={"type": type(error).__name__, "message": str(error)},
                       ended_unix=time.time())
        with (directory / "failure.json").open("xb") as stream:
            stream.write(canonical_json(receipt))
        raise
    finally:
        if (resume / "machine.dat").is_file():
            (resume / "machine.dat").unlink()
        if resume.is_dir():
            resume.rmdir()


if __name__ == "__main__":
    main()
