#!/usr/bin/env python3
"""Source-bound, lossless checkpoints of the independent event machine.

Only locally generated checkpoints are inputs. Python bytecode and object state
are executable, not an interchange format for untrusted files. Verify the
receipt, interpreter and complete source identity before deserialization.
"""

import argparse
import importlib
import io
import json
import marshal
from pathlib import Path
import pickle
import sys
import time
import types
import zlib


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from preparation import source_hashes
from system_checks import relative_path
from system_oracle import BOUND, IMAGE_LAYOUT, Scenario, canonical_json, digest, load_images
from system_prediction import Prediction


MODULES = frozenset((
    "architecture", "rv64_reference", "system_checkpoint", "system_core",
    "system_execution", "system_memory", "system_oracle", "system_platform",
    "system_prediction", "system_protocol",
))
STREAMS = ("expected-events.txt", "expected-uart.bin")
MAX_PART_EDGES = 67108864


def interpreter():
    return {"implementation": sys.implementation.name,
            "version": list(sys.version_info[:3]), "marshal_version": marshal.version}


def portable_code(code):
    filename = Path(code.co_filename)
    if filename.is_absolute():
        filename = filename.relative_to(ROOT)
    return code.replace(
        co_filename=filename.as_posix(),
        co_consts=tuple(portable_code(item) if isinstance(item, types.CodeType) else item
                        for item in code.co_consts),
    )


def empty_cell():
    return types.CellType()


def restore_cell(cell, state):
    if state:
        cell.cell_contents = state[0]


def restore_function(function, state):
    defaults, kwdefaults, attributes = state
    function.__defaults__, function.__kwdefaults__ = defaults, kwdefaults
    function.__dict__.update(attributes)


def function_with_cells(module, encoded, cells):
    if module not in MODULES:
        raise ValueError(f"Unapproved callback module: {module}")
    code = marshal.loads(encoded)
    return types.FunctionType(
        code, importlib.import_module(module).__dict__, code.co_name,
        closure=cells or None,
    )


class CallbackPickler(pickle.Pickler):
    """Preserve callback cycles using deferred cell contents and pickle memoization."""

    def reducer_override(self, value):
        if isinstance(value, types.CellType):
            try:
                state = (value.cell_contents,)
            except ValueError:
                state = ()
            return empty_cell, (), state, None, None, restore_cell
        if isinstance(value, types.FunctionType) and "<locals>" in value.__qualname__:
            if value.__module__ not in MODULES:
                raise ValueError(f"Cannot checkpoint foreign callback: {value.__module__}")
            return (
                function_with_cells,
                (value.__module__, marshal.dumps(portable_code(value.__code__)),
                 value.__closure__ or ()),
                (value.__defaults__, value.__kwdefaults__, value.__dict__),
                None, None, restore_function,
            )
        return NotImplemented


def encode(value):
    stream = io.BytesIO()
    CallbackPickler(stream, protocol=5).dump(value)
    return stream.getvalue()


def decode(data):
    return pickle.loads(data)


def write_checkpoint(prediction, directory, binding, parent):
    if hasattr(prediction, "event_file") or hasattr(prediction, "uart_file"):
        raise AssertionError("Prediction streams must be settled before checkpointing")
    directory.mkdir(parents=True, exist_ok=False)
    original_out = prediction.out
    prediction.out = original_out.relative_to(ROOT)
    try:
        raw = encode(prediction)
        payload = zlib.compress(raw, level=1)
    finally:
        prediction.out = original_out
    checkpoint = directory / "machine.pickle.z"
    with checkpoint.open("xb") as stream:
        stream.write(payload)
    record = {
        "schema": 1, "scope": "independent-machine-checkpoint-not-linux-acceptance",
        "interpreter": interpreter(), "source_sha256": source_hashes(),
        "binding": binding, "parent": parent,
        "edge": prediction.clock.edge, "phase": int(prediction.clock.phase),
        "callbacks": prediction.clock.callbacks, "retired": prediction.core.machine.commits,
        "events": prediction.events, "uart_bytes": prediction.uart_bytes,
        "final_edge": prediction.final_edge,
        "payload": {"path": "machine.pickle.z", "bytes": len(payload),
                    "uncompressed_bytes": len(raw), "codec": "zlib",
                    "sha256": digest(checkpoint)},
        "streams": {name: {"bytes": (original_out / name).stat().st_size,
                            "sha256": digest(original_out / name)} for name in STREAMS},
        "created_unix": time.time(),
    }
    with (directory / "checkpoint.json").open("xb") as stream:
        stream.write(canonical_json(record))
    return record


def read_checkpoint(directory, binding):
    record = json.loads((directory / "checkpoint.json").read_text())
    if record["schema"] != 1 or record["scope"] != \
            "independent-machine-checkpoint-not-linux-acceptance" or \
            record["interpreter"] != interpreter() or \
            record["source_sha256"] != source_hashes() or record["binding"] != binding:
        raise ValueError("Checkpoint interpreter/source/input binding differs")
    payload = directory / "machine.pickle.z"
    if payload.is_symlink() or record["payload"]["path"] != payload.name or \
            record["payload"]["codec"] != "zlib" or payload.stat().st_size != \
            record["payload"]["bytes"] or digest(payload) != record["payload"]["sha256"]:
        raise ValueError("Checkpoint payload identity differs")
    previous_edge, parent = record["edge"], record["parent"]
    while parent is not None:
        parent_path = ROOT / relative_path(ROOT, parent["path"], output=True)
        if parent_path.name != "checkpoint.json" or parent_path.is_symlink() or \
                digest(parent_path) != parent["sha256"]:
            raise ValueError("Checkpoint parent hash chain differs")
        previous = json.loads(parent_path.read_text())
        if previous["edge"] != parent["edge"] or not -1 <= previous["edge"] < previous_edge or \
                previous["binding"] != binding or \
                previous["source_sha256"] != record["source_sha256"] or \
                previous["interpreter"] != record["interpreter"]:
            raise ValueError("Checkpoint parent time/input chain differs")
        previous_edge, parent = previous["edge"], previous["parent"]
    out = ROOT / relative_path(ROOT, binding["out"], output=True)
    for name in STREAMS:
        if (out / name).stat().st_size != record["streams"][name]["bytes"] or \
                digest(out / name) != record["streams"][name]["sha256"]:
            raise ValueError(f"Checkpoint output prefix differs: {name}")
    raw = zlib.decompress(payload.read_bytes())
    if len(raw) != record["payload"]["uncompressed_bytes"]:
        raise ValueError("Checkpoint uncompressed length differs")
    prediction = decode(raw)
    if not isinstance(prediction, Prediction) or prediction.out != Path(binding["out"]) or \
            prediction.clock.edge != record["edge"] or \
            int(prediction.clock.phase) != record["phase"] or \
            prediction.clock.callbacks != record["callbacks"] or \
            prediction.core.machine.commits != record["retired"] or \
            prediction.events != record["events"] or \
            prediction.uart_bytes != record["uart_bytes"] or \
            prediction.final_edge != record["final_edge"]:
        raise ValueError("Decoded checkpoint state differs from its receipt")
    prediction.out = out
    return prediction, record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--through", required=True, type=int)
    parser.add_argument("--resume")
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--diagnostic-uart-bytes", type=int)
    args = parser.parse_args()
    if not 0 <= args.through < BOUND or args.diagnostic_uart_bytes is not None and \
            args.diagnostic_uart_bytes <= 0:
        parser.error("Invalid absolute edge or diagnostic goal")
    out = ROOT / relative_path(ROOT, args.out, output=True)
    checkpoint = ROOT / relative_path(ROOT, args.checkpoint, output=True)
    manifest_path = relative_path(ROOT, args.manifest)
    scenario_path = relative_path(ROOT, args.scenario)
    manifest, images = load_images(ROOT, manifest_path)
    scenario = Scenario.read(ROOT / scenario_path)
    if dict(scenario.image_hashes) != {
        name: manifest["images"][name]["sha256"] for name, _, _ in IMAGE_LAYOUT
    }:
        raise ValueError("Scenario and software images differ")
    binding = {
        "out": out.relative_to(ROOT).as_posix(),
        "manifest_sha256": digest(ROOT / manifest_path),
        "scenario_sha256": digest(ROOT / scenario_path),
        "images": dict(scenario.image_hashes),
        "diagnostic_uart_bytes": args.diagnostic_uart_bytes,
        "bound": BOUND,
    }
    parent = None
    if args.resume:
        previous = ROOT / relative_path(ROOT, args.resume, output=True)
        prediction, record = read_checkpoint(previous, binding)
        parent = {"path": (previous / "checkpoint.json").relative_to(ROOT).as_posix(),
                  "sha256": digest(previous / "checkpoint.json"), "edge": record["edge"]}
        if prediction.final_edge is not None or args.through <= prediction.clock.edge:
            raise ValueError("Checkpoint is complete or does not advance absolute time")
    else:
        out.mkdir(parents=True, exist_ok=False)
        prediction = Prediction(scenario, images, out,
                                diagnostic_uart_bytes=args.diagnostic_uart_bytes)
    if args.through - prediction.clock.edge > MAX_PART_EDGES:
        raise ValueError(f"A diagnostic checkpoint part covers at most {MAX_PART_EDGES} edges")
    began = time.monotonic()
    try:
        prediction.advance(args.through, resume=bool(args.resume))
    except Exception as error:
        checkpoint.mkdir(parents=True, exist_ok=False)
        failure = {
            "scope": "failed-independent-checkpoint-part-not-linux-acceptance",
            "binding": binding, "parent": parent,
            "source_sha256": source_hashes(),
            "failure": {"type": type(error).__name__, "message": str(error)},
            "edge": prediction.clock.edge, "pc": prediction.core.machine.pc,
            "retired": prediction.core.machine.commits,
            "events": prediction.events, "uart_bytes": prediction.uart_bytes,
            "coverage": prediction.coverage.counts,
            "recent": list(prediction.core.recent),
            "uart_context": list(prediction.core.platform.uart_transactions),
            "uart_modes": list(prediction.core.platform.uart_modes),
        }
        with (checkpoint / "failure.json").open("xb") as stream:
            stream.write(canonical_json(failure))
        raise
    record = write_checkpoint(prediction, checkpoint, binding, parent)
    print(f"CHECKPOINT edge={record['edge']} retired={record['retired']} "
          f"events={record['events']} uart_bytes={record['uart_bytes']} "
          f"final_edge={record['final_edge']} seconds={time.monotonic() - began:.3f}",
          flush=True)


if __name__ == "__main__":
    importlib.import_module("system_checkpoint").main()
