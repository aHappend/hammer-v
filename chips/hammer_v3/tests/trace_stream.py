"""Lossless bounded-memory capture of simulator records, without per-edge stdout."""

from contextlib import contextmanager
import gzip
import hashlib
import os
from pathlib import Path
import select
import threading
import sys
from unittest.mock import patch


@contextmanager
def capture_trace(experiment, destination):
    fifo = destination.with_suffix(".fifo")
    os.mkfifo(fifo)
    descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    stopped = threading.Event()
    initialized = threading.Event()
    errors = []
    record = {
        "path": experiment.relative(destination),
        "encoding": "gzip",
        "uncompressed_bytes": 0,
        "records": 0,
    }

    def consume():
        checksum = hashlib.sha256()
        try:
            with gzip.open(destination, "xb", compresslevel=1) as output:
                initialized.set()
                while True:
                    readable, _, _ = select.select([descriptor], [], [], 0.1)
                    if not readable:
                        if stopped.is_set():
                            break
                        continue
                    data = os.read(descriptor, 65536)
                    output.write(data)
                    checksum.update(data)
                    record["uncompressed_bytes"] += len(data)
                    record["records"] += data.count(b"\n")
            record["uncompressed_sha256"] = checksum.hexdigest()
            record["compressed_bytes"] = destination.stat().st_size
        except Exception as error:
            errors.append(error)
            record["failure"] = f"{type(error).__name__}: {error}"
        finally:
            initialized.set()
            os.close(descriptor)

    reader = threading.Thread(target=consume, name="verification-trace", daemon=True)
    reader.start()
    try:
        if not initialized.wait(timeout=60):
            raise RuntimeError("TRACE_CAPTURE_STARTUP_TIMEOUT")
        if errors:
            raise RuntimeError(f"TRACE_CAPTURE_FAILED: {record['failure']}") from errors[0]
        yield fifo
    finally:
        stopped.set()
        reader.join(timeout=60)
        fifo.unlink()
        experiment.receipt.setdefault("trace_streams", []).append(record)
        experiment.persist()
        if reader.is_alive():
            raise RuntimeError("TRACE_CAPTURE_DRAIN_TIMEOUT")
        if errors:
            raise RuntimeError(f"TRACE_CAPTURE_FAILED: {record['failure']}") from errors[0]


def read_trace(path):
    with gzip.open(path, "rt", encoding="ascii") as source:
        for line in source:
            yield line.rstrip("\n")


def self_test(experiment):
    destination = experiment.folder / "capture.txt.gz"
    writer = (
        "import sys\n"
        "with open(sys.argv[1], 'wb') as output:\n"
        " for number in range(50000):\n"
        "  output.write(('record %08x %016x\\n' % (number, number * 1234567)).encode('ascii'))\n"
    )
    with capture_trace(experiment, destination) as fifo:
        experiment.run("trace-writer", [sys.executable, "-c", writer,
                                        experiment.relative(fifo)])
    for number, line in enumerate(read_trace(destination)):
        if line != f"record {number:08x} {number * 1234567:016x}":
            raise AssertionError(f"TRACE_CAPTURE_CONTENT_MISMATCH record={number}")
    expected = b"".join(f"record {number:08x} {number * 1234567:016x}\n".encode("ascii")
                        for number in range(50000))
    record = experiment.receipt["trace_streams"][-1]
    if (record["records"] != 50000 or record["uncompressed_bytes"] != len(expected) or
            record["uncompressed_sha256"] != hashlib.sha256(expected).hexdigest()):
        raise AssertionError("TRACE_CAPTURE_INTEGRITY_MISMATCH")
    failure_observed = False
    with patch.object(gzip, "open", side_effect=OSError("injected full output device")):
        try:
            with capture_trace(experiment, experiment.folder / "failed.txt.gz"):
                raise AssertionError("TRACE_CAPTURE_FAILED_STARTUP_WAS_ACCEPTED")
        except RuntimeError as error:
            if not str(error).startswith("TRACE_CAPTURE_FAILED:"):
                raise
            failure_observed = True
    if not failure_observed or list(experiment.folder.glob("*.fifo")):
        raise AssertionError("TRACE_CAPTURE_FAILURE_OR_CLEANUP_MISSING")
    experiment.receipt["assertions"].append({
        "id": "lossless-stream-and-output-error-rejection", "passed": True,
        "compared_records": 50000, "compared_bytes": len(expected),
        "injected_output_error_rejected": failure_observed})


if __name__ == "__main__":
    import argparse

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from probe import Probe, ROOT

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repair-of", help="Project-relative retained diagnostic being repaired")
    arguments = parser.parse_args()
    experiment = Probe("verifier-trace-stream")
    if arguments.repair_of:
        prior = ROOT / arguments.repair_of
        if not prior.is_file() or ROOT not in prior.resolve().parents:
            raise ValueError("--repair-of must name an existing project-local receipt")
        experiment.receipt["repair_of"] = arguments.repair_of
        experiment.persist()
    try:
        self_test(experiment)
    except Exception as error:
        experiment.finish(f"{type(error).__name__}: {error}")
        raise
    experiment.finish()
