"""Lossless bounded-memory capture of simulator records, without per-edge stdout."""

from contextlib import contextmanager
import gzip
import hashlib
import errno
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
        persistence_error = None
        try:
            experiment.persist()
        except Exception as error:
            persistence_error = error
        if reader.is_alive():
            message = "TRACE_CAPTURE_DRAIN_TIMEOUT"
            if persistence_error is not None:
                message += f"; {persistence_error}"
            raise RuntimeError(message) from persistence_error
        if errors:
            message = f"TRACE_CAPTURE_FAILED: {record['failure']}"
            if persistence_error is not None:
                message += f"; {persistence_error}"
            raise RuntimeError(message) from errors[0]
        if persistence_error is not None:
            raise persistence_error


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
    persistence_self_test(experiment)


def persistence_self_test(experiment):
    import probe

    real_gzip_open = gzip.open

    def partial_write(receipt, output, **kwargs):
        output.write('{"incomplete":')
        output.flush()
        raise OSError(errno.ENOSPC, "injected receipt write exhaustion")

    cases = []
    for stage in ("write", "fsync", "replace"):
        fixture = object.__new__(probe.Probe)
        fixture.folder = experiment.folder / f"receipt-{stage}-00000031"
        fixture.folder.mkdir()
        fixture.receipt = {"assertions": [], "generation": "last-valid"}
        fixture.persist()
        path = fixture.folder / "receipt.json"
        original = path.read_bytes()
        fixture.receipt["generation"] = "must-not-replace"
        target = {"write": "probe.json.dump", "fsync": "probe.os.fsync",
                  "replace": "probe.os.replace"}[stage]
        injected_error = (partial_write if stage == "write" else
                          OSError(errno.ENOSPC, f"injected receipt {stage} exhaustion"))
        first_record = threading.Event()
        capture_failed = threading.Event()

        @contextmanager
        def failing_capture(*args, **kwargs):
            with real_gzip_open(*args, **kwargs) as output:
                class FailingOutput:
                    def write(self, data):
                        if first_record.is_set():
                            capture_failed.set()
                            raise OSError(errno.ENOSPC, "injected trace capture exhaustion")
                        output.write(data)
                        first_record.set()

                yield FailingOutput()

        with patch(target, side_effect=injected_error):
            with patch.object(gzip, "open", side_effect=failing_capture):
                try:
                    with capture_trace(fixture, fixture.folder / "failed.txt.gz") as fifo:
                        with fifo.open("wb", buffering=0) as writer:
                            writer.write(b"retained first record\n")
                            if not first_record.wait(timeout=60):
                                raise AssertionError("INJECTED_CAPTURE_FIRST_RECORD_MISSING")
                            writer.write(b"rejected second record\n")
                            if not capture_failed.wait(timeout=60):
                                raise AssertionError("INJECTED_CAPTURE_FAILURE_MISSING")
                except RuntimeError as error:
                    diagnostic = str(error)
                    if not (diagnostic.startswith("TRACE_CAPTURE_FAILED:") and
                            "injected trace capture exhaustion" in diagnostic and
                            "RECEIPT_PERSIST_FAILED:" in diagnostic and
                            f"injected receipt {stage} exhaustion" in diagnostic):
                        raise AssertionError(f"CAPTURE_DIAGNOSIS_OBSCURED: {diagnostic}")
                else:
                    raise AssertionError("COMBINED_CAPTURE_PERSISTENCE_FAILURE_ACCEPTED")
                # The suite's outer failure handler must not obscure the capture either.
                try:
                    fixture.finish(diagnostic)
                except RuntimeError as error:
                    final_diagnostic = str(error)
                    if ("TRACE_CAPTURE_FAILED:" not in final_diagnostic or
                            "RECEIPT_PERSIST_FAILED:" not in final_diagnostic):
                        raise AssertionError(f"FINAL_DIAGNOSIS_OBSCURED: {error}")
                else:
                    raise AssertionError("FAILED_RECEIPT_FINALIZATION_ACCEPTED")
        if path.read_bytes() != original:
            raise AssertionError(f"LAST_VALID_RECEIPT_CHANGED: {stage}")
        if list(fixture.folder.glob(".receipt-*.tmp")) or list(fixture.folder.glob("*.fifo")):
            raise AssertionError(f"FAILED_PERSISTENCE_CLEANUP_MISSING: {stage}")
        log = fixture.folder / "injected.stderr.txt"
        log.write_text(diagnostic + "\n" + final_diagnostic + "\n")
        fixture.receipt["assertions"].append({
            "id": "injected-failure-retained", "passed": True,
            "last_valid_receipt_unchanged": True, "stage": stage})
        fixture.persist()
        recovered = probe.json.loads(path.read_text())
        stream = recovered["trace_streams"][0]
        if (len(recovered["persistence_errors"]) != 2 or
                "injected trace capture exhaustion" not in stream["failure"] or
                stream["records"] != 1 or
                stream["uncompressed_bytes"] != len(b"retained first record\n")):
            raise AssertionError(f"PERSISTENCE_ERROR_RECOVERY_MISSING: {stage}")
        cases.append({"stage": stage, "receipt": fixture.relative(path),
                      "stderr": fixture.relative(log)})
    experiment.receipt["assertions"].append({
        "id": "capture-plus-receipt-enospc", "passed": True,
        "last_valid_receipts_preserved": len(cases), "cases": cases})


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
