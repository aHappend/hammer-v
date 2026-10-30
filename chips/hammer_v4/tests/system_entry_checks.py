#!/usr/bin/env python3
"""Verify the current missing-oracle boundary without launching any RTL boot.

This negative check is for the in-progress implementation only. When the full
oracle is implemented, replace the missing-producer fixture, not the mandatory
complete-boot check or its thresholds.
"""

import argparse
import json
from pathlib import Path
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_checks import Execution, inventory, relative_path
from system_oracle import canonical_json, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    relative = relative_path(ROOT, args.out, output=True)
    manifest = relative_path(ROOT, args.manifest)
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    canonical = ROOT / "evidence/uart_linux_boot.log"
    old_canonical = digest(canonical) if canonical.is_file() else None
    execution = Execution(out, ["python3", "tests/system_entry_checks.py",
                                "--out", args.out, "--manifest", args.manifest])
    failure = None
    try:
        execution.prepare(ROOT, manifest, relative / "seed-11", execution.receipt["runs"][0])
    except RuntimeError as error:
        failure = error
        execution.fail(error)
    finally:
        execution.receipt.update(
            ended_unix=time.time(),
            sources_unchanged=inventory(ROOT) == execution.receipt["source_sha256"],
        )
        execution.save()
    if failure is None:
        raise AssertionError("This negative check is obsolete: oracle generation did not reject")
    commands = execution.receipt["commands"]
    if len(commands) != 1 or commands[0]["argv"][1] != "tests/system_oracle.py" or \
            commands[0]["exit_code"] != 1 or commands[0]["ended_unix"] is None:
        raise AssertionError("Expected one settled oracle rejection, not a simulator/tool failure")
    if b"No expected UART stream has been generated" not in (
        ROOT / commands[0]["stderr"]
    ).read_bytes():
        raise AssertionError("Oracle failed for an unexpected reason")
    if list(out.rglob("launch-seal.json")) or list(out.rglob("uart.bin")) or \
            list(out.rglob("system-probe")) or list(out.rglob("compile-obj")):
        raise AssertionError("Incomplete oracle was followed by DUT compilation/execution")
    if (digest(canonical) if canonical.is_file() else None) != old_canonical:
        raise AssertionError("A rejected expectation changed the canonical UART log")
    statuses = [record["status"] for record in execution.receipt["runs"]]
    if execution.receipt["status"] != "failed" or statuses != [
        "failed", "not_run", "not_run", "not_run"
    ]:
        raise AssertionError("Unexecuted required boots disappeared from the denominator")
    (out / "summary.json").write_bytes(canonical_json({
        "scope": "negative orchestration check only; no RTL or complete oracle executed",
        "oracle_rejection_receipt": (execution.evidence / "receipt.json")
                                    .relative_to(ROOT).as_posix(),
        "all_four_required_boot_statuses": statuses,
        "dut_launched": False, "canonical_log_changed": False,
    }))
    print("COMPARED incomplete oracle rejected before DUT compilation; "
          "all four required boots retained as failed/not_run, not accepted")


if __name__ == "__main__":
    main()
