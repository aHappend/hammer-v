#!/usr/bin/env python3
"""Compare independent untimed Linux output with an existing RTL diagnostic.

This is not a timed oracle or an admitted seed run. In particular, generating
an ISA model's output while the DUT is running does not freeze expectations
before DUT execution.
"""

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def argument(receipt, name):
    return receipt["argv"][receipt["argv"].index(name) + 1]


def project_path(value):
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise AssertionError(f"Expected project-relative input: {value}")
    return ROOT / path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--functional-receipt", required=True)
    parser.add_argument("--rtl-receipt", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    receipts = [json.loads(project_path(value).read_text())
                for value in (args.functional_receipt, args.rtl_receipt)]
    reference, rtl = receipts
    scripts = ("tests/functional_boot.py", "tests/platform_probe.py")
    unchanged = []
    for receipt, script in zip(receipts, scripts):
        if receipt["exit_code"] != 0 or receipt["argv"][1] != script:
            raise AssertionError(f"Not a successful diagnostic for {script}")
        executed = [script, "tests/preparation.py"]
        if script == scripts[0]:
            executed.extend(["tests/rv64_reference.py", "tests/architecture.py"])
        else:
            executed.append("tests/platform_probe.cpp")
        for name, old_hash in receipt["source_sha256"].items():
            if name.startswith(("rtl/", "software/", "design/", "hammer_v3_reference/")):
                executed.append(name)
        for name in executed:
            if digest(project_path(name)) != receipt["source_sha256"][name]:
                raise AssertionError(f"Changed diagnostic execution source: {name}")
        unchanged.append(sorted(set(executed)))
    manifest_name = argument(reference, "--manifest")
    if manifest_name != argument(rtl, "--manifest"):
        raise AssertionError("Diagnostics did not use the same image manifest")
    manifest_path = project_path(manifest_name)
    manifest = json.loads(manifest_path.read_text())
    for name, image in manifest["images"].items():
        if digest(project_path(image["path"])) != image["sha256"]:
            raise AssertionError(f"Changed diagnostic image: {name}")
    ref_out = project_path(argument(reference, "--out"))
    rtl_out = project_path(argument(rtl, "--out"))
    result = json.loads((ref_out / "result.json").read_text())
    if not result["diagnostic_only"] or result["timed_full_system_oracle"] or \
            not result["complete_pid1_panic"]:
        raise AssertionError("Independent diagnostic scope or completion mismatch")
    expected_path, actual_path = ref_out / "functional-uart.bin", rtl_out / "uart.bin"
    expected, actual = expected_path.read_bytes(), actual_path.read_bytes()
    if digest(expected_path) != result["uart_sha256"] or len(expected) != result["uart_bytes"]:
        raise AssertionError("Independent diagnostic output changed")
    panic = (
        b"---[ end Kernel panic - not syncing: Attempted to kill init! "
        b"exitcode=0x00000000 ]---"
    )
    if not expected.endswith(panic):
        raise AssertionError("Independent diagnostic omitted the full panic")
    mismatch = next((index for index, pair in enumerate(zip(expected, actual))
                     if pair[0] != pair[1]), None)
    if mismatch is None and len(expected) != len(actual):
        mismatch = min(len(expected), len(actual))
    summary = {
        "scope": "post-run functional comparison only",
        "acceptance_evidence": False,
        "timed_full_system_oracle": False,
        "functional_reference_finished_before_rtl_start":
            reference["ended_unix"] <= rtl["started_unix"],
        "receipts": [args.functional_receipt, args.rtl_receipt],
        "receipt_sha256": [digest(project_path(value))
                           for value in (args.functional_receipt, args.rtl_receipt)],
        "manifest": manifest_name, "manifest_sha256": digest(manifest_path),
        "images": {name: image["sha256"] for name, image in manifest["images"].items()},
        "unchanged_execution_sources": unchanged,
        "reference_uart": expected_path.relative_to(ROOT).as_posix(),
        "rtl_uart": actual_path.relative_to(ROOT).as_posix(),
        "reference_bytes": len(expected), "rtl_bytes": len(actual),
        "reference_sha256": digest(expected_path), "rtl_sha256": digest(actual_path),
        "full_byte_equality": expected == actual, "first_mismatch": mismatch,
    }
    if mismatch is not None:
        summary["expected_context_hex"] = expected[max(0, mismatch - 16):mismatch + 17].hex()
        summary["actual_context_hex"] = actual[max(0, mismatch - 16):mismatch + 17].hex()
    (out / "comparison.json").write_text(json.dumps(summary, indent=2) + "\n")
    if mismatch is not None:
        raise AssertionError(f"Independent functional UART mismatch at byte {mismatch}")
    print(f"Compared all {len(actual)} bytes without normalization; untimed post-run "
          "diagnostic only, not pre-frozen timed-oracle acceptance")


if __name__ == "__main__":
    main()
