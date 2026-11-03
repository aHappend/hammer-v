#!/usr/bin/env python3
"""Verify public-pin evaluation equivalence and measure compiled throughput.

The bounded benchmark is not a full boot or a functional timing threshold.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from parameters import ports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    outputs = [name for direction, _, name in ports() if direction == "output"]
    if len(outputs) < 70:
        raise AssertionError("Incomplete public output discovery")
    (out / "public_outputs.hpp").write_text(
        "".join(f"CHECK_OUTPUT({name})\n" for name in outputs)
    )
    manifest = json.loads((ROOT / args.manifest).read_text())
    for item in manifest["images"].values():
        if hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest() != item["sha256"]:
            raise AssertionError("Benchmark software image hash mismatch")
    records = []

    def run(argv):
        index = len(records)
        record = {"argv": [str(arg) for arg in argv], "cwd": ".",
                  "started_unix": time.time()}
        records.append(record)
        with (out / f"{index}.stdout.log").open("wb") as so, (
            out / f"{index}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(record["argv"], cwd=ROOT, stdout=so, stderr=se,
                                    check=False)
        record.update(exit_code=result.returncode, ended_unix=time.time())
        (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(f"Eval-schedule command {index} failed: {relative}")
        return (out / f"{index}.stdout.log").read_text()

    model = out / "compile-obj"
    try:
        run(["verilator", "-O3", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
             "--top-module", "hammer_v4_top", "--Mdir", model,
             "-GIMEM_WORDS=32", "-GDMEM_WORDS=3",
             "-CFLAGS", f"-O3 -std=c++17 -I{out}",
             *[p.relative_to(ROOT) for p in sorted((ROOT / "rtl").glob("*.sv"))],
             ROOT / "tests/eval_schedule_probe.cpp", "-MAKEFLAGS", "OPT_FAST=-O3"])
        executable = out / "eval-schedule-probe"
        shutil.copyfile(model / "Vhammer_v4_top", executable)
        executable.chmod(0o755)
        results = {}
        for mode, bound in (("equivalence", 1048576), ("redundant", 16777216),
                            ("combined", 16777216)):
            (out / mode).mkdir()
            text = run([executable,
                        *[ROOT / manifest["images"][name]["path"]
                          for name in ("fw_jump.bin", "Image", "hammer-v4.dtb")],
                        out / mode, mode, str(bound)])
            results[mode] = json.loads(text)
        for field in ("edges", "retired", "traps", "reads", "writes", "uart_bytes"):
            if results["redundant"][field] != results["combined"][field]:
                raise AssertionError(f"Schedule benchmark changed observable {field}")
        if (out / "redundant/uart.bin").read_bytes() != (
            out / "combined/uart.bin"
        ).read_bytes():
            raise AssertionError("Schedule benchmark changed serialized UART bytes")
        (out / "summary.json").write_text(json.dumps({
            "scope": "public-pin evaluation equivalence and bounded throughput only",
            "public_output_count": len(outputs),
            "exact_pin_comparisons": len(outputs) * 2 * results["equivalence"]["edges"],
            "results": results,
            "combined_edges_per_second": 16777216 / results["combined"]["seconds"],
        }, indent=2) + "\n")
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in model.glob(pattern):
                path.unlink()
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()
