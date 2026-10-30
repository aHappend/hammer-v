#!/usr/bin/env python3
"""Focused firmware/Sv39 diagnostic, not full-system acceptance or an oracle."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--mode", choices=("firmware", "sv39", "user"), default="firmware")
    args = parser.parse_args()
    out = Path(args.out)
    if out.is_absolute() or ".." in out.parts or out.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / out
    out.mkdir(parents=True, exist_ok=False)
    manifest_path = ROOT / args.manifest
    manifest = json.loads(manifest_path.read_text())
    for item in manifest["images"].values():
        path = ROOT / item["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"Image hash mismatch: {item['path']}")
    model = out / "compile-obj"
    commands = []

    def run(argv, name):
        commands.append({"argv": [str(arg) for arg in argv], "cwd": "."})
        with (out / f"{name}.stdout.log").open("wb") as so, (
            out / f"{name}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
        commands[-1]["exit_code"] = result.returncode
        (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError(f"{name} exited {result.returncode}; see {args.out}")

    run([
        "verilator", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
        "--top-module", "hammer_v4_top", "--Mdir", str(model),
        "-GIMEM_WORDS=32", "-GDMEM_WORDS=3",
        "-CFLAGS", "-O2 -std=c++17",
        *[str(p.relative_to(ROOT)) for p in sorted((ROOT / "rtl").glob("*.sv"))],
        str(ROOT / "tests/platform_probe.cpp"),
    ], "compile")
    executable = out / "platform-probe"
    shutil.copyfile(model / "Vhammer_v4_top", executable)
    executable.chmod(0o755)
    try:
        run([
            str(executable),
            *[str(ROOT / manifest["images"][name]["path"])
              for name in ("fw_jump.bin", "Image", "hammer-v4.dtb")],
            str(out), args.mode,
        ], "simulate")
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in model.glob(pattern):
                path.unlink()
    print(f"Focused diagnostic completed: {args.out}")


if __name__ == "__main__":
    main()
