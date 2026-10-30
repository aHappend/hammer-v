#!/usr/bin/env python3
"""Rebuild/audit declared software inputs in a clean project directory.

This diagnostic establishes clean source/build reproduction only. It is not
the required clean default-seed timed-oracle/RTL boot, which remains separate.
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
PATTERNS = (
    "rtl/*.sv", "software/*", "design/*.md", "hammer_v3_reference/rtl/*.sv",
    "tests/*.py", "tests/*.cpp", "tests/*.hpp",
)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--compare-manifest")
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    project = out / "project"
    project.mkdir()
    sources = {}
    for pattern in PATTERNS:
        for source in sorted(ROOT.glob(pattern)):
            if not source.is_file():
                continue
            path = source.relative_to(ROOT)
            if any(part in (".git", ".vulcan", ".tooling", "VULCAN") for part in path.parts):
                raise AssertionError("Runtime metadata in reproduction selector")
            target = project / path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            sources[path.as_posix()] = digest(source)
            if digest(target) != sources[path.as_posix()]:
                raise AssertionError(f"Clean reproduction copy mismatch: {path}")
    if not sources or (project / "build").exists() or (project / "evidence").exists():
        raise AssertionError("Clean reproduction contains original build/evidence artifacts")
    (out / "source-manifest.json").write_text(json.dumps(sources, indent=2) + "\n")
    records = []
    commands = [
        [sys.executable, "software/build.py", "--out", "build/software-rebuild", "--jobs", "4"],
        [sys.executable, "tests/asset_checks.py", "--manifest",
         "build/software-rebuild/image-manifest.json", "--out", "build/assets"],
    ]
    for index, argv in enumerate(commands):
        record = {"argv": argv, "cwd": (relative / "project").as_posix(),
                  "started_unix": time.time()}
        records.append(record)
        with (out / f"{index}.stdout.log").open("wb") as so, (
            out / f"{index}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(argv, cwd=project, stdout=so, stderr=se, check=False)
        record.update(exit_code=result.returncode, ended_unix=time.time())
        (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        if result.returncode:
            raise AssertionError(f"Clean software reproduction command {index}: {relative}")
    clean = json.loads((project / "build/software-rebuild/image-manifest.json").read_text())
    compared = []
    if args.compare_manifest:
        original = json.loads((ROOT / args.compare_manifest).read_text())
        for name, image in original["images"].items():
            if clean["images"][name]["sha256"] != image["sha256"]:
                raise AssertionError(f"Clean build changed deterministic image: {name}")
            compared.append(name)
    (out / "summary.json").write_text(json.dumps({
        "scope": "clean source build/audit only, not the complete clean RTL boot",
        "timed_default_seed_boot": False, "copied_sources": len(sources),
        "deterministic_images_compared": compared,
        "images": clean["images"],
    }, indent=2) + "\n")
    print(f"Clean-built/audited {len(clean['images'])} images from {len(sources)} declared inputs; "
          f"byte-identical original images compared={len(compared)}; full clean RTL boot outstanding")


if __name__ == "__main__":
    main()
