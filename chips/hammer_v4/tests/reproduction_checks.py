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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reproduction_diff import cpio_entries, file_symbols, sections


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
        [sys.executable, "software/build.py", "--jobs", "4"],
        [sys.executable, "tests/asset_checks.py", "--manifest",
         "build/software/image-manifest.json", "--out", "build/assets"],
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
    clean = json.loads((project / "build/software/image-manifest.json").read_text())
    compared = []
    if args.compare_manifest:
        original = json.loads((ROOT / args.compare_manifest).read_text())
        for key in ("sources", "tools", "platform", "layout"):
            if clean[key] != original[key]:
                raise AssertionError(f"Clean build changed {key}")
        if set(clean["images"]) != set(original["images"]):
            raise AssertionError("Clean build changed the declared image set")
        for name, image in sorted(original["images"].items()):
            old_path = ROOT / image["path"]
            new_path = project / clean["images"][name]["path"]
            for path, facts in ((old_path, image), (new_path, clean["images"][name])):
                if path.stat().st_size != facts["bytes"] or digest(path) != facts["sha256"]:
                    raise AssertionError(f"Image does not match its own manifest: {path}")
            if old_path.read_bytes() != new_path.read_bytes():
                raise AssertionError(f"Clean build changed deterministic image: {name}")
            compared.append({"name": name, "bytes": image["bytes"],
                             "sha256": image["sha256"]})
    epoch = clean["platform"]["source_date_epoch"]
    entries = cpio_entries((project / clean["images"]["initramfs.cpio"]["path"]).read_bytes())
    if any(entry["mtime"] != epoch for entry in entries if entry["name"] != "TRAILER!!!"):
        raise AssertionError("Packaged initramfs timestamps differ from the frozen epoch")
    init_entry = next(entry for entry in entries if entry["name"] == "init")
    if init_entry["payload_sha256"] != clean["images"]["init"]["sha256"]:
        raise AssertionError("Packaged /init differs from declared ELF")
    symbols = {}
    for name, required in (("init", "init_entry.o"), ("fw_jump.elf", "fw_entry.o")):
        blob = (project / clean["images"][name]["path"]).read_bytes()
        symbols[name] = file_symbols(blob, sections(blob))
        if required not in symbols[name] or any(
            symbol.startswith("cc") and symbol.endswith(".o") for symbol in symbols[name]
        ):
            raise AssertionError(f"Unstable assembly object identity: {name}")
    (out / "summary.json").write_text(json.dumps({
        "scope": "clean source build/audit only, not the complete clean RTL boot",
        "timed_default_seed_boot": False, "copied_sources": len(sources),
        "deterministic_images_compared": compared,
        "images": clean["images"],
        "initramfs_entries": entries, "elf_file_symbols": symbols,
        "default_build_destination": "build/software",
        "repair_of": clean["platform"]["build_reproducibility"]["repair_of"],
        "diagnosis": clean["platform"]["build_reproducibility"]["diagnosis"],
    }, indent=2) + "\n")
    print(f"Clean-built/audited {len(clean['images'])} images from {len(sources)} declared inputs; "
          f"byte-identical original images compared={len(compared)}; full clean RTL boot outstanding")


if __name__ == "__main__":
    main()
