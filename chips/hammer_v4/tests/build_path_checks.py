#!/usr/bin/env python3
"""Exercise build destination rejection without writing to protected trees."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--occupied", required=True,
                        help="completed real build to check for non-overwriting")
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    occupied = Path(args.occupied)
    if occupied.is_absolute() or ".." in occupied.parts:
        parser.error("--occupied must be project-relative")
    manifest_path = ROOT / occupied / "image-manifest.json"
    original_manifest = manifest_path.read_bytes()
    manifest = json.loads(original_manifest)
    original_images = {
        name: (ROOT / item["path"]).read_bytes()
        for name, item in manifest["images"].items()
    }
    protected = ("rtl", "software", "design", "tests", "hammer_v3_reference",
                 "evidence", ".vulcan", ".git", ".tooling", "VULCAN")
    overlap = "--out must not overlap owned sources, evidence or runtime metadata"
    cases = [
        ("absolute", str(ROOT / relative / "absolute"), "project-relative"),
        ("parent-traversal", (relative / "../escape").as_posix(), "without '..'"),
        ("empty", "", "nonempty"),
        ("root", ".", "nonempty"),
        ("occupied-build", occupied.as_posix(), "already exists"),
    ]
    for index, name in enumerate(protected):
        cases.append((f"protected-{index}", name + "/forbidden", overlap))
        alias = out / f"alias-{index}"
        alias.symlink_to(ROOT / name, target_is_directory=True)
        cases.append((f"resolved-{index}",
                      (relative / alias.name / "forbidden").as_posix(), overlap))
    for name, target in (("root-alias", ROOT), ("outside-alias", ROOT.parent)):
        (out / name).symlink_to(target, target_is_directory=True)
    cases.extend([
        ("resolved-ancestor", (relative / "root-alias").as_posix(), overlap),
        ("resolved-source-through-root",
         (relative / "root-alias/software/forbidden").as_posix(), overlap),
        ("outside", (relative / "outside-alias/forbidden").as_posix(),
         "resolves outside"),
    ])
    (out / "dangling").symlink_to(out / "absent-target", target_is_directory=True)
    cases.append(("dangling", (relative / "dangling").as_posix(), "already exists"))
    (out / "loop").symlink_to("loop", target_is_directory=True)
    cases.append(("symlink-loop", (relative / "loop/forbidden").as_posix(),
                  "resolution failed"))
    records = []
    try:
        for name, destination, diagnostic in cases:
            argv = [sys.executable, "software/build.py", "--out", destination]
            with (out / f"{name}.stdout.log").open("wb") as so, (
                out / f"{name}.stderr.log"
            ).open("wb") as se:
                result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
            stderr = (out / f"{name}.stderr.log").read_text()
            records.append({
                "name": name, "argv": argv, "cwd": ".", "exit_code": result.returncode,
                "expected_diagnostic": diagnostic,
                "stdout": (relative / f"{name}.stdout.log").as_posix(),
                "stderr": (relative / f"{name}.stderr.log").as_posix(),
            })
            if result.returncode != 2 or diagnostic not in stderr:
                raise AssertionError(f"Wrong rejection for {name}: {stderr}")
            if (out / f"{name}.stdout.log").stat().st_size:
                raise AssertionError(f"Rejected path started a build: {name}")
        if manifest_path.read_bytes() != original_manifest or any(
            (ROOT / manifest["images"][name]["path"]).read_bytes() != content
            for name, content in original_images.items()
        ):
            raise AssertionError("Rejected occupied-output request changed retained images")
        (out / "summary.json").write_text(json.dumps({
            "rejected_paths": len(records), "occupied_images_unchanged": len(original_images),
            "records": records,
        }, indent=2) + "\n")
    finally:
        (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        for name in [f"alias-{index}" for index in range(len(protected))] + [
            "root-alias", "outside-alias", "dangling", "loop"
        ]:
            (out / name).unlink()
    print(f"Rejected {len(records)} forbidden/occupied destinations without starting a build")


if __name__ == "__main__":
    main()
