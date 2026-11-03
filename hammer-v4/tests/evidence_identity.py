#!/usr/bin/env python3
"""Explain source additions during a diagnostic without rewriting its receipt."""

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from preparation import source_hashes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    receipt = json.loads((ROOT / args.receipt).read_text())
    old = receipt["source_sha256"]
    current = source_hashes()
    changed = sorted(name for name in old if current.get(name) != old[name])
    added = sorted(set(current) - set(old))
    protected = ("rtl/", "software/", "design/", "hammer_v3_reference/")
    design_changes = [name for name in changed + added if name.startswith(protected)]
    executed = ("tests/platform_probe.cpp", "tests/platform_probe.py", "tests/preparation.py")
    if design_changes or any(name not in old or current.get(name) != old[name] for name in executed):
        raise AssertionError(f"Diagnostic execution inputs changed: {design_changes}, {changed}")
    manifest_path = ROOT / args.manifest
    manifest = json.loads(manifest_path.read_text())
    for name, image in manifest["images"].items():
        path = ROOT / image["path"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != image["sha256"]:
            raise AssertionError(f"Loaded image changed: {name}")
    print(json.dumps({
        "receipt": args.receipt, "original_sources_unchanged": receipt["sources_unchanged"],
        "changed_prior_files": changed, "added_files": added,
        "design_and_executed_probe_sources_match_original_hashes": True,
        "images_match_build_manifest": True,
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "acceptance_evidence": False,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
