"""Clean source-only reproduction, with no imported outputs or runtime directories."""

import shutil

import compiler
from retention import ROOT, fresh, sources


def run_portable(campaign):
    compiler.discover()
    tree = fresh(campaign.evidence.directory, "clean-source")
    for relative in sources():
        target = tree / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for component in ("smoke", "sha256", "synthesis"):
        campaign.evidence.command(
            ["python3", "tests/portable_child.py", component], cwd=tree)
    return {"source_tree": str(tree.relative_to(ROOT)),
            "components": ["compact real Icarus smoke", "freshly compiled C SHA-256",
                           "memory-preserving representative Yosys synthesis"]}
