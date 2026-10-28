#!/usr/bin/env python3
"""Retain the outer command even if an advisory runner has an import/syntax error."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
from retention import Evidence, ToolFailure


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repair-of")
    args, _ = parser.parse_known_args()
    evidence = Evidence("outer-probe", preparation=True)
    argv = ["python3", "tests/verify.py", "--suite", "smoke", "--prepare", *sys.argv[1:]]
    try:
        evidence.command(argv, timeout=2700)
    except ToolFailure as error:
        print(evidence.finish("failed", error=str(error), repair_of=args.repair_of))
        return 1
    print(evidence.finish("passed", repair_of=args.repair_of))
    return 0


if __name__ == "__main__":
    sys.exit(main())
