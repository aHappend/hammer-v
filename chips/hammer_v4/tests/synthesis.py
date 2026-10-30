#!/usr/bin/env python3
"""Full-hierarchy Yosys structural check with memory-preserving synthesis."""

import argparse
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
REQUIRED = {
    "hammer_v4_top", "hammer_v4_boot_rom", "hammer_v3_top",
    "hammer_v3_core", "hammer_v3_mmu", "hammer_v3_accel_bridge",
    "hammer_v3_fabric", "hammer_v3_uart", "hammer_v3_plic",
    "hammer_v2_clint", "hammer_v3_icache", "hammer_v3_dcache",
    "hammer_v3_axi_master",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    sources = " ".join(
        p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "rtl").glob("*.sv"))
    )
    script = (
        f"read_verilog -sv {sources}\n"
        "hierarchy -check -top hammer_v4_top "
        "-chparam IMEM_WORDS 32 -chparam DMEM_WORDS 3\n"
        "proc\nopt_expr\nopt_clean\ncheck -noinit -assert\n"
        "memory -nomap\nopt_clean\ncheck -assert\n"
        "select -assert-none t:$dlatch t:$adlatch t:$dlatchsr t:$div t:$mod\n"
        "stat\n"
        f"write_json {relative.as_posix()}/netlist.json\n"
    )
    script_path = out / "synthesis.ys"
    script_path.write_text(script)
    argv = ["yosys", "-Q", "-T", "-s", script_path.relative_to(ROOT).as_posix()]
    with (out / "stdout.log").open("wb") as so, (out / "stderr.log").open("wb") as se:
        result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
    if result.returncode:
        raise RuntimeError(f"Yosys exited {result.returncode}; see {args.out}")
    netlist = json.loads((out / "netlist.json").read_text())
    modules = netlist["modules"]
    found = set()
    active = set()
    states = 0
    memory_bits = 0
    cell_count = 0

    def visit(name):
        nonlocal states, memory_bits, cell_count
        if name in active:
            raise AssertionError(f"Recursive hierarchy at {name}")
        active.add(name)
        module = modules[name]
        attributes = module.get("attributes", {})
        if int(attributes.get("blackbox", "0"), 2):
            raise AssertionError(f"Blackboxed design module {name}")
        original = attributes.get("hdlname", name).split()[0].lstrip("\\")
        found.add(original)
        if not module.get("ports") or not module.get("cells"):
            raise AssertionError(f"Empty hierarchy module {name}")
        for cell in module["cells"].values():
            cell_count += 1
            kind = cell["type"]
            if not cell.get("connections"):
                raise AssertionError(f"Unconnected cell {kind}")
            if kind in modules:
                visit(kind)
            elif kind.startswith(("$dlatch", "$adlatch")) or kind in {"$div", "$mod"}:
                raise AssertionError(f"Forbidden cell {kind}")
            elif "dff" in kind.lower():
                states += 1
            elif kind.startswith("$mem"):
                parameters = cell["parameters"]
                width = int(parameters.get("WIDTH", "0"), 2)
                size = int(parameters.get("SIZE", "0"), 2)
                memory_bits += width * size
                states += 1
        active.remove(name)

    visit("hammer_v4_top")
    missing = REQUIRED - found
    if missing or not states or not memory_bits:
        raise AssertionError(
            f"Missing hierarchy={sorted(missing)}, state_cells={states}, "
            f"memory_bits={memory_bits}"
        )
    summary = {
        "configuration": {"IMEM_WORDS": 32, "DMEM_WORDS": 3},
        "argv": argv, "exit_code": result.returncode,
        "reachable_modules": sorted(found), "cells": cell_count,
        "state_cells": states, "memory_bits": memory_bits,
        "latches": 0, "combinational_div_mod": 0,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
