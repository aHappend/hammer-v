#!/usr/bin/env python3
"""Functional sensitivity of compact public-pin checks on disposable RTL copies.

The delayed-pending leaf check and full-core quiescent-WFI boundary check have
separate controls. Neither establishes the complete Linux timed oracle.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
MUTATIONS = {
    "dtb-handoff": (
        "hammer_v4_boot_rom.sv", "32'h043f05b7", "32'h043e05b7",
        "UART_COMPARISON", "firmware",
    ),
    "sv39-user-permission": (
        "hammer_v3_page_leaf.sv",
        "if (priv == 0 && !flags[4]) fault = 1'b1;",
        "if (1'b0) fault = 1'b1;",
        "SV39_PERMISSION_COMPARISON", "firmware",
    ),
    "sbi-timer-clear": (
        "hammer_v3_csr.sv", "stip_q <= changed[5];",
        "stip_q <= changed[5] | changed[7];",
        "TIMER_COMPARISON", "firmware",
    ),
    "uart-data": (
        "hammer_v3_uart.sv", "tx_fifo[tx_tail] <= write_byte;",
        "tx_fifo[tx_tail] <= write_byte ^ 8'h01;",
        "UART_COMPARISON", "firmware",
    ),
    "time-csr-plus-one": (
        "hammer_v3_csr.sv", "12'hc01: raw_read = mtime;",
        "12'hc01: raw_read = mtime + 64'd1;",
        "TIME_CSR_COMPARISON", "firmware",
    ),
    "timer-pending-delayed-leaf": (
        "hammer_v2_clint.sv",
        "assign irq_mtip = rst_n && time_q >= cmp_q;",
        "reg delayed_timer;\n"
        "    always @(posedge clk or negedge rst_n) begin\n"
        "        if (!rst_n) delayed_timer <= 1'b0;\n"
        "        else delayed_timer <= time_q >= cmp_q;\n"
        "    end\n"
        "    assign irq_mtip = rst_n && delayed_timer;",
        "TIMER_COMPARISON", "timer",
    ),
    "timer-pending-delayed-boundary": (
        "hammer_v2_clint.sv",
        "assign irq_mtip = rst_n && time_q >= cmp_q;",
        "reg delayed_timer;\n"
        "    always @(posedge clk or negedge rst_n) begin\n"
        "        if (!rst_n) delayed_timer <= 1'b0;\n"
        "        else delayed_timer <= time_q >= cmp_q;\n"
        "    end\n"
        "    assign irq_mtip = rst_n && delayed_timer;",
        "TIMER_BOUNDARY_COMPARISON", "temporal",
    ),
    "coherent-invalidation": (
        "hammer_v3_top.sv", ".req_ready(da_ready), .req_cmd({2'b11,2'b0,route_cmd}),",
        ".req_ready(da_ready), .req_cmd({2'b10,2'b0,route_cmd}),",
        "COHERENCE_COMPARISON", "compatibility",
    ),
    "mmu-mprv-bypass": (
        "hammer_v3_mmu.sv", "priv == 3 && mstatus[17] ? mstatus[12:11] : priv;",
        "1'b0 ? mstatus[12:11] : priv;",
        "MMU_TRANSLATION_COMPARISON", "mmu",
    ),
    "mmu-asid-fence-global": (
        "hammer_v3_tlb.sv", "(!flags[n][5] && asid[n] == invalidate_asid)))",
        "(asid[n] == invalidate_asid)))",
        "MMU_PTE_ADDRESS_COMPARISON", "mmu",
    ),
    "mmu-reserved-pte": (
        "hammer_v3_ptw.sv", "|pte_q[63:54];", "1'b0;",
        "MMU_PTE_ADDRESS_COMPARISON", "mmu",
    ),
}


def hashes(directory):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.glob("*.sv"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--case", action="append", choices=sorted(MUTATIONS),
                        help="diagnostic subset; the mandatory default executes every mutant")
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    original = hashes(ROOT / "rtl")
    selected = {name: MUTATIONS[name] for name in args.case} if args.case else MUTATIONS
    records = []

    def run(name, scope, rtl):
        directory = out / name
        command = [
            sys.executable, f"tests/{scope}_checks.py",
            "--out", (relative / name / "execution").as_posix(), "--rtl", rtl,
        ]
        if scope in ("firmware", "temporal"):
            command.extend(["--manifest", args.manifest])
        elif scope in ("timer", "mmu"):
            command.extend(["--simulator", "verilator"])
        elif scope == "compatibility":
            command.append("--v4-only")
        directory.mkdir()
        start = time.time()
        with (directory / "stdout.log").open("wb") as so, (
            directory / "stderr.log"
        ).open("wb") as se:
            result = subprocess.run(command, cwd=ROOT, stdout=so, stderr=se, check=False)
        record = {"name": name, "argv": command, "cwd": ".",
                  "started_unix": start, "ended_unix": time.time(),
                  "exit_code": result.returncode, "scope": scope}
        records.append(record)
        (out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        return record

    controls = {}
    for scope in ("firmware", "timer", "compatibility", "temporal", "mmu"):
        if scope not in {mutation[4] for mutation in selected.values()}:
            continue
        record = run(f"control-{scope}", scope, "rtl")
        if record["exit_code"]:
            raise AssertionError(f"Unchanged {scope} control failed: {relative}")
        controls[scope] = record

    for name, (filename, before, after, marker, scope) in selected.items():
        rtl = out / f"{name}-rtl"
        rtl.mkdir()
        for source in sorted((ROOT / "rtl").glob("*.sv")):
            shutil.copyfile(source, rtl / source.name)
        target = rtl / filename
        text = target.read_text()
        if text.count(before) != 1:
            raise AssertionError(f"{name}: mutation target not unique")
        target.write_text(text.replace(before, after))
        record = run(name, scope, rtl.relative_to(ROOT).as_posix())
        record["accepted_source_sha256"] = original
        record["mutated_source_sha256"] = hashes(rtl)
        record["mutation"] = {"file": filename, "before": before, "after": after}
        (out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        directory = out / name / "execution"
        raw_name = {"firmware": "3", "timer": "1", "temporal": "4",
                    "compatibility": "v4/simulate", "mmu": "entries-1/1"}[scope]
        stdout = directory / f"{raw_name}.stdout.log"
        stderr = directory / f"{raw_name}.stderr.log"
        # A syntax/link failure never reaches these simulator artifacts. Require
        # the targeted functional mismatch, not nonzero exit alone.
        raw = (stdout.read_bytes() if stdout.exists() else b"") + \
            (stderr.read_bytes() if stderr.exists() else b"")
        if not record["exit_code"] or marker.encode() not in raw:
            raise AssertionError(f"{name}: not rejected by targeted functional assertion")
        record["targeted_assertion"] = marker
        record["functional_rejection"] = True
        if scope in ("firmware", "compatibility", "temporal", "mmu"):
            control_text = (out / f"control-{scope}/execution/{raw_name}.stdout.log").read_text()
            control_edge = int(re.search(r"\bedges=(\d+)", control_text).group(1))
            failure_text = raw.decode() if scope == "mmu" else stderr.read_text()
            mutant_edge = int(re.search(r"\bedge=(\d+)", failure_text).group(1))
            if mutant_edge > control_edge:
                raise AssertionError(f"{name}: failure exceeds unchanged control completion")
            record["control_completion_edge"] = control_edge
            record["mutant_failure_edge"] = mutant_edge
        (out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
        print(f"REJECTED {name}: {marker}", flush=True)
    if original != hashes(ROOT / "rtl"):
        raise AssertionError("Accepted RTL changed during disposable mutation checks")
    print(f"Compared {len(controls)} unchanged controls and {len(selected)} functional mutants")


if __name__ == "__main__":
    main()
