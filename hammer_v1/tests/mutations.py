"""Disposable RTL defects must elaborate and fail executed semantic comparisons."""

import hashlib
import json

from cycle import ComparisonFailure
from encoding import ECALL, branch, i, load, lui, r, store
from iss import DATA
from retention import ROOT, fresh


def run_mutations(campaign, names=None):
    basic = [i("ADDI", 1, 0, 7), i("ADDI", 2, 0, 3), r("ADD", 3, 1, 2), ECALL]
    sign = [lui(20, DATA >> 12), load("LW", 1, 20, 4), ECALL]
    priority = [i("ADDI", 1, 0, 1), i("ADDI", 1, 0, 2), r("ADD", 2, 1, 1), ECALL]
    interlock = [lui(20, DATA >> 12), load("LD", 1, 20), r("ADD", 2, 1, 1), ECALL]
    kill = [lui(20, DATA >> 12), branch("BEQ", 0, 0, 8), store("SD", 0, 20), ECALL]
    zero = [i("ADDI", 1, 0, 17), r("DIVU", 2, 1, 0), ECALL]
    mutants = (
        ("add", "hammer_v1_alu.sv", "0: full_result = a + b;",
         "0: full_result = a + b + 64'd1;", basic),
        ("lw-sign", "hammer_v1_core.sv",
         "2: extend_load = {{32{shifted[31]}}, shifted[31:0]};",
         "2: extend_load = {32'b0, shifted[31:0]};", sign),
        ("forward-priority", "hammer_v1_hazard.sv",
         "mem_we && mem_ready_result && mem_rd != 0 &&",
         "mem_we && mem_ready_result && mem_rd != 0 && !(wb_we && wb_rd == mem_rd) &&", priority),
        ("load-interlock", "hammer_v1_hazard.sv",
         "assign interlock = ex_load &&", "assign interlock = 1'b0 && ex_load &&", interlock),
        ("wrong-path-kill", "hammer_v1_core.sv",
         "!interlock && !older_fault && !redirect &&", "!interlock && !older_fault &&", kill),
        ("divide-zero", "hammer_v1_muldiv.sv",
         "wire [63:0] signed_q = zero_divisor ? 64'hffffffffffffffff :",
         "wire [63:0] signed_q = zero_divisor ? 64'b0 :", zero),
    )
    selected = {entry[0] for entry in mutants} if names is None else set(names)
    if not selected or selected - {entry[0] for entry in mutants}:
        raise ValueError(f"unknown or empty mutation selection: {names}")
    results = []
    for name, filename, before, after, code in mutants:
        if name not in selected:
            continue
        # A passing original counterpart is essential; compile/timeout/parser failures
        # are not recognized as semantic defect detections.
        original = type(campaign)(campaign.evidence)
        original.run("original-" + name, code, (32, 3, 1, 4))
        directory = fresh(campaign.evidence.directory, "mutant-" + name)
        bindings = {}
        files = []
        found = False
        for source in sorted(ROOT.glob("rtl/*.sv")):
            target = directory / source.name
            text = source.read_text()
            if source.name == filename:
                occurrences = text.count(before)
                expected_occurrences = 2 if name == "forward-priority" else 1
                if occurrences != expected_occurrences:
                    raise ComparisonFailure(f"mutation rule {name}: {occurrences} != {expected_occurrences} matches")
                text = text.replace(before, after)
                found = True
            target.write_text(text)
            files.append(str(target.relative_to(ROOT)))
            bindings[str(target.relative_to(ROOT))] = hashlib.sha256(target.read_bytes()).hexdigest()
        if not found:
            raise ComparisonFailure(f"missing mutation target {filename}")
        (directory / "mutation.json").write_text(json.dumps({
            "name": name, "file": filename, "before": before, "after": after,
            "source_sha256": bindings}, indent=2) + "\n")
        mutant = type(campaign)(campaign.evidence)
        mutant.build((32, 3, 1, 4), rtl=files)
        try:
            mutant.run("execute-" + name, code, (32, 3, 1, 4), rtl=files)
        except ComparisonFailure as mismatch:
            results.append({"name": name, "elaborated": True, "detected": True,
                            "comparison_failure": str(mismatch),
                            "mutation": str((directory / "mutation.json").relative_to(ROOT)),
                            "execution_receipt": campaign.evidence.commands[-1]})
        else:
            raise ComparisonFailure(f"UNDETECTED_MUTANT: {name}")
    if len(results) != len(selected):
        raise ComparisonFailure(f"{len(selected)} distinct semantic defect detections required")
    return results
