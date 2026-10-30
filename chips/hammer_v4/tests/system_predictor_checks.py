#!/usr/bin/env python3
"""Compact branch predicate/alias checks against public predictor pins."""

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from architecture import branch_condition
from system_core import Predictor
from system_oracle import canonical_json


BENCH = r"""
module tb;
  reg clk=0, rst_n=0, update=0, update_taken=0, update_conditional=0;
  reg [63:0] pc=0, update_pc=0, update_target=0;
  reg [31:0] insn=32'h13;
  wire [63:0] next_pc;
  hammer_v2_predictor dut(.*);
  integer fd,n,taken,conditional,count=0;
  reg [63:0] want;
  reg [1023:0] vectors;
  initial begin
    if (!$value$plusargs("vectors=%s",vectors)) $fatal(1,"missing vectors");
    fd=$fopen(vectors,"r");
    if (!fd) $fatal(1,"cannot read vectors");
    repeat(4) begin #5 clk=1; #5 clk=0; end
    rst_n=1;
    while (!$feof(fd)) begin
      n=$fscanf(fd,"%h %h %d %d %h %h\n",
                update_pc,update_target,taken,conditional,pc,want);
      if (n != 6) $fatal(1,"invalid vector");
      update=1; update_taken=1'(taken); update_conditional=1'(conditional);
      #5 clk=1; #1;
      if (next_pc !== want)
        $fatal(1,"PREDICTOR_ALIAS case=%0d pc=%h got=%h want=%h",
               count,pc,next_pc,want);
      count=count+1;
      #4 clk=0;
    end
    $display("COMPARED_PREDICTOR_ALIAS cases=%0d",count);
    $finish;
  end
endmodule
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    predicates = (
        (0, 0, 0, True), (0, 0, 1, False), (1, 0, 1, True), (1, 1, 1, False),
        (4, (1 << 64) - 1, 0, True), (4, 0, (1 << 64) - 1, False),
        (5, 0, (1 << 64) - 1, True), (5, (1 << 64) - 1, 0, False),
        (6, 0, (1 << 64) - 1, True), (6, (1 << 64) - 1, 0, False),
        (7, (1 << 64) - 1, 0, True), (7, 0, (1 << 64) - 1, False),
    )
    rows = []
    model = Predictor()
    for funct3, first, second, want in predicates:
        taken = branch_condition(funct3, first, second)
        if taken != want:
            raise AssertionError("ISA branch predicate")
        for pc, target, decision, conditional, query in (
            (0x1028, 0x1048, True, True, 0x1028),
            # Same predictor slot; taken PC+4 must evict the earlier branch.
            (0x1068, 0x106C, taken, True, 0x1028),
            (0x1068, 0x106C, taken, True, 0x1068),
        ):
            model.resolve(pc, target, decision, conditional)
            rows.append(f"{pc:x} {target:x} {int(decision)} {int(conditional)} "
                        f"{query:x} {model.predict(query):x}\n")
    (out / "vectors.txt").write_text("".join(rows))
    (out / "bridge.sv").write_text(BENCH)
    records = []
    for index, argv in enumerate((
        ["iverilog", "-g2012", "-Wall", "-s", "tb", "-o",
         (relative / "sim").as_posix(), "rtl/hammer_v2_predictor.sv",
         (relative / "bridge.sv").as_posix()],
        ["vvp", (relative / "sim").as_posix(),
         "+vectors=" + (relative / "vectors.txt").as_posix()],
    )):
        record = {"argv": argv, "cwd": ".", "exit_code": None}
        records.append(record)
        with (out / f"{index}.stdout.log").open("xb") as so, (
            out / f"{index}.stderr.log"
        ).open("xb") as se:
            record["exit_code"] = subprocess.run(
                argv, cwd=ROOT, stdout=so, stderr=se, check=False).returncode
        (out / "commands.json").write_bytes(canonical_json(records))
        if record["exit_code"]:
            raise AssertionError(f"Predictor alias comparison failed: {relative}")
    (out / "summary.json").write_bytes(canonical_json({
        "scope": "compact predicate/BTB alias check, not Linux acceptance",
        "predicate_cases": len(predicates), "compared_updates": len(rows),
        "taken_pc_plus_4_cases": sum(want for _, _, _, want in predicates),
    }))
    print(f"COMPARED_PREDICTOR predicates={len(predicates)} aliases={len(rows)}")


if __name__ == "__main__":
    main()
