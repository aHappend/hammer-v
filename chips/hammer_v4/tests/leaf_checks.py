#!/usr/bin/env python3
"""Compare public Sv39 leaf ports to independent privileged ISA rules."""

import argparse
import itertools
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from architecture import PageFault, leaf


LEAF_TB = r"""`timescale 1ns/1ps
module tb;
  reg [63:0] va;
  reg [43:0] ppn;
  reg [1:0] level, access_kind, priv;
  reg [7:0] flags;
  reg sum, mxr;
  wire [55:0] pa;
  wire fault;
  reg expected_fault;
  reg [55:0] expected_pa;
  integer file_handle, fields, count;
  string vector_file;
  hammer_v3_page_leaf dut(.*);
  initial begin
    if (!$value$plusargs("vectors=%s", vector_file)) $fatal(1,"vectors missing");
    file_handle = $fopen(vector_file, "r");
    if (!file_handle) $fatal(1,"cannot open vectors");
    count = 0;
    while (!$feof(file_handle)) begin
      fields = $fscanf(file_handle, "%h %h %d %h %d %d %d %d %d %h\n",
                       va, ppn, level, flags, access_kind, priv, sum, mxr,
                       expected_fault, expected_pa);
      if (fields == 10) begin
        #1;
        if (fault !== expected_fault || (!expected_fault && pa !== expected_pa))
          $fatal(1,"Sv39 vector=%0d va=%h ppn=%h level=%d flags=%h access=%d priv=%d sum=%d mxr=%d fault=%b expected=%b pa=%h expected_pa=%h",
                 count, va, ppn, level, flags, access_kind, priv, sum, mxr,
                 fault, expected_fault, pa, expected_pa);
        count = count + 1;
      end else if (!(fields == 0 && $feof(file_handle)))
        $fatal(1,"malformed non-EOF vector fields=%0d", fields);
    end
    if (count == 0) $fatal(1,"empty comparison");
    $display("COMPARED Sv39 leaves=%0d", count);
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
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    good = bad = 0
    count = 0
    with (out / "leaf.vectors").open("w") as stream:
        cases = itertools.chain(
            ((0x12345000, 0x80000, level, flags, access, priv, sum_bit, mxr)
             for level, flags, access, priv, sum_bit, mxr in itertools.product(
                 range(3), range(256), range(4), (0, 1), (0, 1), (0, 1))),
            ((va, ppn, level, 0xdf, access, priv, sum_bit, mxr)
             for va, ppn, level, access, priv, sum_bit, mxr in itertools.product(
                 (0, (1 << 38) - 1, 1 << 38, (1 << 64) - (1 << 38),
                  (1 << 64) - 1, 0x8000000000000000),
                 (0, 1, 511, 512, 0x40000, (1 << 44) - 1),
                 range(4), range(4), (0, 1), (0, 1), (0, 1))),
        )
        for va, ppn, level, flags, access, priv, sum_bit, mxr in cases:
            try:
                physical = leaf(
                    va, ppn, level, flags, ("fetch", "load", "store", "atomic")[access],
                    priv, bool(sum_bit), bool(mxr)
                ).physical
                fault = 0
                good += 1
            except PageFault:
                physical, fault = 0, 1
                bad += 1
            count += 1
            stream.write(
                f"{va:x} {ppn:x} {level} {flags:x} {access} {priv} "
                f"{sum_bit} {mxr} {fault} {physical:x}\n"
            )
    if not good or not bad or count > 500000:
        raise AssertionError("Insufficient positive/negative coverage or excessive compact vectors")
    (out / "leaf_tb.sv").write_text(LEAF_TB)
    commands = [
        ["iverilog", "-g2012", "-Wall", "-s", "tb", "-o", str(out / "leaf.vvp"),
         "rtl/hammer_v3_page_leaf.sv", str(out / "leaf_tb.sv")],
        ["vvp", str(out / "leaf.vvp"), f"+vectors={out / 'leaf.vectors'}"],
    ]
    for index, argv in enumerate(commands):
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
        (out / f"{index}.stdout.log").write_bytes(result.stdout)
        (out / f"{index}.stderr.log").write_bytes(result.stderr)
        if result.returncode or (index == 1 and b"COMPARED Sv39 leaves=" not in result.stdout):
            raise AssertionError(f"Sv39 leaf comparison failed; see {args.out}")
    summary = {"commands": commands, "comparisons": count,
               "permitted_translations": good, "expected_page_faults": bad}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
