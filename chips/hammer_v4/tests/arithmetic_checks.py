#!/usr/bin/env python3
"""Compact sequential M-unit black-box numerical and completion checks."""

import argparse
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from architecture import muldiv


TB = r"""`timescale 1ns/1ps
module tb;
  reg clk = 0;
  reg rst_n, start, word_op, consume;
  reg [2:0] op;
  reg [63:0] a, b;
  wire busy, done;
  wire [63:0] result;
  reg [63:0] expected;
  integer file_handle, fields, count, cycles, n;
  reg [1023:0] vector_file;
  hammer_v2_muldiv dut(.*);
  always #5 clk = ~clk;
  always @(posedge clk) begin
    cycles = cycles + 1;
    if (cycles > 500000) $fatal(1,"compact arithmetic cycle bound");
    if (!rst_n && (busy !== 0 || done !== 0 || result !== 0))
      $fatal(1,"arithmetic active-region reset");
  end
  always @(negedge clk)
    if (!rst_n && (busy !== 0 || done !== 0 || result !== 0))
      $fatal(1,"arithmetic falling-edge reset");
  initial begin
    rst_n = 0; start = 0; word_op = 0; consume = 0; op = 0; a = 0; b = 0;
    cycles = 0; count = 0;
    #1;
    if (busy !== 0 || done !== 0 || result !== 0) $fatal(1,"arithmetic time-zero reset");
    repeat (3) @(negedge clk);
    rst_n = 1;
    if (!$value$plusargs("vectors=%s", vector_file)) $fatal(1,"missing vectors");
    file_handle = $fopen(vector_file,"r");
    if (!file_handle) $fatal(1,"cannot open vectors");
    while (!$feof(file_handle)) begin
      fields = $fscanf(file_handle,"%d %d %h %h %h\n",op,word_op,a,b,expected);
      if (fields == 5) begin
        @(negedge clk); start = 1;
        @(posedge clk); #1;
        if (busy !== 1 || done !== 0) $fatal(1,"M-unit accept status");
        @(negedge clk); start = 0;
        for (n = 0; n < 64; n = n + 1) begin
          @(posedge clk); #1;
          if (busy !== 1 || done !== 0) $fatal(1,"premature M-unit completion");
        end
        @(posedge clk); #1;
        if (busy !== 0 || done !== 1 || result !== expected)
          $fatal(1,"M-unit vector=%0d op=%d word=%d a=%h b=%h result=%h expected=%h",
                 count,op,word_op,a,b,result,expected);
        repeat (3) begin
          @(posedge clk); #1;
          if (done !== 1 || result !== expected || busy !== 0)
            $fatal(1,"M-unit result unstable before consume");
        end
        @(negedge clk); consume = 1;
        @(posedge clk); #1;
        if (done !== 0) $fatal(1,"M-unit consume");
        @(negedge clk); consume = 0;
        count = count + 1;
      end else if (!(fields == 0 && $feof(file_handle)))
        $fatal(1,"malformed non-EOF M-unit vector");
    end
    if (count < 100) $fatal(1,"insufficient M-unit comparisons");
    $display("COMPARED M-unit=%0d cycles=%0d",count,cycles);
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
    operations = ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu")
    boundaries = (0, 1, 2, (1 << 64) - 1, 1 << 63, (1 << 63) - 1,
                  1 << 31, (1 << 31) - 1, (1 << 32) - 1)
    rng = random.Random(0x48414D4D455234)
    count = 0
    with (out / "arithmetic.vectors").open("w") as stream:
        for word in (False, True):
            for operation, name in enumerate(operations):
                if word and operation in (1, 2, 3):
                    continue
                pairs = itertools.chain(
                    itertools.product(boundaries, repeat=2),
                    ((rng.getrandbits(64), rng.getrandbits(64)) for _ in range(32)),
                )
                for lhs, rhs in pairs:
                    answer = muldiv(name, lhs, rhs, word)
                    stream.write(f"{operation} {int(word)} {lhs:x} {rhs:x} {answer:x}\n")
                    count += 1
    (out / "tb.sv").write_text(TB)
    commands = [
        ["iverilog", "-g2012", "-Wall", "-s", "tb", "-o", str(out / "sim.vvp"),
         "rtl/hammer_v2_muldiv.sv", str(out / "tb.sv")],
        ["vvp", str(out / "sim.vvp"), f"+vectors={out / 'arithmetic.vectors'}"],
    ]
    for index, argv in enumerate(commands):
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
        (out / f"{index}.stdout.log").write_bytes(result.stdout)
        (out / f"{index}.stderr.log").write_bytes(result.stderr)
        if result.returncode or (index == 1 and b"COMPARED M-unit=" not in result.stdout):
            raise AssertionError(f"M-unit comparison failed; see {args.out}")
    summary = {"commands": commands, "comparisons": count,
               "operations": operations, "excludes_illegal_high_product_word_ops": True}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
