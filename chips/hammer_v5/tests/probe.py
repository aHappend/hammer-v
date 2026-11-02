#!/usr/bin/env python3
"""Bounded independent advisory probes; these do not replace admitted suites."""
import argparse
import json
from pathlib import Path
import random
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence import Evidence, ROOT, digest
from reference import bf16_dot, int8_dot, rms, self_check


LEAF_TB = r"""
module probe_tb;
reg clk=0;
always #5 clk=~clk;
reg rst_n;
reg req_valid=0, rsp_ready=0;
reg [63:0] req_a=0, req_b=0, req_seed=0;
reg req_square=0;
wire iready, ivalid, bready, bvalid;
wire [63:0] idata, bdata;
reg use_bf=0;
hammer_v5_int8 i8 (.clk(clk),.rst_n(rst_n),
 .req_valid(req_valid && !use_bf),.req_ready(iready),
 .req_a(req_a),.req_b(req_b),.req_seed(req_seed),.req_square(req_square),
 .rsp_valid(ivalid),.rsp_ready(rsp_ready),.rsp_data(idata));
hammer_v5_bf16 bf (.clk(clk),.rst_n(rst_n),
 .req_valid(req_valid && use_bf),.req_ready(bready),
 .req_a(req_a),.req_b(req_b),.rsp_valid(bvalid),.rsp_ready(rsp_ready),.rsp_data(bdata));
wire ready=use_bf ? bready : iready;
wire valid=use_bf ? bvalid : ivalid;
wire [63:0] data=use_bf ? bdata : idata;
integer file, count=0, status, op, latency, age, stall, j;
reg [63:0] expected;
reg [1023:0] case_path;
task reset_check;
begin
 if ({iready,ivalid,bready,bvalid,idata,bdata} !== 132'b0)
   $fatal(1,"RESET output leakage");
end
endtask
always @(posedge clk or negedge clk) if (!rst_n) reset_check();
initial begin
 rst_n=0;
 #0; reset_check();
 #21; rst_n=1;
 if (!$value$plusargs("cases=%s",case_path)) case_path="cases.txt";
 file=$fopen(case_path,"r");
 if (!file) $fatal(1,"missing cases");
 while (!$feof(file)) begin
   status=$fscanf(file,"%d %h %h %h %h %d\n",op,req_a,req_b,req_seed,expected,stall);
   if (status != 6) $fatal(1,"invalid case record");
   @(negedge clk);
   use_bf=(op==2); req_square=(op==1);
   #1;
   if (ready !== 1'b1) $fatal(1,"idle not ready case %0d",count);
   req_valid=1;
   @(posedge clk);
   if (valid !== 1'b0) $fatal(1,"response at accepting edge");
   #1;
   req_valid=0;
   if (ready !== 1'b0 || valid !== 1'b0) $fatal(1,"accept boundary");
   latency=use_bf ? 12 : 6;
   for (age=1;age<=latency;age=age+1) begin
     @(posedge clk);
     if (valid !== 1'b0) $fatal(1,"early response case %0d E%0d",count,age);
     #1;
     if (valid !== (age==latency)) $fatal(1,"latency case %0d E%0d",count,age);
     if (age<latency && data !== 64'b0) $fatal(1,"inactive payload");
   end
   if (data !== expected)
     $fatal(1,"NUMERICAL case=%0d op=%0d a=%h b=%h seed=%h expected=%h observed=%h",
       count,op,req_a,req_b,req_seed,expected,data);
   for (j=0;j<stall;j=j+1) begin
     @(posedge clk); #1;
     if (valid !== 1'b1 || data !== expected || ready !== 1'b0)
       $fatal(1,"STABILITY case %0d",count);
   end
   @(negedge clk); rsp_ready=1;
   @(posedge clk);
   if (valid !== 1'b1 || data !== expected) $fatal(1,"missing response transfer");
   #1; rsp_ready=0;
   if (valid !== 1'b0 || ready !== 1'b1 || data !== 64'b0)
     $fatal(1,"response duplicated");
   count=count+1;
 end
 $fclose(file);
 if (count==0) $fatal(1,"empty comparison");
 $display("SUMMARY compared=%0d",count);
 $finish;
end
initial begin
 #5000000; $fatal(1,"CYCLE LIMIT 500000");
end
endmodule
"""


def numerical(ev):
    self_check()
    cases = []
    endpoints = (0, (1 << 64) - 1, 0x8080808080808080,
                 0x7F7F7F7F7F7F7F7F, 0x0102030405060708)
    for a in endpoints:
        for b in endpoints:
            cases.append((0, a, b, 0, int8_dot(a, b), 3))
            cases.append((1, a, b, (1 << 64) - 1, rms(a, (1 << 64) - 1), 2))
    bfvalues = (0, 0x8000, 1, 0x007F, 0x0080, 0x3F80, 0xBF80, 0x7F7F,
                0xFF7F, 0x7F80, 0xFF80, 0x7FC1, 0x7F81, 0x3F81, 0x0081)
    for a in bfvalues:
        for b in bfvalues:
            pa, pb = a * 0x0001000100010001, b * 0x0001000100010001
            cases.append((2, pa, pb, 0, bf16_dot(pa, pb), 2))
    for seed in (17, 43, 89):
        rng = random.Random(seed)
        for _ in range(1000):
            a, b, s = (rng.getrandbits(64) for _ in range(3))
            cases.append((0, a, b, s, int8_dot(a, b), rng.randrange(5)))
            cases.append((1, a, b, s, rms(a, s), rng.randrange(5)))
            cases.append((2, a, b, s, bf16_dot(a, b), rng.randrange(5)))
    (ev.directory / "cases.txt").write_text(
        "".join(f"{op} {a:016x} {b:016x} {s:016x} {result:016x} {stall}\n"
                for op, a, b, s, result, stall in cases))
    testbench = ev.directory / "probe_tb.sv"
    testbench.write_text(LEAF_TB)
    all_cases = (ev.directory / "cases.txt").read_text()
    (ev.directory / "smoke.txt").write_text(
        "".join(all_cases.splitlines(keepends=True)[:275]))
    ev.record["generated_sha256"] = {
        ev.relative(path): digest(path)
        for path in (testbench, ev.directory / "cases.txt", ev.directory / "smoke.txt")
    }
    ev.record["scope"] = {
        "public_pin_leaf_only": True, "seeds": [17, 43, 89],
        "per_seed": {"int8": 1000, "rms": 1000, "bf16": 1000},
        "comparisons": len(cases), "cycle_limit": 500000,
        "not_covered": ["integrated architectural execution", "cache", "Linux",
                        "full required defect matrix", "synthesis", "hardware"],
    }
    sources = [ROOT / "rtl" / name for name in (
        "hammer_v5_int8.sv", "hammer_v5_bf16.sv", "hammer_v5_bf16_mul.sv",
        "hammer_v5_fp32_add.sv", "hammer_v5_fp32_round.sv")]
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.version("make")
    ev.version("g++")
    # Interpreted execution is compact startup/endpoints only.
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "probe_tb",
            "-o", ev.relative(ev.directory / "smoke.vvp"),
            ev.relative(testbench), *map(ev.relative, sources)], "iverilog-compile")
    ev.run(["vvp", "./smoke.vvp", "+cases=smoke.txt"],
           "icarus-smoke", cwd=ev.directory)
    ev.run(["verilator", "--binary", "--timing", "--top-module", "probe_tb",
            "-Wno-fatal", "--Mdir", ev.relative(ev.directory / "compile-obj"),
            "-o", "probe-sim", ev.relative(testbench), *map(ev.relative, sources)],
           "verilator-compile")
    result = ev.run(["./compile-obj/probe-sim"], "verilator-numerical", cwd=ev.directory)
    if f"SUMMARY compared={len(cases)}" not in result:
        raise AssertionError("compiled simulation did not compare all generated cases")
    ev.record["observed"] = {"numerical_comparisons": len(cases),
                             "icarus_comparisons": 275}
    # Only build intermediates from this probe's exact output directory are removed.
    import shutil
    shutil.rmtree(ev.directory / "compile-obj")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", choices=("numerical", "software"), required=True)
    parser.add_argument("--repair-of")
    args = parser.parse_args()
    selectors = ["rtl/*.sv", "tests/*.py", "software/*", "design/*.md"]
    ev = Evidence(f"v5-{args.probe}", selectors, args.repair_of)
    ev.record["argv"] = ["python3", "tests/probe.py", *sys.argv[1:]]
    ev.version("python3")
    try:
        if args.probe == "numerical":
            numerical(ev)
        else:
            ev.run(["python3", "software/build.py", "--output",
                    ev.relative(ev.directory / ("boot-build-" + ev.directory.name.rsplit("-", 1)[1])),
                    "--jobs", "2"], "offline-software", timeout_s=86400)
        print(json.dumps({"exit": 0, "receipt": ev.finish(0)}))
        return 0
    except (OSError, RuntimeError, AssertionError, ValueError) as error:
        print(json.dumps({"exit": 1, "error": str(error), "receipt": ev.finish(1, error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
