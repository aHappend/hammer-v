#!/usr/bin/env python3
"""Clock-exact public CLINT/CSR checks, independent of instruction scheduling."""

import argparse
import json
from pathlib import Path
import random
import subprocess


ROOT = Path(__file__).resolve().parent.parent
MASK = (1 << 64) - 1


def vectors():
    time, compare, software = 0, MASK, 0
    response, error, data = 0, 0, 0
    result = []
    rng = random.Random(0x48414D4D455234)

    def edge(reset=1, valid=0, write=0, size=3, address=0x200BFF8,
             value=0, strobes=255, ready=1):
        nonlocal time, compare, software, response, error, data
        if not reset:
            time, compare, software = 0, MASK, 0
            response, error, data = 0, 0, 0
        pre = (int(reset and not response), int(reset and response),
               data if reset and response else 0,
               int(reset and response and error), time, software,
               int(reset and time >= compare))
        accepted = valid and pre[0]
        if reset:
            old_time = time
            time = (time + 1) & MASK
            if response and ready:
                response = 0
            if accepted:
                base = address & ~7
                width = 1 << size
                extent = 4 if base == 0x2000000 else 8
                legal = base in (0x2000000, 0x2004000, 0x200BFF8) and \
                    address % width == 0 and address % 8 + width <= extent
                snapshot = {0x2000000: software, 0x2004000: compare,
                            0x200BFF8: old_time}.get(base, 0)
                response, error, data = 1, int(not legal), snapshot if legal else 0
                if legal and write:
                    byte_mask = sum(255 << (lane * 8) for lane in range(8)
                                    if strobes >> lane & 1)
                    merged = (snapshot & ~byte_mask) | (value & byte_mask)
                    if base == 0x2000000 and strobes & 1:
                        software = value & 1
                    elif base == 0x2004000:
                        compare = merged
                    elif base == 0x200BFF8 and strobes:
                        time = merged
        post = (int(reset and not response), int(reset and response),
                data if reset and response else 0,
                int(reset and response and error), time, software,
                int(reset and time >= compare))
        result.append((reset, valid, write, size, address, value, strobes, ready,
                       *pre, *post))

    def transaction(write, address, value=0, strobes=255, size=3, stall=0):
        if response:
            edge()
        edge(valid=1, write=write, address=address, value=value,
             strobes=strobes, size=size, ready=0)
        for _ in range(stall):
            edge(ready=0)
        edge()

    edge(reset=0)
    edge(reset=0)
    edge()
    transaction(1, 0x2004000, 20, stall=5)
    for _ in range(24):
        edge()
    transaction(0, 0x200BFF8, stall=7)
    transaction(1, 0x2004000, MASK)
    transaction(1, 0x200BFF8, MASK - 2)
    for _ in range(8):
        edge()
    transaction(1, 0x2000000, 1, size=2)
    transaction(0, 0x2000000, size=2)
    transaction(1, 0x2000000, 0, strobes=0, size=2)
    transaction(0, 0x2000000, size=2)
    for lane in range(8):
        transaction(1, 0x2004000 + lane, (0x80 + lane) << (lane * 8),
                    strobes=1 << lane, size=0)
        transaction(0, 0x2004000, stall=2)
    for address, size in ((0x2000000, 3), (0x2000004, 2),
                          (0x2004001, 3), (0x200BFFF, 1), (0x2001000, 3)):
        transaction(1, address, 0xDEADBEEF, size=size)
    for _ in range(512):
        transaction(rng.randrange(2), rng.choice((0x2000000, 0x2004000, 0x200BFF8)),
                    rng.getrandbits(64), strobes=rng.randrange(256),
                    size=rng.randrange(4), stall=rng.randrange(4))
    # Reset with a response held, then demonstrate absence of the stale reply.
    transaction(1, 0x2004000, 0)
    edge(valid=1, ready=0)
    edge(reset=0, ready=0)
    edge()
    edge(valid=1)
    edge()
    return result


TB = r"""`timescale 1ns/1ps
module tb;
  reg clk=0, rst_n, req_valid, req_write, rsp_ready;
  reg [1:0] req_size;
  reg [63:0] req_addr,req_wdata;
  reg [7:0] req_wstrb;
  wire req_ready,rsp_valid,rsp_error,irq_msip,irq_mtip;
  wire [63:0] rsp_rdata,mtime,csr_rdata;
  wire csr_illegal;
  hammer_v2_clint timer(.*);
  hammer_v3_csr csr(
    .clk(clk),.rst_n(rst_n),.csr_valid(1'b1),.csr_commit(1'b0),
    .csr_addr(12'hc01),.csr_op(3'd2),.csr_src(64'b0),
    .csr_read(1'b1),.csr_write(1'b0),.csr_rdata(csr_rdata),
    .csr_illegal(csr_illegal),.retire(1'b0),.mtime(mtime),
    .irq_msip(irq_msip),.irq_mtip(irq_mtip),.irq_meip(1'b0),.irq_seip(1'b0),
    .return_kind(2'b0),.return_commit(1'b0),.trap_enter(1'b0),
    .trap_target(2'b0),.trap_epc(64'b0),.trap_cause(64'b0),.trap_tval(64'b0)
  );
  always #5 clk=~clk;
  integer file_handle,fields,count;
  string vector_file;
  reg [63:0] pre[0:6],post[0:6];
  task automatic compare(input bit after_edge);
    reg [63:0] e[0:6];
    integer n;
    begin
      for(n=0;n<7;n=n+1) e[n]=after_edge ? post[n] : pre[n];
      if(req_ready !== e[0][0] || rsp_valid !== e[1][0] ||
         rsp_rdata !== e[2] || rsp_error !== e[3][0] || mtime !== e[4] ||
         irq_msip !== e[5][0] || irq_mtip !== e[6][0])
        $fatal(1,"TIMER_COMPARISON vector=%0d post=%b time=%h expected=%h mtip=%b expected=%b",
               count,after_edge,mtime,e[4],irq_mtip,e[6][0]);
      if(csr_illegal !== 0 || csr_rdata !== e[4])
        $fatal(1,"CSR_TIME_COMPARISON vector=%0d post=%b time=%h expected=%h",
               count,after_edge,csr_rdata,e[4]);
    end
  endtask
  initial begin
    rst_n=0;req_valid=0;req_write=0;req_size=0;
    req_addr=0;req_wdata=0;req_wstrb=0;rsp_ready=0;count=0;
    #1;
    if(req_ready !== 0 || rsp_valid !== 0 || mtime !== 0 ||
       irq_msip !== 0 || irq_mtip !== 0 || csr_rdata !== 0)
      $fatal(1,"Time-zero timer reset");
    @(posedge clk);
    if(req_ready !== 0 || rsp_valid !== 0 || mtime !== 0 || csr_rdata !== 0)
      $fatal(1,"Active-region first-edge timer reset");
    if(!$value$plusargs("vectors=%s",vector_file)) $fatal(1,"missing vectors");
    file_handle=$fopen(vector_file,"r");
    if(!file_handle) $fatal(1,"cannot open vectors");
    while(!$feof(file_handle)) begin
      @(negedge clk);
      fields=$fscanf(file_handle,
        "%h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h %h\n",
        rst_n,req_valid,req_write,req_size,req_addr,req_wdata,req_wstrb,rsp_ready,
        pre[0],pre[1],pre[2],pre[3],pre[4],pre[5],pre[6],
        post[0],post[1],post[2],post[3],post[4],post[5],post[6]);
      if(fields==22) begin
        #1; compare(0);
        @(posedge clk); compare(0);
        #1; compare(1);
        count=count+1;
      end else if(!(fields==0 && $feof(file_handle)))
        $fatal(1,"Malformed non-EOF timer vector");
    end
    if(count<1000) $fatal(1,"Insufficient timer comparisons");
    $display("COMPARED clock-exact CLINT/CSR cycles=%0d observations=%0d",count,count*3);
    $finish;
  end
endmodule
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    parser.add_argument("--rtl", default="rtl")
    parser.add_argument("--simulator", choices=("iverilog", "verilator", "both"),
                        default="both")
    args = parser.parse_args()
    relative = Path(args.out)
    rtl = Path(args.rtl)
    for name, path in (("--out", relative), ("--rtl", rtl)):
        if path.is_absolute() or ".." in path.parts or (
            path != Path("rtl") and path.parts[:1] != ("build",)
        ):
            parser.error(f"{name} must be a project-relative build/ path or rtl")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    cases = vectors()
    (out / "timer.vectors").write_text(
        "".join(" ".join(f"{value:x}" for value in case) + "\n" for case in cases)
    )
    (out / "tb.sv").write_text(TB)
    sources = [str(rtl / name) for name in ("hammer_v2_clint.sv", "hammer_v3_csr.sv")]
    commands = []
    if args.simulator in ("iverilog", "both"):
        commands.extend([
            ["iverilog", "-g2012", "-Wall", "-s", "tb", "-o",
             str(out / "sim.vvp"), *sources, str(out / "tb.sv")],
            ["vvp", str(out / "sim.vvp"), f"+vectors={out / 'timer.vectors'}"],
        ])
    if args.simulator in ("verilator", "both"):
        commands.extend([
            ["verilator", "--binary", "--timing", "--build", "-j", "4", "-Wno-fatal",
             "--top-module", "tb", "--Mdir", str(out / "compile-obj"),
             *sources, str(out / "tb.sv")],
            [str(out / "compile-obj/Vtb"), f"+vectors={out / 'timer.vectors'}"],
        ])
    records = []
    try:
        for index, argv in enumerate(commands):
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
            (out / f"{index}.stdout.log").write_bytes(result.stdout)
            (out / f"{index}.stderr.log").write_bytes(result.stderr)
            records.append({"argv": argv, "exit_code": result.returncode})
            (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
            if result.returncode:
                raise AssertionError(f"Timer/CSR check failed: {relative}, command {index}")
            if index % 2:
                if b"COMPARED clock-exact CLINT/CSR cycles=" not in result.stdout:
                    raise AssertionError("Missing timer functional comparisons")
                print(result.stdout.decode(), end="")
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in (out / "compile-obj").glob(pattern):
                path.unlink()
    (out / "summary.json").write_text(json.dumps({
        "cycles": len(cases), "observations_per_simulator": len(cases) * 3,
        "simulator": args.simulator, "scope": "public CLINT and CSR, not core scheduling",
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
