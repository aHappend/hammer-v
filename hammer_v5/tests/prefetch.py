"""Directed demand/prefetch priority, failure, coherence and boundary checks."""
import shutil

from evidence import ROOT, digest
from memory import TB


CONTROL = r"""
integer compared=0,lookups=0,hits=0,demand_events=0,hit_events=0,age,j;
reg force_stall=0,block_after_accept=0;
always @(posedge clk) if(rst_n) begin
 if(event_l2_access === 1) demand_events=demand_events+1;
 else if(event_l2_access !== 0) $fatal(1,"prefetch active X access event");
 if(event_l2_hit === 1) hit_events=hit_events+1;
 else if(event_l2_hit !== 0) $fatal(1,"prefetch active X hit event");
end
task access(input [1:0] command,input [63:0] address,input [63:0] value,
 input [7:0] mask,input [63:0] expected,input integer error,input integer hit);
integer waited;
begin
 @(negedge clk); #1;
 req_valid=1; req_cmd=command; req_addr=address; req_wdata=value; req_wstrb=mask;
 waited=0;
 while(req_ready !== 1) begin
  @(negedge clk); waited=waited+1;
  if(waited>1000) $fatal(1,"prefetch demand not admitted");
 end
 @(posedge clk);
 if(rsp_valid !== 0) $fatal(1,"prefetch response at demand acceptance");
 #1; req_valid=0;
 if(block_after_accept) prefetch_block=1;
 force_stall=0;
 age=0;
 while(rsp_valid !== 1) begin
  @(posedge clk); #1; age=age+1;
  if(age>1000) $fatal(1,"prefetch demand response missing");
 end
 if(hit==1 && command==0 && age!=3)
  $fatal(1,"prefetched resident line not E3 hit");
 repeat(3) begin
  if(rsp_rdata !== expected || rsp_error !== (error!=0) || req_ready !== 0)
   $fatal(1,"PREFETCH MISMATCH case=%d addr=%h expected=%h/%d observed=%h/%b",
     compared,address,expected,error,rsp_rdata,rsp_error);
  @(negedge clk);
 end
 rsp_ready=1;
 @(posedge clk);
 if(rsp_valid !== 1) $fatal(1,"prefetch response transfer missing");
 #1; rsp_ready=0;
 if(rsp_valid !== 0 || rsp_error !== 0 || rsp_rdata !== 0)
  $fatal(1,"prefetch stale response");
 if(command<2 && address>=64'h80000000 && address<64'h100000000) begin
  lookups=lookups+1; hits=hits+hit;
 end
 if(demand_events!=lookups || hit_events!=hits)
  $fatal(1,"PREFETCH COUNTERS lookup=%d/%d hit=%d/%d",
    demand_events,lookups,hit_events,hits);
 compared=compared+1;
end
endtask
task wait_reads(input integer target);
integer waited;
begin
 waited=0;
 while(bus_reads<target) begin
  @(negedge clk); waited=waited+1;
  if(waited>2000) $fatal(1,"required next-line transfer not observed");
 end
 repeat(100) @(negedge clk);
 if(bus_reads!=target) $fatal(1,"unexpected/chained prefetch transfers %d/%d",bus_reads,target);
end
endtask
initial begin
 rst_n=0;
 for(k=0;k<32768;k=k+1) memory[k]=(k*37+11)&255;
 #0; reset_check(); #21; rst_n=1;
__CASES__
 $display("SUMMARY PREFETCH compared=%0d lookups=%0d hits=%0d reads=%0d writes=%0d",
   compared,lookups,hits,bus_reads,bus_writes);
 $finish;
end
initial begin #5000000; $fatal(1,"PREFETCH CYCLE LIMIT 500000"); end
endmodule
"""


def prefetch_probe(ev):
    initial = bytearray((i * 37 + 11) & 255 for i in range(32768))

    def word(offset):
        return int.from_bytes(initial[offset & 32767:(offset & 32767) + 8], "little")

    calls = []

    def read(address, hit=0):
        calls.append(f"access(0,64'h{address:x},0,0,64'h{word(address-0x80000000):016x},0,{hit});")

    calls.append("prefetch_block=0;")
    read(0x80000000)
    calls.append("wait_reads(8);")
    read(0x80000020, 1)
    value, mask = 0x8877665544332211, 0xA5
    calls.append(f"access(1,64'h80000020,64'h{value:016x},8'h{mask:02x},0,0,1);")
    for lane in range(8):
        if mask >> lane & 1:
            initial[32 + lane] = value >> (8 * lane) & 255
    read(0x80000020, 1)
    calls.extend(("if(bus_writes!=1) $fatal(1,\"write-through prefetch coherence\");",
                  "access(3,0,0,0,0,0,0);", "prefetch_block=0;"))
    read(0x80000100)
    calls.extend(("force_stall=1; repeat(10) @(negedge clk);",
                  "if(bus_reads!=12) $fatal(1,\"speculative transfer accepted while stalled\");",
                  "block_after_accept=1;"))
    read(0x80000120)
    calls.extend(("wait_reads(16);", "block_after_accept=0;",
                  "access(3,0,0,0,0,0,0);", "prefetch_block=0;"))
    read(0x80000200)
    calls.extend(("fail_kind=1;", "wait_reads(21);", "prefetch_block=1;"))
    read(0x80000220)
    calls.extend(("wait_reads(25);", "prefetch_block=0;"))
    read(0xFFFFFFE0)
    calls.append("wait_reads(29);")
    read(0xFFFFFFF8, 1)
    calls.extend(("access(0,64'h10010000,0,0,0,1,0);", "wait_reads(29);",
                  "rst_n=0; #1; reset_check(); #19; rst_n=1;",
                  "demand_events=0; hit_events=0; lookups=0; hits=0; prefetch_block=1;"))
    read(0x80000000)
    calls.extend(("wait_reads(33);", "prefetch_block=0;"))
    read(0x80001000)
    calls.extend(("while(bus_reads<38) @(negedge clk);",
                  "rst_n=0; #1; reset_check(); #19; rst_n=1;",
                  "demand_events=0; hit_events=0; lookups=0; hits=0; prefetch_block=1;",
                  "repeat(20) begin @(negedge clk); if(rsp_valid !== 0) "
                  "$fatal(1,\"stale prefetched response crossed reset epoch\"); end"))
    read(0x80001020)
    calls.append("wait_reads(42);")
    prefix = TB.split("integer file,status", 1)[0]
    prefix = prefix.replace("SETS=1, PREFETCH=0", "SETS=1, PREFETCH=1")
    prefix = prefix.replace("mem_addr>=64'h80008000", "mem_addr>=64'h100000000")
    prefix = prefix.replace("pending_addr<=mem_addr-64'h80000000",
                            "pending_addr<=(mem_addr-64'h80000000)&64'h7fff")
    prefix = prefix.replace("mem_ready=rst_n &&", "mem_ready=rst_n && !force_stall &&")
    tb = ev.directory / "prefetch_tb.sv"
    tb.write_text(prefix + CONTROL.replace("__CASES__", "\n".join(calls)))
    ev.record.setdefault("generated_sha256", {})[ev.relative(tb)] = digest(tb)
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "memory_tb", "-o",
            ev.relative(ev.directory / "prefetch.vvp"), ev.relative(tb),
            "rtl/hammer_v5_l2.sv"], "prefetch-compile")
    summary = "SUMMARY PREFETCH compared=16"
    text = ev.run(["vvp", "./prefetch.vvp"], "prefetch-icarus", cwd=ev.directory)
    if summary not in text:
        raise AssertionError("required directed prefetch comparisons incomplete")
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "memory_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "prefetch-sim",
            ev.relative(tb), "rtl/hammer_v5_l2.sv"], "prefetch-verilator-compile")
    try:
        text = ev.run(["./compile-obj/prefetch-sim"], "prefetch-verilator", cwd=ev.directory)
        if summary not in text:
            raise AssertionError("compiled prefetch comparisons incomplete")
        ev.record["observed"] = {"compared": 16, "next_line": True,
                                 "no_chaining": True, "demand_preempts_unaccepted": True,
                                 "failed_prefetch_not_resident": True, "masked_coherence": True,
                                 "last_region_line": True, "mmio_rejection": True,
                                 "reset_epochs": 2}
    finally:
        shutil.rmtree(objects)
