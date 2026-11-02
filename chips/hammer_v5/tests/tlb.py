"""Public TLB permission, ASID, global and selective-fence transactions."""
import shutil

from evidence import ROOT, digest
from mmu import translate


TB = r"""
module tlb_tb;
reg clk=0;
always #5 clk=~clk;
reg rst_n,req_valid=0,rsp_ready=0;
reg [63:0] req_va=0;
reg [15:0] req_asid=0;
reg [1:0] req_access=0,req_priv=0;
reg req_sum=0,req_mxr=0;
wire req_ready,rsp_valid,rsp_hit,rsp_fault;
wire [55:0] rsp_pa;
reg refill_valid=0;
reg [63:0] refill_va=0;
reg [15:0] refill_asid=0;
reg [43:0] refill_ppn=0;
reg [1:0] refill_level=0;
reg [7:0] refill_flags=0;
reg invalidate_valid=0,invalidate_va_valid=0,invalidate_asid_valid=0;
reg [63:0] invalidate_va=0;
reg [15:0] invalidate_asid=0;
integer compared=0;
hammer_v3_tlb #(.ENTRIES(__ENTRIES__)) dut(.*);
task reset_check;
begin
 if({req_ready,rsp_valid,rsp_hit,rsp_fault,rsp_pa} !== 60'b0)
  $fatal(1,"TLB RESET");
end
endtask
always @(posedge clk or negedge clk) if(!rst_n) reset_check();
task fill(input [63:0] va,input [43:0] ppn,input [15:0] asid,
          input [1:0] level,input [7:0] flags);
begin
 @(negedge clk);
 refill_valid=1; refill_va=va; refill_ppn=ppn; refill_asid=asid;
 refill_level=level; refill_flags=flags;
 @(posedge clk); #1; refill_valid=0;
end
endtask
task invalidate(input integer va_valid,input [63:0] va,
                input integer asid_valid,input [15:0] asid);
begin
 @(negedge clk);
 invalidate_valid=1; invalidate_va_valid=va_valid;
 invalidate_va=va; invalidate_asid_valid=asid_valid; invalidate_asid=asid;
 #1; if(req_ready !== 0) $fatal(1,"TLB invalidation admitted a lookup");
 @(posedge clk); #1; invalidate_valid=0;
 invalidate_va_valid=0; invalidate_asid_valid=0;
end
endtask
task query(input [63:0] va,input [15:0] asid,input [1:0] access,
           input [1:0] privilege,input integer sum_enabled,input integer mxr,
           input integer hit,input [55:0] expected,input integer fault);
begin
 @(negedge clk);
 req_va=va; req_asid=asid; req_access=access; req_priv=privilege;
 req_sum=sum_enabled; req_mxr=mxr; req_valid=1;
 #1; if(req_ready !== 1) $fatal(1,"TLB missing readiness");
 @(posedge clk);
 if(rsp_valid !== 0) $fatal(1,"TLB accepting-edge response");
 #1; req_valid=0;
 if(rsp_valid !== 0 || req_ready !== 0) $fatal(1,"TLB capture boundary");
 @(posedge clk);
 if(rsp_valid !== 0) $fatal(1,"TLB response not registered");
 #1;
 repeat(3) begin
  if(rsp_valid !== 1 || rsp_hit !== (hit!=0) ||
     rsp_pa !== expected || rsp_fault !== (fault!=0) || req_ready !== 0)
   $fatal(1,"TLB MISMATCH case=%d va=%h asid=%d expected=%h/%d/%d observed=%h/%b/%b",
     compared,va,asid,expected,hit,fault,rsp_pa,rsp_hit,rsp_fault);
  @(negedge clk);
 end
 rsp_ready=1;
 @(posedge clk);
 if(rsp_valid !== 1) $fatal(1,"TLB response transfer missing");
 #1; rsp_ready=0;
 if(rsp_valid !== 0 || rsp_pa !== 0 || req_ready !== 1)
  $fatal(1,"TLB stale/duplicated response");
 compared=compared+1;
end
endtask
initial begin
 rst_n=0; #0; reset_check(); #21; rst_n=1;
__CASES__
 fill(64'h400000,44'h80001,16'd17,0,8'hcf);
 @(negedge clk); req_va=64'h400001; req_asid=17; req_access=1; req_priv=1; req_valid=1;
 @(posedge clk); #1; req_valid=0;
 @(posedge clk); #1;
 if(rsp_valid !== 1 || rsp_hit !== 1) $fatal(1,"TLB pending reset scenario not reached");
 rst_n=0; #1; reset_check(); #19; rst_n=1;
 query(64'h400001,17,1,1,0,0,0,0,0);
 if(compared!=__COUNT__) $fatal(1,"TLB required coverage missing");
 $display("SUMMARY TLB compared=%0d entries=__ENTRIES__ reset_aborted=1",compared);
 $finish;
end
initial begin #5000000; $fatal(1,"TLB CYCLE LIMIT 500000"); end
endmodule
"""


def tlb_probe(ev):
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    observations = []
    for entries in (1, 8):
        directory = ev.directory / f"tlb-{entries}-78b5d5e6"
        directory.mkdir()
        calls, compared = [], 0

        def query(va, asid=17, access=1, privilege=1, sum_enabled=0, mxr=0,
                  hit=True, ppn=0x80001, level=0, flags=0xCF):
            nonlocal compared
            memory, root, table = {}, 0x81000, 0x81000
            for depth in (2, 1, 0):
                address = (table << 12) + (((va >> (12 + 9 * depth)) & 511) * 8)
                memory[address] = (ppn << 10) | flags if depth == level else (
                    (table + 1) << 10) | 1
                table += 1
                if depth == level:
                    break
            pa, fault, *_ = translate(va, root, privilege, access, sum_enabled, mxr, memory)
            if not hit:
                pa, fault = 0, 0
            calls.append(f"query(64'h{va:x},16'd{asid},2'd{access},2'd{privilege},"
                         f"{sum_enabled},{mxr},{int(hit)},56'h{pa:x},{fault});")
            compared += 1

        calls.append("fill(64'h400000,44'h80001,17,0,8'hcf);")
        query(0x400123)
        query(0x400123, access=0)
        query(0x400123, privilege=0)
        query(0x400123, asid=43, hit=False)
        calls.append("fill(64'h400000,44'h80001,17,0,8'hd9);")
        query(0x400123, privilege=0, flags=0xD9)
        query(0x400123, privilege=0, mxr=1, flags=0xD9)
        query(0x400123, access=0, sum_enabled=1, flags=0xD9)
        query(0x400123, sum_enabled=1, mxr=1, flags=0xD9)
        calls.append("fill(64'h400000,44'h80001,17,0,8'hef);")
        query(0x400123, asid=43, flags=0xEF)
        calls.append("invalidate(0,0,1,17);")
        query(0x400123, asid=43, flags=0xEF)
        calls.append("invalidate(1,64'h400999,0,0);")
        query(0x400123, hit=False)
        calls.append("fill(64'h401123,44'h80400,17,1,8'hcf);")
        query(0x5FFABC, ppn=0x80400, level=1)
        calls.append("invalidate(1,64'h400001,1,43);")
        query(0x5FFABC, ppn=0x80400, level=1)
        calls.append("invalidate(1,64'h400001,1,17);")
        query(0x5FFABC, hit=False)
        calls.append("fill(64'h40001123,44'hc0000,17,2,8'hcf);")
        query(0x7FFFFFFF, ppn=0xC0000, level=2)
        calls.append("invalidate(0,0,0,0);")
        query(0x7FFFFFFF, hit=False)
        calls.append("fill(64'h400000,44'h80001,17,0,8'hcf);")
        query(0x8000400000)
        calls.append("invalidate(0,0,0,0);")
        for page in range(4):
            calls.append(f"fill(64'h{0x600000+page*4096:x},44'h{0x82000+page:x},17,0,8'hcf);")
        for page in range(4):
            query(0x600000 + page * 4096 + 8, ppn=0x82000 + page,
                  hit=entries > 1 or page == 3)
        text = TB.replace("__ENTRIES__", str(entries)).replace("__CASES__", "\n".join(calls))
        text = text.replace("__COUNT__", str(compared + 1))
        tb = directory / "tlb_tb.sv"
        tb.write_text(text)
        ev.record.setdefault("generated_sha256", {})[ev.relative(tb)] = digest(tb)
        sources = [ROOT / "rtl/hammer_v3_tlb.sv", ROOT / "rtl/hammer_v3_page_leaf.sv"]
        label = f"tlb-{entries}"
        ev.run(["iverilog", "-g2012", "-Wall", "-s", "tlb_tb", "-o",
                ev.relative(directory / "tlb.vvp"), ev.relative(tb),
                *map(ev.relative, sources)], label + "-compile")
        summary = f"SUMMARY TLB compared={compared+1} entries={entries}"
        text = ev.run(["vvp", "./tlb.vvp"], label + "-icarus", cwd=directory)
        if summary not in text:
            raise AssertionError("TLB comparisons incomplete")
        objects = directory / "compile-obj"
        ev.run(["verilator", "--binary", "--timing", "--top-module", "tlb_tb",
                "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "tlb-sim",
                ev.relative(tb), *map(ev.relative, sources)], label + "-verilator-compile")
        try:
            text = ev.run(["./compile-obj/tlb-sim"], label + "-verilator", cwd=directory)
            if summary not in text:
                raise AssertionError("compiled TLB comparisons incomplete")
            observations.append({"entries": entries, "compared": compared + 1,
                                 "ASID_global_selective_fence": True, "reset_aborted": 1})
            ev.record["observed"] = observations
        finally:
            shutil.rmtree(objects)
