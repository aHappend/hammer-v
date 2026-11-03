"""Independent translated halfword assembly, fault and reset-epoch tests."""
import shutil

from compressed import decode
from evidence import ROOT, digest


TB = r"""
module fetch_tb;
reg clk=0;
always #5 clk=~clk;
reg rst_n,req_valid=0,rsp_ready=0;
reg [63:0] req_addr=0;
reg [1:0] req_cmd=0;
wire req_ready,rsp_valid,rsp_error,rsp_page_fault,rsp_illegal;
wire [63:0] rsp_rdata,rsp_tval,tr_va,cache_addr;
wire [31:0] rsp_insn_raw;
wire [2:0] rsp_insn_bytes;
wire tr_valid,tr_rsp_ready,cache_valid,cache_rsp_ready;
reg tr_ready=0,tr_rsp_valid=0,tr_page_fault=0,tr_access_fault=0;
reg [55:0] tr_pa=0;
reg cache_ready=0,cache_rsp_valid=0,cache_error=0;
reg [63:0] cache_rdata=0;
wire [1:0] cache_cmd;
hammer_v5_fetch_path dut(.*);
integer compared=0,translations=0,cache_reads=0;
task reset_check;
begin
 if({req_ready,rsp_valid,rsp_error,rsp_page_fault,rsp_illegal,rsp_rdata,
     rsp_tval,rsp_insn_raw,rsp_insn_bytes,tr_valid,tr_rsp_ready,tr_va,
     cache_valid,cache_rsp_ready,cache_addr,cache_cmd} !== 302'b0)
  $fatal(1,"FETCH RESET");
end
endtask
always @(posedge clk or negedge clk) if(!rst_n) reset_check();
task request(input [63:0] address);
begin
 @(negedge clk); req_addr=address; req_valid=1;
 while(req_ready !== 1) @(negedge clk);
 @(posedge clk);
 if(rsp_valid !== 0) $fatal(1,"FETCH same-edge completion");
 #1; req_valid=0;
 if(req_ready !== 0) $fatal(1,"FETCH duplicate acceptance");
end
endtask
task translate(input [63:0] va,input [55:0] pa,input integer fault);
integer waited;
begin
 waited=0;
 while(tr_valid !== 1) begin
  @(negedge clk); waited=waited+1;
  if(waited>100) $fatal(1,"missing translation");
 end
 if(tr_va !== va) $fatal(1,"FETCH TRANSLATION expected=%h observed=%h",va,tr_va);
 repeat(3) begin
  @(posedge clk); #1;
  if(tr_valid !== 1 || tr_va !== va || rsp_valid !== 0)
   $fatal(1,"translation payload unstable");
 end
 @(negedge clk); tr_ready=1;
 @(posedge clk); #1; tr_ready=0;
 if(tr_valid !== 0 || tr_rsp_ready !== 1) $fatal(1,"translation handshake");
 @(negedge clk); tr_pa=pa; tr_page_fault=(fault==1); tr_access_fault=(fault==2);
 tr_rsp_valid=1;
 @(posedge clk); #1;
 tr_rsp_valid=0; tr_pa=0; tr_page_fault=0; tr_access_fault=0;
 translations=translations+1;
end
endtask
task read_cache(input [63:0] address,input [31:0] data);
integer waited;
begin
 waited=0;
 while(cache_valid !== 1) begin
  @(negedge clk); waited=waited+1;
  if(waited>100) $fatal(1,"missing cache request");
 end
 if(cache_addr !== address || cache_cmd !== 0)
  $fatal(1,"FETCH CACHE expected=%h observed=%h",address,cache_addr);
 repeat(3) begin
  @(posedge clk); #1;
  if(cache_valid !== 1 || cache_addr !== address || rsp_valid !== 0)
   $fatal(1,"cache request payload unstable");
 end
 @(negedge clk); cache_ready=1;
 @(posedge clk); #1; cache_ready=0;
 if(cache_valid !== 0 || cache_rsp_ready !== 1) $fatal(1,"cache handshake");
 @(negedge clk); cache_rdata={32'b0,data}; cache_rsp_valid=1;
 @(posedge clk); #1; cache_rdata=0; cache_rsp_valid=0;
 cache_reads=cache_reads+1;
end
endtask
task response(input [31:0] raw,input [31:0] expanded,input [2:0] length,
              input integer error,input integer page,input integer illegal,
              input [63:0] tval);
integer waited;
begin
 waited=0;
 while(rsp_valid !== 1) begin
  @(negedge clk); waited=waited+1;
  if(waited>100) $fatal(1,"missing fetch response");
 end
 repeat(4) begin
  if(rsp_insn_raw !== raw || rsp_rdata !== {32'b0,expanded} ||
     rsp_insn_bytes !== length || rsp_error !== (error!=0) ||
     rsp_page_fault !== (page!=0) || rsp_illegal !== (illegal!=0) ||
     rsp_tval !== tval || req_ready !== 0 ||
     tr_valid !== 0 || cache_valid !== 0)
   $fatal(1,"FETCH MISMATCH case=%d raw=%h expanded=%h bytes=%d flags=%b tval=%h",
     compared,rsp_insn_raw,rsp_rdata,rsp_insn_bytes,
     {rsp_error,rsp_page_fault,rsp_illegal},rsp_tval);
  @(negedge clk);
 end
 rsp_ready=1;
 @(posedge clk);
 if(rsp_valid !== 1) $fatal(1,"fetch response missing at transfer");
 #1; rsp_ready=0;
 if(rsp_valid !== 0 || req_ready !== 1 || rsp_rdata !== 0 || rsp_tval !== 0)
  $fatal(1,"stale fetch response");
 compared=compared+1;
end
endtask
initial begin
 rst_n=0; #0; reset_check(); #21; rst_n=1;
__CASES__
 // Reset a translated request while its cache request is stalled.
 request(64'h400002);
 translate(64'h400002,56'h80000002,0);
 while(cache_valid !== 1) @(negedge clk);
 rst_n=0; #1; reset_check(); #19; rst_n=1;
 cache_rsp_valid=1; cache_rdata=64'hdeadbeef;
 repeat(3) begin
  @(posedge clk); #1;
  if(rsp_valid !== 0 || cache_rsp_ready !== 0) $fatal(1,"post-reset stale result");
 end
 @(negedge clk); cache_rsp_valid=0; cache_rdata=0;
 // Reset while holding a completed response under backpressure.
 request(64'h400000);
 translate(64'h400000,56'h80000000,0);
 read_cache(64'h80000000,32'h00010001);
 if(rsp_valid !== 1) $fatal(1,"reset-response scenario not reached");
 rst_n=0; #1; reset_check(); #19; rst_n=1;
 repeat(3) begin
  @(posedge clk); #1;
  if(rsp_valid !== 0 || req_ready !== 1) $fatal(1,"reset failed to discard response");
 end
 if(compared!=__COUNT__ || translations!=__TRANSLATIONS__+2 ||
    cache_reads!=__READS__+1) $fatal(1,"fetch coverage missing");
 $display("SUMMARY FETCH compared=%0d translations=%0d cache_reads=%0d reset_epochs=2",
    compared,translations,cache_reads);
 $finish;
end
initial begin #5000000; $fatal(1,"FETCH CYCLE LIMIT 500000"); end
endmodule
"""


def fetch_probe(ev):
    calls = []
    translations = reads = compared = 0
    for address in (0x400000, 0x400002, 0x40001E, 0x400FFE):
        first_pa = 0x80000000 + (address & 4095)
        for raw in (0x440D, 0x2000, 0xFFF40493):
            calls.append(f"request(64'h{address:x});")
            calls.append(f"translate(64'h{address:x},56'h{first_pa:x},0);")
            translations += 1
            payload = raw if not address & 2 else (raw & 65535) << 16 | 0xDEAD
            calls.append(f"read_cache(64'h{first_pa & ~3:x},32'h{payload:08x});")
            reads += 1
            if raw & 3 != 3:
                expanded, illegal, _ = decode(raw)
                length = 2
            else:
                expanded, illegal, length = raw, False, 4
                if address & 2:
                    second = address + 2
                    second_pa = (0x90000000 if second & ~4095 != address & ~4095
                                 else 0x80000000) + (second & 4095)
                    calls.append(f"translate(64'h{second:x},56'h{second_pa:x},0);")
                    calls.append(f"read_cache(64'h{second_pa & ~3:x},32'h{raw >> 16:08x});")
                    translations += 1
                    reads += 1
            calls.append(f"response(32'h{raw:08x},32'h{expanded:08x},3'd{length},"
                         f"0,0,{int(illegal)},64'h{raw if illegal else 0:x});")
            compared += 1
    for fault in (1, 2):
        calls.extend(("request(64'h400ffe);",
                      "translate(64'h400ffe,56'h80000ffe,0);",
                      "read_cache(64'h80000ffc,32'h0493dead);",
                      f"translate(64'h401000,56'h90000000,{fault});",
                      f"response(0,0,0,{int(fault==2)},{int(fault==1)},0,64'h401000);"))
        translations += 2
        reads += 1
        compared += 1
    calls.extend(("request(64'h400001);", "response(0,0,0,1,0,0,64'h400001);"))
    compared += 1
    text = TB.replace("__CASES__", "\n".join(calls)).replace("__COUNT__", str(compared))
    text = text.replace("__TRANSLATIONS__", str(translations)).replace("__READS__", str(reads))
    tb = ev.directory / "fetch_tb.sv"
    tb.write_text(text)
    ev.record.setdefault("generated_sha256", {})[ev.relative(tb)] = digest(tb)
    sources = [ROOT / "rtl/hammer_v5_fetch_path.sv", ROOT / "rtl/hammer_v5_decompress.sv"]
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "fetch_tb", "-o",
            ev.relative(ev.directory / "fetch.vvp"), ev.relative(tb),
            *map(ev.relative, sources)], "fetch-compile")
    summary = f"SUMMARY FETCH compared={compared}"
    output = ev.run(["vvp", "./fetch.vvp"], "fetch-icarus", cwd=ev.directory)
    if summary not in output:
        raise AssertionError("translated fetch comparisons incomplete")
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "fetch_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "fetch-sim",
            ev.relative(tb), *map(ev.relative, sources)], "fetch-verilator-compile")
    try:
        output = ev.run(["./compile-obj/fetch-sim"], "fetch-verilator", cwd=ev.directory)
        if summary not in output:
            raise AssertionError("compiled translated fetch comparisons incomplete")
        ev.record["observed"] = {"compared": compared, "translations": translations + 2,
                                 "cache_reads": reads + 1, "reset_epochs": 2}
    finally:
        shutil.rmtree(objects)
