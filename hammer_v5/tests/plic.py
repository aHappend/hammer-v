"""Public-pin discrimination of the inherited PLIC Yosys range warning."""
from evidence import ROOT, digest


TB = r"""
module plic_tb;
reg clk=0;
always #5 clk=~clk;
reg rst_n;
reg uart_irq=0;
reg [30:0] plic_sources=0;
reg req_valid=0, req_write=0, rsp_ready=0;
reg [63:0] req_addr=0, req_wdata=0;
reg [7:0] req_wstrb=0;
reg [1:0] req_size=2;
wire irq_meip, irq_seip, req_ready, rsp_valid, rsp_error;
wire [63:0] rsp_rdata;
integer compared=0;
hammer_v3_plic dut(.*);
task reset_check;
begin
 if ({irq_meip,irq_seip,req_ready,rsp_valid,rsp_error,rsp_rdata} !== 69'b0)
  $fatal(1,"PLIC RESET");
end
endtask
always @(posedge clk or negedge clk) if (!rst_n) reset_check();
task access(input bit wr,input [63:0] addr,input [31:0] value,
            input [31:0] expected);
reg [63:0] aligned;
integer cycles;
begin
 @(negedge clk);
 req_valid=1; req_write=wr; req_addr=addr;
 req_wstrb=addr[2] ? 8'hf0 : 8'h0f;
 req_wdata=addr[2] ? {value,32'b0} : {32'b0,value};
 cycles=0;
 while (req_ready !== 1'b1) begin
  @(negedge clk); cycles=cycles+1;
  if (cycles>40) $fatal(1,"PLIC request not accepted");
 end
 @(posedge clk);
 if (rsp_valid !== 1'b0) $fatal(1,"PLIC response at accepting edge");
 #1; req_valid=0;
 aligned=wr ? 64'b0 : addr[2] ? {expected,32'b0} : {32'b0,expected};
 if (rsp_valid !== 1'b1 || rsp_error !== 1'b0 || rsp_rdata !== aligned)
  $fatal(1,"PLIC MISMATCH address=%h expected=%h observed=%h error=%b",
         addr,aligned,rsp_rdata,rsp_error);
 repeat (2) begin
  @(posedge clk); #1;
  if (rsp_valid !== 1'b1 || rsp_rdata !== aligned || req_ready !== 1'b0)
   $fatal(1,"PLIC response unstable");
 end
 @(negedge clk); rsp_ready=1;
 @(posedge clk);
 if (rsp_valid !== 1'b1) $fatal(1,"PLIC response missing at transfer");
 #1; rsp_ready=0;
 if (rsp_valid !== 1'b0 || req_ready !== 1'b1)
  $fatal(1,"PLIC duplicate response");
 compared=compared+1;
end
endtask
initial begin
 rst_n=0; #0; reset_check();
 #21; rst_n=1;
 access(1,64'h0c000004,3,0);
 access(1,64'h0c002000,2,0);
 access(0,64'h0c002000,0,2);
 uart_irq=1;
 repeat (8) @(negedge clk);
 if (irq_meip !== 1'b1) $fatal(1,"PLIC UART interrupt not witnessed");
 access(0,64'h0c200004,0,1);
 uart_irq=0;
 access(1,64'h0c200004,1,0);
 access(1,64'h0c000080,7,0);
 access(1,64'h0c002004,1,0);
 access(0,64'h0c002004,0,1);
 plic_sources=31'h40000000;
 repeat (8) @(negedge clk);
 if (irq_meip !== 1'b1) $fatal(1,"PLIC source 32 interrupt not witnessed");
 access(0,64'h0c001004,0,1);
 access(0,64'h0c200004,0,32);
 plic_sources=0;
 access(1,64'h0c200004,32,0);
 access(1,64'h0c002084,1,0);
 access(0,64'h0c002084,0,1);
 $display("SUMMARY PLIC compared=%0d",compared);
 $finish;
end
initial begin #50000; $fatal(1,"PLIC CYCLE LIMIT"); end
endmodule
"""


def plic_probe(ev):
    source = ROOT / "rtl/hammer_v3_plic.sv"
    parent = ROOT / "hammer_v4_reference/rtl/hammer_v3_plic.sv"
    ev.record["parent_comparison"] = {
        "source_sha256": digest(source), "parent_sha256": digest(parent),
        "byte_identical": source.read_bytes() == parent.read_bytes(),
    }
    tb = ev.directory / "plic_tb.sv"
    tb.write_text(TB)
    ev.record.setdefault("generated_sha256", {})[ev.relative(tb)] = digest(tb)
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("yosys", ("-V",))
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "plic_tb", "-o",
            ev.relative(ev.directory / "rtl.vvp"), ev.relative(tb),
            ev.relative(source)], "plic-rtl-compile")
    result = ev.run(["vvp", "./rtl.vvp"], "plic-rtl-run", cwd=ev.directory)
    if "SUMMARY PLIC compared=13" not in result:
        raise AssertionError("PLIC RTL comparison count missing")
    ev.record["observed"] = {"rtl_compared": 13}
    ev.save()
    script = ev.directory / "plic.ys"
    lowered = ev.directory / "lowered.sv"
    script.write_text(
        "read_verilog -sv rtl/hammer_v3_plic.sv\n"
        "hierarchy -check -top hammer_v3_plic\n"
        "proc\nopt_expr\nopt_clean\ncheck -assert\n"
        "write_verilog -noattr " + ev.relative(lowered) + "\n")
    ev.record["generated_sha256"][ev.relative(script)] = digest(script)
    ev.run(["yosys", "-Q", "-T", "-s", ev.relative(script)], "plic-lower")
    ev.record["generated_sha256"][ev.relative(lowered)] = digest(lowered)
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "plic_tb", "-o",
            ev.relative(ev.directory / "lowered.vvp"), ev.relative(tb),
            ev.relative(lowered)], "plic-lowered-compile")
    result = ev.run(["vvp", "./lowered.vvp"], "plic-lowered-run", cwd=ev.directory)
    if "SUMMARY PLIC compared=13" not in result:
        raise AssertionError("lowered PLIC comparison count missing")
    ev.record["observed"]["lowered_compared"] = 13
