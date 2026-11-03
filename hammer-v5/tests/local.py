"""Integrated host masks and partial-last-line local-memory execution."""
import random
import shutil

from evidence import ROOT, digest
from integration import ports


TB = r"""
always #5 clk=~clk;
hammer_v5_top #(.IMEM_WORDS(33),.DMEM_WORDS(3),.BOOT_ENABLE(0),.LEGACY_TRAPS(1),
 .BTB_ENTRIES(1),.ICACHE_LINES(1),.DCACHE_LINES(1),
 .ITLB_ENTRIES(1),.DTLB_ENTRIES(1),.L2_SETS(1)) dut(.*);
integer compared=0,retired=0,cycles=0;
reg trapped=0;
task access(input integer instruction,input integer write,input [31:0] address,
 input [63:0] data,input [7:0] mask,input integer error,input [63:0] expected);
integer waited;
begin
 @(negedge clk);
 host_imem=instruction; host_write=write; host_addr=address;
 host_wdata=data; host_wstrb=mask; host_valid=1;
 waited=0;
 while(host_ready !== 1) begin
  @(negedge clk); waited=waited+1;
  if(waited>10000) $fatal(1,"host local-memory request not admitted");
 end
 @(posedge clk); #1; host_valid=0;
 waited=0;
 while(host_rsp_valid !== 1) begin
  @(negedge clk); waited=waited+1;
  if(waited>10000) $fatal(1,"host local-memory response missing");
 end
 if(host_rsp_error !== (error!=0) || (!write && host_rdata !== expected) ||
    (^host_rdata) === 1'bx)
  $fatal(1,"LOCAL MEMORY MISMATCH case=%0d imem=%0d write=%0d addr=%h expected=%h/%0d observed=%h/%b",
    compared,instruction,write,address,expected,error,host_rdata,host_rsp_error);
 compared=compared+1;
 @(negedge clk);
end
endtask
always @(posedge clk) if(rst_n) begin
 cycles=cycles+1;
 if(m_mem_axi_arvalid !== 0 || m_mem_axi_awvalid !== 0 || m_mem_axi_wvalid !== 0 ||
    m_axi_arvalid !== 0 || m_axi_awvalid !== 0 || m_axi_wvalid !== 0)
  $fatal(1,"local partial-line access escaped onto an external bus");
 if(retire_valid === 1) begin
  case(retired)
   0: if(retire_pc!==0 || retire_next_pc!==4 || retire_rd!==1 ||
         retire_rd_data!==64'h10000000) $fatal(1,"local base LUI");
   1: if(retire_pc!==4 || retire_next_pc!==8 || retire_rd!==2 ||
         retire_rd_data!==64'h__LAST__ || retire_mem_addr!==64'h10000010)
       $fatal(1,"last partial-line local data word");
   2: if(retire_pc!==8 || retire_next_pc!==12 || retire_rd!==3 ||
         retire_rd_data!==64'h__FIRST__ || retire_mem_addr!==64'h10000000)
       $fatal(1,"first local data word");
   3: if(retire_pc!==12 || retire_next_pc!==128 || retire_rd_we!==0)
       $fatal(1,"jump to final partial instruction line");
   4: if(retire_pc!==128 || retire_next_pc!==130 || retire_insn!==32'h440d ||
         retire_rd!==8 || retire_rd_data!==3) $fatal(1,"last instruction word");
   default: $fatal(1,"duplicate retirement after last local instruction word");
  endcase
  retired=retired+1;
 end else if(retire_valid !== 0) $fatal(1,"active X retirement");
 if(trap_valid === 1) begin
  if(trap_pc!==130 || trap_cause!==3 || retired!=5)
   $fatal(1,"wrong trap at final local halfword");
  trapped=1;
 end else if(trap_valid !== 0) $fatal(1,"active X trap");
 if(cycles>200000) $fatal(1,"local integration cycle bound");
end
initial begin
 rst_n=0; uart_rx=1; #21; rst_n=1;
__CASES__
 @(negedge clk); start=1;
 @(posedge clk); #1; start=0;
 while(!trapped) @(negedge clk);
 while(halted !== 1) @(negedge clk);
 if(compared!=__COUNT__) $fatal(1,"local-memory host comparison coverage missing");
 $display("SUMMARY LOCAL host_compared=%0d retired=%0d final_halfword_trap=1",compared,retired);
 $finish;
end
endmodule
"""


def local_probe(ev):
    declarations = []
    for direction, width, name in ports(ROOT / "rtl/hammer_v5_top.sv"):
        initial = "" if direction == "output" or name == "rst_n" else "=0"
        declarations.append(f"{'reg' if direction == 'input' else 'wire'} "
                            f"{width} {name}{initial};")
    data = bytearray(24)
    calls = []
    rng = random.Random(89)

    def access(instruction, write, address, value=0, mask=0, error=0, expected=0):
        calls.append(f"access({instruction},{write},32'h{address:08x},"
                     f"64'h{value:016x},8'h{mask:02x},{error},64'h{expected:016x});")

    for address in (0, 8, 16):
        access(0, 0, address)
    for mask in range(256):
        address = 0 if mask & 1 else 16
        value = rng.getrandbits(64)
        access(0, 1, address, value, mask)
        for lane in range(8):
            if mask >> lane & 1:
                data[address + lane] = value >> (lane * 8) & 255
        access(0, 0, address, expected=int.from_bytes(data[address:address + 8], "little"))
    for address in (24, 25, 0xFFFFFFFF):
        access(0, 0, address, error=1)
    for address in (132, 133, 0xFFFFFFFF):
        access(1, 0, address, error=1)
    for address, word in ((0, 0x100000B7), (4, 0x0100B103), (8, 0x0000B183),
                          (12, 0x0740006F), (128, 0x9002440D)):
        access(1, 1, address, word, 15)
        access(1, 0, address, expected=word)
    text = "module local_tb;\n" + "\n".join(declarations) + "\n" + TB
    text = text.replace("__CASES__", "\n".join(calls)).replace("__COUNT__", str(len(calls)))
    text = text.replace("__FIRST__", f"{int.from_bytes(data[:8], 'little'):016x}")
    text = text.replace("__LAST__", f"{int.from_bytes(data[16:], 'little'):016x}")
    tb = ev.directory / "local_tb.sv"
    tb.write_text(text)
    ev.record.setdefault("generated_sha256", {})[ev.relative(tb)] = digest(tb)
    sources = sorted((ROOT / "rtl").glob("*.sv"))
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "local_tb", "-o",
            ev.relative(ev.directory / "local.vvp"), ev.relative(tb),
            *map(ev.relative, sources)], "local-compile")
    summary = f"SUMMARY LOCAL host_compared={len(calls)} retired=5"
    text = ev.run(["vvp", "./local.vvp"], "local-icarus", cwd=ev.directory)
    if summary not in text:
        raise AssertionError("local-memory integration comparisons incomplete")
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "local_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "local-sim",
            ev.relative(tb), *map(ev.relative, sources)], "local-verilator-compile")
    try:
        text = ev.run(["./compile-obj/local-sim"], "local-verilator", cwd=ev.directory)
        if summary not in text:
            raise AssertionError("compiled local-memory comparisons incomplete")
        ev.record["observed"] = {"host_compared": len(calls), "byte_masks": 256,
                                 "retired": 5, "last_halfword": 130, "trap": 1}
    finally:
        shutil.rmtree(objects)
