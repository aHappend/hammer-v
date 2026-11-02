"""Compact public architectural checks of the complete delivered SoC."""
import re
import shutil

from evidence import ROOT, digest


def ports(source):
    header = source.read_text().split(") (", 1)[1].split(");", 1)[0].strip()
    matches = re.finditer(
        r"\b(input|output)\s+wire\s+(\[[^]]+\]\s*)?(.+?)"
        r"(?=,\s*(?:input|output)\s+wire|\s*$)", header, re.S)
    result = []
    for match in matches:
        for name in match[3].split(","):
            name = name.strip()
            if not re.fullmatch(r"\w+", name):
                raise ValueError(f"unexpected public port syntax: {name}")
            result.append((match[1], (match[2] or "").strip(), name))
    if len({name for _, _, name in result}) != len(result) or not result:
        raise ValueError("missing or duplicated public ports")
    return result


def top_smoke(ev):
    interface = ports(ROOT / "rtl/hammer_v5_top.sv")
    parent = ports(ROOT / "hammer_v4_reference/rtl/hammer_v4_top.sv")
    if interface != parent:
        raise AssertionError("V5 top changed the inherited public port contract")
    declarations = []
    for direction, width, name in interface:
        initial = "" if direction == "output" or name == "rst_n" else "=0"
        declarations.append(
            f"{'reg' if direction == 'input' else 'wire'} {width} {name}{initial};")
    # Hand-encoded instructions; expected retirement is derived from ISA effects.
    instructions = [
        (0x440D, 2), (0xFFF40493, 4), (0x94A2, 2), (0x14F9, 2),
        (0x008000EF, 4), (0x54FD, 2), (0x0001, 2),
        (0x00008513, 4), (0x9002, 2),
    ]
    program = b"".join(word.to_bytes(length, "little")
                       for word, length in instructions)
    expected = (
        (0, 2, 0x440D, 8, 3), (2, 6, 0xFFF40493, 9, 2),
        (6, 8, 0x94A2, 9, 5), (8, 10, 0x14F9, 9, 3),
        (10, 18, 0x008000EF, 1, 14), (18, 22, 0x00008513, 10, 14),
    )
    loads = "\n".join(
        f"host_load(32'd{offset},32'h{int.from_bytes(program[offset:offset+4], 'little'):08x});"
        for offset in range(0, len(program), 4))
    expectations = "\n".join(
        f"epc[{i}]=64'd{pc}; enext[{i}]=64'd{nxt}; eraw[{i}]=32'h{raw:08x}; "
        f"erd[{i}]=5'd{rd}; edata[{i}]=64'd{data};"
        for i, (pc, nxt, raw, rd, data) in enumerate(expected))
    tb = ev.directory / "top_tb.sv"
    tb.write_text("module top_tb;\n" + "\n".join(declarations) + r"""
always #5 clk=~clk;
hammer_v5_top #(.IMEM_WORDS(33),.DMEM_WORDS(3),.PRED_MODE(1),
 .BTB_ENTRIES(1),.ICACHE_LINES(1),.DCACHE_LINES(1),
 .ITLB_ENTRIES(1),.DTLB_ENTRIES(1),.BOOT_ENABLE(0),
 .LEGACY_TRAPS(1),.L2_SETS(1)) dut(.*);
reg [63:0] epc[0:5],enext[0:5],edata[0:5];
reg [31:0] eraw[0:5];
reg [4:0] erd[0:5];
integer compared=0, cycles=0;
reg observed_trap=0;
task reset_check;
begin
 if ({host_ready,host_rsp_valid,host_rsp_error,retire_valid,trap_valid,
      boot_ready,boot_error,m_axi_awvalid,m_axi_wvalid,m_axi_arvalid,
      m_mem_axi_awvalid,m_mem_axi_wvalid,m_mem_axi_arvalid,
      s_acc_axi_awready,s_acc_axi_wready,s_acc_axi_arready,
      s_acc_axi_bvalid,s_acc_axi_rvalid} !== 18'b0 ||
     halted !== 1'b1 || uart_tx !== 1'b1)
  $fatal(1,"TOP RESET flags=%b halted=%b uart=%b",
     {host_ready,host_rsp_valid,host_rsp_error,retire_valid,trap_valid,
      boot_ready,boot_error,m_axi_awvalid,m_axi_wvalid,m_axi_arvalid,
      m_mem_axi_awvalid,m_mem_axi_wvalid,m_mem_axi_arvalid,
      s_acc_axi_awready,s_acc_axi_wready,s_acc_axi_arready,
      s_acc_axi_bvalid,s_acc_axi_rvalid},halted,uart_tx);
end
endtask
always @(posedge clk or negedge clk) if (!rst_n) reset_check();
always @(posedge clk) if (rst_n) begin
 cycles=cycles+1;
 if (retire_valid === 1'b1) begin
  if (compared>=6) $fatal(1,"TOP duplicate/squashed retirement");
  if (retire_pc !== epc[compared] || retire_next_pc !== enext[compared] ||
      retire_insn !== eraw[compared] || retire_rd_we !== 1'b1 ||
      retire_rd !== erd[compared] || retire_rd_data !== edata[compared] ||
      retire_priv !== 2'd3 || retire_mem_valid !== 1'b0)
   $fatal(1,"ARCH MISMATCH case=%0d pc=%h next=%h raw=%h rd=%d data=%h",
      compared,retire_pc,retire_next_pc,retire_insn,retire_rd,retire_rd_data);
  compared=compared+1;
 end else if (retire_valid !== 1'b0) $fatal(1,"TOP active X retirement");
 if (trap_valid === 1'b1) begin
  if (observed_trap || compared!=6 || trap_pc !== 64'd22 ||
      trap_cause !== 64'd3 || trap_interrupt !== 1'b0 ||
      trap_target_priv !== 2'd3)
   $fatal(1,"TOP unexpected trap pc=%h cause=%h compared=%d",
     trap_pc,trap_cause,compared);
  observed_trap=1;
 end else if (trap_valid !== 1'b0) $fatal(1,"TOP active X trap");
 if (cycles>10000) $fatal(1,"TOP CYCLE LIMIT");
end
task host_load(input [31:0] address,input [31:0] data);
integer waited;
begin
 @(negedge clk);
 host_valid=1; host_write=1; host_imem=1; host_addr=address;
 host_wdata={32'b0,data}; host_wstrb=8'h0f;
 waited=0;
 while (host_ready !== 1'b1) begin
  @(negedge clk); waited=waited+1;
  if (waited>1000) $fatal(1,"TOP host accept missing");
 end
 @(posedge clk); #1; host_valid=0;
 waited=0;
 while (host_rsp_valid !== 1'b1) begin
  @(negedge clk); waited=waited+1;
  if (waited>1000) $fatal(1,"TOP host response missing");
 end
 if (host_rsp_error !== 1'b0 || (^host_rdata) === 1'bx)
  $fatal(1,"TOP host failed");
 @(negedge clk);
end
endtask
initial begin
""" + expectations + r"""
 rst_n=0; uart_rx=1;
 #0; reset_check();
 #21; rst_n=1;
""" + loads + r"""
 @(negedge clk); start=1;
 while (!observed_trap) @(negedge clk);
 start=0;
 while (halted !== 1'b1) @(negedge clk);
 dbg_raddr=9; #1;
 if (dbg_rdata !== 64'd3) $fatal(1,"TOP squashed write changed x9");
 dbg_raddr=1; #1;
 if (dbg_rdata !== 64'd14) $fatal(1,"TOP compressed link mismatch");
 $display("SUMMARY TOP compared=6 trap=1 squashed=1 host_words=6");
 $finish;
end
endmodule
""")
    ev.record["generated_sha256"] = {ev.relative(tb): digest(tb)}
    ev.record["scope"] = {
        "top": "hammer_v5_top", "geometry": "33/3 singleton boot-off",
        "public_pin_only": True, "not_linux_execution": True,
        "expected_retirement": [list(row) for row in expected],
    }
    sources = sorted((ROOT / "rtl").glob("*.sv"))
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.version("make")
    ev.version("g++")
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "top_tb", "-o",
            ev.relative(ev.directory / "top.vvp"), ev.relative(tb),
            *map(ev.relative, sources)], "top-icarus-compile")
    output = ev.run(["vvp", "./top.vvp"], "top-icarus-run", cwd=ev.directory)
    summary = "SUMMARY TOP compared=6 trap=1 squashed=1 host_words=6"
    if summary not in output:
        raise AssertionError("compact architectural Icarus smoke incomplete")
    ev.record["observed"] = {"icarus_retirements": 6, "icarus_traps": 1}
    ev.save()
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "top_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "top-sim",
            ev.relative(tb), *map(ev.relative, sources)], "top-verilator-compile")
    output = ev.run(["./compile-obj/top-sim"], "top-verilator-run", cwd=ev.directory)
    if summary not in output:
        raise AssertionError("compiled architectural smoke incomplete")
    ev.record["observed"].update(verilator_retirements=6, verilator_traps=1)
    shutil.rmtree(objects)
