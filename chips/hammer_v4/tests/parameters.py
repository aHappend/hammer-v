#!/usr/bin/env python3
"""Compact public-pin reset, boot-loader, host and parameter regressions."""

import argparse
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parent.parent
DEFAULT = {
    "IMEM_WORDS": 32, "DMEM_WORDS": 3, "PRED_MODE": 1, "BTB_ENTRIES": 16,
    "ICACHE_LINES": 64, "DCACHE_LINES": 64, "LEGACY_TRAPS": 0,
    "ITLB_ENTRIES": 8, "DTLB_ENTRIES": 8, "BOOT_ENABLE": 1,
}


def ports():
    source = (ROOT / "rtl/hammer_v4_top.sv").read_text()
    header = source.split(") (", 1)[1].split(");", 1)[0]
    declarations = []
    for match in re.finditer(
        r"\b(input|output)\s+(?:wire|reg)\s*(\[[^\]]+\])?\s*"
        r"([a-zA-Z0-9_,\s]+?)(?=,\s*(?:input|output)\b|$)",
        header.strip(), re.MULTILINE,
    ):
        direction, width, names = match.groups()
        for name in names.replace("\n", "").split(","):
            name = name.strip()
            if name:
                declarations.append((direction, width or "", name))
    if len(declarations) < 100:
        raise ValueError("Top-level ANSI port discovery failed")
    return declarations


def testbench(parameters):
    declarations = ports()
    signals = "\n".join(
        f"  {'reg' if direction == 'input' else 'wire'} {width} {name};"
        for direction, width, name in declarations
    )
    connections = ", ".join(f".{name}({name})" for _, _, name in declarations)
    settings = ", ".join(f".{name}({value})" for name, value in parameters.items())
    initialize = "\n".join(
        f"    {name} = {1 if name in {'uart_rx', 'm_mem_axi_rlast'} else 0};"
        for direction, _, name in declarations if direction == "input" and name != "clk"
    )
    return f"""`timescale 1ns/1ps
module tb;
{signals}
  hammer_v4_top #({settings}) dut ({connections});
  initial clk = 0;
  always #5 clk = ~clk;
  integer comparisons = 0;
  integer cycles = 0;
  integer j;
  reg [31:0] expected;
  reg executing;
  reg [63:0] expected_data;
  integer retirements, load_comparisons;
  always @(posedge clk) begin
    cycles = cycles + 1;
    if (cycles > 500000) $fatal(1, "compact diagnostic cycle bound");
    if (!rst_n) begin
      if (halted !== 1 || uart_tx !== 1 || host_ready !== 0 ||
          boot_ready !== 0 || boot_error !== 0 || host_rsp_valid !== 0)
        $fatal(1, "active-region reset public pin mismatch");
    end else if ((^{{halted,uart_tx,host_ready,boot_ready,boot_error,
                    host_rsp_valid,host_rsp_error,retire_valid}}) === 1'bx)
      $fatal(1, "active public pin X/Z");
    if (executing && rst_n) begin
      if (trap_valid !== 0) $fatal(1,"compact compatibility program trapped");
      if (retire_valid === 1) begin
        retirements = retirements + 1;
        if (retire_priv !== 3) $fatal(1,"compact program privilege");
        if ({parameters["IMEM_WORDS"]} == 1) begin
          if (retire_pc !== 0 || retire_next_pc !== 0 ||
              retire_insn !== 32'h0000006f || retire_rd_we !== 0)
            $fatal(1,"singleton instruction-memory retirement");
        end else begin
          case (retire_pc)
            0: if (retire_insn !== 32'h100002b7 || retire_rd_data !== 64'h10000000)
                 $fatal(1,"compact base-address instruction");
            4: begin
              if (retire_insn !== 32'h0002b303 || retire_rd_data !== expected_data ||
                  retire_mem_valid !== 1 || retire_mem_write !== 0 ||
                  retire_mem_addr !== 64'h10000000 || retire_mem_rdata !== expected_data)
                $fatal(1,"compact backing-data read got=%h expected=%h",
                       retire_rd_data,expected_data);
              load_comparisons = load_comparisons + 1;
            end
            8: if (retire_insn !== 32'hffdff06f || retire_next_pc !== 4)
                 $fatal(1,"compact loop branch");
            default: $fatal(1,"compact program unexpected PC=%h",retire_pc);
          endcase
        end
      end
    end
  end
  always @(negedge clk) if (!rst_n) begin
    if (halted !== 1 || uart_tx !== 1 || host_ready !== 0 ||
        boot_ready !== 0 || boot_error !== 0 || host_rsp_valid !== 0)
      $fatal(1, "falling-edge reset public pin mismatch");
  end
  task automatic transfer(input bit write_enable, input integer address,
                           input [31:0] data, input [31:0] read_expected);
    begin
      @(negedge clk);
      host_valid = 1; host_write = write_enable; host_imem = 1;
      host_addr = address; host_wdata = {{32'b0,data}}; host_wstrb = 8'h0f;
      do @(posedge clk); while (host_ready !== 1);
      @(negedge clk); host_valid = 0;
      do @(posedge clk); while (host_rsp_valid !== 1);
      if (host_rsp_error !== 0) $fatal(1, "host error at %h", address);
      if (!write_enable && host_rdata !== {{32'b0,read_expected}})
        $fatal(1, "host read addr=%h got=%h expected=%h",
               address, host_rdata, read_expected);
      comparisons = comparisons + 1;
    end
  endtask
  task automatic data_transfer(input bit write_enable,
                               input [63:0] data, input [63:0] read_expected);
    begin
      @(negedge clk);
      host_valid = 1; host_write = write_enable; host_imem = 0;
      host_addr = 0; host_wdata = data; host_wstrb = 8'hff;
      do @(posedge clk); while (host_ready !== 1);
      @(negedge clk); host_valid = 0;
      do @(posedge clk); while (host_rsp_valid !== 1);
      if (host_rsp_error !== 0 || (!write_enable && host_rdata !== read_expected))
        $fatal(1,"compact backing-data host transaction");
      comparisons = comparisons + 1;
    end
  endtask
  task automatic run_program;
    begin
      retirements = 0; load_comparisons = 0; executing = 1;
      @(negedge clk); start = 1;
      @(negedge clk); start = 0;
      while (retirements < 16) @(negedge clk);
      halt_req = 1;
      while (halted !== 1) @(negedge clk);
      executing = 0; halt_req = 0;
      if ({parameters["IMEM_WORDS"]} != 1 && load_comparisons == 0)
        $fatal(1,"no compact data-load comparisons");
    end
  endtask
  initial begin
{initialize}
    executing = 0; expected_data = 0; retirements = 0; load_comparisons = 0;
    #1;
    if (halted !== 1 || uart_tx !== 1 || host_ready !== 0 ||
        boot_ready !== 0 || boot_error !== 0 || host_rsp_valid !== 0)
      $fatal(1, "time-zero reset public pin mismatch");
    repeat (3) @(negedge clk);
    rst_n = 1;
    if ({parameters["BOOT_ENABLE"]} == 1) begin
      start = 1;
      repeat (4) @(negedge clk);
      start = 0;
      while (boot_ready !== 1) begin
        if (host_ready !== 0 || host_rsp_valid !== 0 || boot_error !== 0)
          $fatal(1, "loader leaked external host transaction");
        @(negedge clk);
      end
    end else begin
      @(posedge clk); #1;
      if (boot_ready !== 1) $fatal(1, "compatibility ready edge mismatch");
    end
    repeat (16) begin
      @(negedge clk);
      if (halted !== 1 || retire_valid !== 0)
        $fatal(1, "early start queued or spontaneous execution");
    end
    if ({parameters["BOOT_ENABLE"]} == 1) begin
      for (j = 0; j < 32; j = j + 1) begin
        case (j)
          0: expected = (0 << 20) | (10 << 7) | 7'h13;
          1: expected = (32'h043f0 << 12) | (11 << 7) | 7'h37;
          2: expected = (5 << 20) | (11 << 15) | (1 << 12) | (11 << 7) | 7'h13;
          3: expected = (1 << 20) | (5 << 7) | 7'h13;
          4: expected = (31 << 20) | (5 << 15) | (1 << 12) | (5 << 7) | 7'h13;
          5: expected = (5 << 15) | 7'h67;
          default: expected = 7'h13;
        endcase
        transfer(0, j*4, 0, expected);
      end
    end
    transfer(1, 0, 32'h12300293, 0);
    transfer(0, 0, 0, 32'h12300293);
    transfer(1, ({parameters["IMEM_WORDS"]}-1)*4, 32'h00700313, 0);
    transfer(0, ({parameters["IMEM_WORDS"]}-1)*4, 0, 32'h00700313);
    if ({parameters["IMEM_WORDS"]} == 1)
      transfer(1, 0, 32'h0000006f, 0);
    else begin
      transfer(1, 0, 32'h100002b7, 0);
      transfer(1, 4, 32'h0002b303, 0);
      transfer(1, 8, 32'hffdff06f, 0);
    end
    expected_data = 64'h1122334455667788;
    data_transfer(1, expected_data, 0);
    data_transfer(0, 0, expected_data);
    run_program;
    expected_data = 64'h8877665544332211;
    data_transfer(1, expected_data, 0);
    data_transfer(0, 0, expected_data);
    run_program;
    if (comparisons < 4) $fatal(1, "empty comparisons");
    $display("COMPARED host_transactions=%0d cycles=%0d execution_epochs=2 last_retirements=%0d last_loads=%0d",
             comparisons,cycles,retirements,load_comparisons);
    $finish;
  end
endmodule
"""


def configurations():
    cases = [("boot-minimum", DEFAULT)]
    for depth in (1, 3, 16384):
        parameters = dict(DEFAULT, BOOT_ENABLE=0, IMEM_WORDS=depth,
                          DMEM_WORDS=8192 if depth == 16384 else depth)
        cases.append((f"compat-depth-{depth}", parameters))
    for name, values in {
        "PRED_MODE": (0, 1), "BTB_ENTRIES": (1, 4, 16, 64),
        "ICACHE_LINES": (1, 4, 16, 64), "DCACHE_LINES": (1, 4, 16, 64),
        "ITLB_ENTRIES": (1, 4, 8, 16), "DTLB_ENTRIES": (1, 4, 8, 16),
        "LEGACY_TRAPS": (0, 1),
    }.items():
        for value in values:
            cases.append((f"legal-{name}-{value}",
                          dict(DEFAULT, BOOT_ENABLE=0, **{name: value})))
    return cases


def illegal_configurations():
    for name, values in {
        "IMEM_WORDS": (0, -1, 16385), "DMEM_WORDS": (0, -1, 8193),
        "PRED_MODE": (-1, 2), "BTB_ENTRIES": (0, 3, 65),
        "ICACHE_LINES": (0, 3, 65), "DCACHE_LINES": (0, 3, 65),
        "ITLB_ENTRIES": (0, 2, 17), "DTLB_ENTRIES": (0, 2, 17),
        "LEGACY_TRAPS": (-1, 2), "BOOT_ENABLE": (-1, 2),
    }.items():
        for value in values:
            yield f"illegal-{name}-{value}", dict(DEFAULT, **{name: value})
    yield "illegal-boot-small", dict(DEFAULT, IMEM_WORDS=31)
    yield "illegal-boot-legacy", dict(DEFAULT, LEGACY_TRAPS=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build/ directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    records = []
    sources = [str(p.relative_to(ROOT)) for p in sorted((ROOT / "rtl").glob("*.sv"))]
    for illegal, cases in ((False, configurations()), (True, illegal_configurations())):
        for name, parameters in cases:
            directory = out / name
            directory.mkdir()
            tb = directory / "tb.sv"
            tb.write_text(testbench(parameters))
            executable = directory / "sim.vvp"
            commands = [
                ["iverilog", "-g2012", "-Wall", "-s", "tb", "-o",
                 str(executable), *sources, str(tb)],
                ["vvp", str(executable)],
            ]
            record = {"name": name, "parameters": parameters, "illegal": illegal,
                      "commands": commands, "exits": []}
            records.append(record)
            for index, argv in enumerate(commands):
                result = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
                (directory / f"{index}.stdout.log").write_bytes(result.stdout)
                (directory / f"{index}.stderr.log").write_bytes(result.stderr)
                record["exits"].append(result.returncode)
                (out / "results.json").write_text(json.dumps(records, indent=2) + "\n")
                if index == 0:
                    if result.returncode:
                        raise AssertionError(f"{name}: must elaborate; see {directory}")
                elif illegal:
                    if not result.returncode or b"PARAMETER ERROR" not in result.stdout:
                        raise AssertionError(f"{name}: missing executable parameter diagnostic")
                elif result.returncode or b"COMPARED host_transactions=" not in result.stdout:
                    raise AssertionError(f"{name}: functional failure; see {directory}")
    print(f"Compared {len(records)} legal/illegal parameter cases (not a cross-product)")


if __name__ == "__main__":
    main()
