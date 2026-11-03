"""Separate legal elaboration/reset and executable illegal-parameter diagnostics."""
import hashlib
import json

from evidence import ROOT, digest
from integration import ports

DEFAULT = {
    "IMEM_WORDS": 16384, "DMEM_WORDS": 8192, "PRED_MODE": 1,
    "BTB_ENTRIES": 16, "ICACHE_LINES": 64, "DCACHE_LINES": 64,
    "LEGACY_TRAPS": 0, "ITLB_ENTRIES": 8, "DTLB_ENTRIES": 8,
    "BOOT_ENABLE": 1, "L2_SETS": 64, "PREFETCH_ENABLE": 1,
}


def matrix():
    legal = [DEFAULT.copy()]
    compact = {**DEFAULT, "IMEM_WORDS": 1, "DMEM_WORDS": 1,
               "BTB_ENTRIES": 1, "ICACHE_LINES": 1, "DCACHE_LINES": 1,
               "ITLB_ENTRIES": 1, "DTLB_ENTRIES": 1, "BOOT_ENABLE": 0,
               "L2_SETS": 1}
    legal.extend((compact, {**compact, "IMEM_WORDS": 32, "BOOT_ENABLE": 1},
                  {**DEFAULT, "IMEM_WORDS": 33, "DMEM_WORDS": 3},
                  {**DEFAULT, "BTB_ENTRIES": 64, "ITLB_ENTRIES": 16, "DTLB_ENTRIES": 16}))
    for key in ("BTB_ENTRIES", "ICACHE_LINES", "DCACHE_LINES", "L2_SETS"):
        legal.extend({**DEFAULT, key: value} for value in (1, 4, 16, 64))
    for key in ("ITLB_ENTRIES", "DTLB_ENTRIES"):
        legal.extend({**DEFAULT, key: value} for value in (1, 4, 8, 16))
    for key in ("PRED_MODE", "BOOT_ENABLE", "PREFETCH_ENABLE"):
        legal.extend({**DEFAULT, key: value} for value in (0, 1))
    legal.append({**DEFAULT, "LEGACY_TRAPS": 1, "BOOT_ENABLE": 0})
    illegal = []
    for key in ("IMEM_WORDS", "DMEM_WORDS"):
        illegal.extend({**DEFAULT, key: value} for value in (0, DEFAULT[key] + 1))
    for key in ("BTB_ENTRIES", "ICACHE_LINES", "DCACHE_LINES", "L2_SETS"):
        illegal.extend({**DEFAULT, key: value} for value in (0, 2, 65))
    for key in ("ITLB_ENTRIES", "DTLB_ENTRIES"):
        illegal.extend({**DEFAULT, key: value} for value in (0, 2, 17))
    for key in ("PRED_MODE", "LEGACY_TRAPS", "BOOT_ENABLE", "PREFETCH_ENABLE"):
        illegal.extend({**DEFAULT, key: value} for value in (-1, 2))
    illegal.extend(({**DEFAULT, "IMEM_WORDS": 1},
                    {**DEFAULT, "LEGACY_TRAPS": 1}))
    unique = {json.dumps(row, sort_keys=True): row for row in legal}
    return list(unique.values()), illegal


def parameter_probe(ev):
    interface = ports(ROOT / "rtl/hammer_v5_top.sv")
    declarations = []
    for direction, width, name in interface:
        initial = "" if direction == "output" or name == "rst_n" else "=0"
        declarations.append(f"{'reg' if direction == 'input' else 'wire'} "
                            f"{width} {name}{initial};")
    common = "\n".join(declarations)
    legal, illegal = matrix()
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    sources = sorted((ROOT / "rtl").glob("*.sv"))
    observations = []
    for passing, rows in ((True, legal), (False, illegal)):
        for row in rows:
            key = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()[:16]
            tb = ev.directory / f"parameters-{key}.sv"
            tb.write_text("module parameter_tb;\n" + common +
                          "\nalways #5 clk=~clk;\nhammer_v5_top #(" +
                          ",".join(f".{name}({value})" for name, value in row.items()) +
                          ") dut(.*);\n" + r"""
task check_reset;
begin
 if({retire_valid,trap_valid,host_ready,host_rsp_valid,host_rsp_error,
     boot_ready,boot_error,m_mem_axi_awvalid,m_mem_axi_wvalid,m_mem_axi_arvalid,
     s_acc_axi_awready,s_acc_axi_wready,s_acc_axi_arready,s_acc_axi_bvalid,
     s_acc_axi_rvalid} !== 15'b0 || halted !== 1'b1 || uart_tx !== 1'b1)
  $fatal(1,"parameter reset leakage");
end
endtask
always @(posedge clk or negedge clk) if(!rst_n) check_reset();
initial begin
 rst_n=0; uart_rx=1; #0; check_reset(); #21;
 $display("SUMMARY parameter reset/elaboration complete"); $finish;
end
endmodule
""")
            binary = ev.directory / f"parameters-{key}.vvp"
            ev.record.setdefault("generated_sha256", {})[ev.relative(tb)] = digest(tb)
            ev.run(["iverilog", "-g2012", "-Wall", "-s", "parameter_tb", "-o",
                    ev.relative(binary), ev.relative(tb), *map(ev.relative, sources)],
                   "parameter-" + key + "-compile")
            text = ev.run(["vvp", ev.relative(binary)], "parameter-" + key + "-run",
                          expected_exit=0 if passing else 1)
            required = ("SUMMARY parameter reset/elaboration complete" if passing
                        else "PARAMETER ERROR")
            if required not in text:
                raise AssertionError("parameter case lacks its required executable diagnostic")
            observations.append({"parameters": row, "legal": passing,
                                 "compiled": True, "diagnostic": required})
            ev.record["observed"] = observations
            ev.save()
