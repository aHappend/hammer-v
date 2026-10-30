#!/usr/bin/env python3
"""Compare frozen memory-path predictions at real RTL request/response pins.

This harness has no processor. It connects the delivered fetch/data paths,
atomic unit, MMU/TLB/PTW, both cache arbiters/caches, router, fabric and AXI
master verbatim. Ordinary accesses, maintenance and physical atomic requests
are compared at their public interfaces. Atomic translation-to-start scheduling
is not covered here. This is not a Linux/core acceptance result.
"""

import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_execution_checks import image
from system_memory import AtomicRequest, MemoryExecution, TranslationRequest
from system_oracle import Clock, Phase, SEEDS, canonical_json, digest


def wrapper():
    top = [
        "input wire clk, rst_n",
        "input wire [63:0] satp",
        "input wire i_valid", "output wire i_ready, i_rsp_valid",
        "input wire [63:0] i_addr",
        "output wire [63:0] i_data",
        "output wire i_error, i_page",
        "input wire d_valid, d_write",
        "input wire [1:0] d_command",
        "input wire a_start, a_word, a_invalidate",
        "input wire [4:0] a_op",
        "input wire [63:0] a_addr, a_operand",
        "output wire a_ready, a_done, a_error",
        "output wire [63:0] a_result",
        "output wire d_ready, d_rsp_valid",
        "input wire [63:0] d_addr, d_wdata",
        "input wire [7:0] d_mask",
        "input wire [1:0] d_size",
        "output wire [63:0] d_data",
        "output wire d_error, d_page",
    ]
    nets, instances = {}, []
    external = set(re.findall(r"\b(?:clk|rst_n|satp|[ida]_[a-z_]+)\b", "\n".join(top)))

    def interface(module):
        source = (ROOT / "rtl" / (module + ".sv")).read_text()
        header = source.split(") (", 1)[1] if ") (" in source else source.split("(", 1)[1]
        header = header.split(");", 1)[0].strip()
        result = []
        for match in re.finditer(
            r"\b(input|output)\s+(?:wire|reg)\s*(\[[^\]]+\])?\s*"
            r"([a-zA-Z0-9_,\s]+?)(?=,\s*(?:input|output)\b|$)", header, re.MULTILINE,
        ):
            direction, width, names = match.groups()
            result.extend((direction, width or "", name.strip())
                          for name in names.replace("\n", "").split(",") if name.strip())
        if not result:
            raise AssertionError(f"Missing interface: {module}")
        return result

    axi = interface("hammer_v3_axi_master")
    for direction, width, name in axi:
        if name.startswith("m_mem_axi_"):
            top.append(f"{direction} wire {width} {name}")
            external.add(name)

    def unit(module, name, pins, parameters=""):
        pins = {"clk": "clk", "rst_n": "rst_n", **pins}
        ports = interface(module)
        if set(pins) != {name for _, _, name in ports}:
            raise AssertionError(f"Incomplete harness wiring for {module}: "
                                 f"{set(pins) ^ {name for _, _, name in ports}}")
        for _, width, pin in ports:
            net = pins[pin]
            if re.fullmatch(r"[a-zA-Z_]\w*", net) and net not in external:
                if net in nets and nets[net] != width:
                    raise AssertionError(f"Inconsistent net width: {net}")
                nets[net] = width
        instances.append(f"{module} {parameters} {name} (" +
                         ", ".join(f".{pin}({pins[pin]})" for _, _, pin in ports) + ");")

    unit("hammer_v3_fetch_path", "fetch", {
        "req_valid": "i_valid", "req_ready": "i_ready", "req_addr": "i_addr",
        "req_cmd": "2'b0", "rsp_valid": "i_rsp_valid", "rsp_ready": "1'b1",
        "rsp_rdata": "i_data", "rsp_error": "i_error", "rsp_page_fault": "i_page",
        "tr_valid": "it_valid", "tr_ready": "it_ready", "tr_va": "it_va",
        "tr_rsp_valid": "it_rsp_valid", "tr_rsp_ready": "it_rsp_ready",
        "tr_pa": "it_pa", "tr_page_fault": "it_page", "tr_access_fault": "it_error",
        "cache_valid": "fi_valid", "cache_ready": "ia_ready[0]",
        "cache_addr": "fi_addr", "cache_cmd": "fi_cmd",
        "cache_rsp_valid": "ia_rsp_valid[0]", "cache_rsp_ready": "fi_rsp_ready",
        "cache_rdata": "ia_data[63:0]", "cache_error": "ia_error[0]",
    })
    unit("hammer_v3_data_path", "data", {
        "req_valid": "a_live ? atom_valid : d_valid", "req_physical": "a_live && 1'b1",
        "req_ready": "path_ready",
        "req_addr": "a_live ? atom_addr : d_addr",
        "req_wdata": "a_live ? atom_wdata : d_wdata",
        "req_wstrb": "a_live ? atom_mask : d_mask",
        "req_cmd": "a_live ? atom_cmd : (d_command[1] ? d_command : {1'b0,d_write})",
        "req_size": "a_live ? (a_word_q ? 2'd2 : 2'd3) : d_size",
        "req_access": "d_write ? 2'd2 : 2'd1",
        "rsp_valid": "path_rsp_valid", "rsp_ready": "a_live ? atom_rsp_ready : 1'b1",
        "rsp_rdata": "d_data", "rsp_error": "d_error", "rsp_page_fault": "d_page",
        "at_req_valid": "1'b0", "at_req_ready": "", "at_req_va": "64'b0",
        "at_req_access": "2'b0", "at_rsp_valid": "", "at_rsp_ready": "1'b1",
        "at_rsp_pa": "", "at_rsp_error": "", "at_rsp_page_fault": "",
        "tr_valid": "dt_valid", "tr_ready": "dt_ready", "tr_va": "dt_va",
        "tr_access": "dt_access", "tr_rsp_valid": "dt_rsp_valid",
        "tr_rsp_ready": "dt_rsp_ready", "tr_pa": "dt_pa",
        "tr_page_fault": "dt_page", "tr_access_fault": "dt_error",
        "out_valid": "rt_valid", "out_ready": "rt_ready", "out_addr": "rt_addr",
        "out_wdata": "rt_wdata", "out_wstrb": "rt_mask", "out_cmd": "rt_cmd",
        "out_size": "rt_size", "out_rsp_valid": "rt_rsp_valid",
        "out_rsp_ready": "rt_rsp_ready", "out_rdata": "rt_data", "out_error": "rt_error",
    })
    unit("hammer_v3_atomic", "atomic_unit", {
        "start": "a_start && a_ready", "ready": "atom_ready",
        "op": "a_op", "word_op": "a_word", "addr": "a_addr", "operand": "a_operand",
        "invalidate": "a_invalidate", "store_commit": "1'b0", "store_addr": "64'b0",
        "done": "a_done", "consume": "1'b1", "error": "a_error",
        "cause": "", "tval": "", "result": "a_result", "old_data": "",
        "mem_write": "", "wmask": "", "wdata": "",
        "req_valid": "atom_valid", "req_ready": "path_ready && a_live",
        "req_cmd": "atom_cmd", "req_addr": "atom_addr", "req_wdata": "atom_wdata",
        "req_wstrb": "atom_mask", "rsp_valid": "path_rsp_valid && a_live",
        "rsp_ready": "atom_rsp_ready", "rsp_rdata": "d_data", "rsp_error": "d_error",
    })
    unit("hammer_v3_mmu", "mmu", {
        "satp": "satp", "mstatus": "64'b0", "priv": "2'b0",
        "i_req_valid": "it_valid", "i_req_ready": "it_ready", "i_req_va": "it_va",
        "i_req_bypass": "1'b0", "i_rsp_valid": "it_rsp_valid",
        "i_rsp_ready": "it_rsp_ready", "i_rsp_pa": "it_pa",
        "i_rsp_page_fault": "it_page", "i_rsp_access_fault": "it_error",
        "d_req_valid": "dt_valid", "d_req_ready": "dt_ready", "d_req_va": "dt_va",
        "d_req_access": "dt_access", "d_req_bypass": "1'b0",
        "d_rsp_valid": "dt_rsp_valid", "d_rsp_ready": "dt_rsp_ready", "d_rsp_pa": "dt_pa",
        "d_rsp_page_fault": "dt_page", "d_rsp_access_fault": "dt_error",
        "sfence_valid": "1'b0", "sfence_ready": "", "sfence_va_valid": "1'b0",
        "sfence_asid_valid": "1'b0", "sfence_va": "64'b0", "sfence_asid": "16'b0",
        "pt_req_valid": "pt_valid", "pt_req_ready": "da_ready[1]",
        "pt_req_addr": "pt_addr", "pt_rsp_valid": "da_rsp_valid[1]",
        "pt_rsp_ready": "pt_rsp_ready", "pt_rsp_rdata": "da_data[127:64]",
        "pt_rsp_error": "da_error[1]",
    })
    unit("hammer_v3_data_router", "router", {
        "req_valid": "rt_valid", "req_ready": "rt_ready", "req_addr": "rt_addr",
        "req_wdata": "rt_wdata", "req_wstrb": "rt_mask", "req_cmd": "rt_cmd",
        "req_size": "rt_size", "rsp_valid": "rt_rsp_valid", "rsp_ready": "rt_rsp_ready",
        "rsp_rdata": "rt_data", "rsp_error": "rt_error",
        "target_valid": "route_valid", "target_ready": "{4'b0,da_ready[0]}",
        "target_addr": "route_addr", "target_wdata": "route_wdata",
        "target_wstrb": "route_mask", "target_cmd": "route_cmd", "target_size": "",
        "target_rsp_valid": "{4'b0,da_rsp_valid[0]}",
        "target_rsp_ready": "route_rsp_ready", "target_rsp_error": "{4'b0,da_error[0]}",
        "target_rdata": "{256'b0,da_data[63:0]}",
    })
    for kind in ("i", "d"):
        instruction = kind == "i"
        unit("hammer_v3_cache_arbiter", kind + "_arbiter", {
            "req_valid": "{2'b0,fi_valid}" if instruction else "{1'b0,pt_valid,route_valid[0]}",
            "req_ready": kind + "a_ready",
            "req_cmd": "{4'b0,fi_cmd}" if instruction else "{4'b0,route_cmd}",
            "req_addr": "{128'b0,fi_addr}" if instruction else "{64'b0,8'b0,pt_addr,route_addr}",
            "req_wdata": "192'b0" if instruction else "{128'b0,route_wdata}",
            "req_wstrb": "24'b0" if instruction else "{16'b0,route_mask}",
            "rsp_valid": kind + "a_rsp_valid", "rsp_error": kind + "a_error",
            "rsp_ready": "{2'b0,fi_rsp_ready}" if instruction else
                         "{1'b0,pt_rsp_ready,route_rsp_ready[0]}",
            "rsp_rdata": kind + "a_data", "out_valid": kind + "c_valid",
            "out_ready": kind + "c_ready", "out_cmd": kind + "c_cmd",
            "out_addr": kind + "c_addr", "out_wdata": kind + "c_wdata",
            "out_wstrb": kind + "c_mask", "out_rsp_valid": kind + "c_rsp_valid",
            "out_rsp_ready": kind + "c_rsp_ready", "out_rsp_rdata": kind + "c_data",
            "out_rsp_error": kind + "c_error",
        })
        unit("hammer_v3_icache" if instruction else "hammer_v3_dcache", kind + "_cache", {
            "req_valid": kind + "c_valid", "req_ready": kind + "c_ready",
            "req_cmd": kind + "c_cmd", "req_addr": kind + "c_addr",
            "req_wdata": kind + "c_wdata", "req_wstrb": kind + "c_mask",
            "rsp_valid": kind + "c_rsp_valid", "rsp_ready": kind + "c_rsp_ready",
            "rsp_rdata": kind + "c_data", "rsp_error": kind + "c_error",
            "mem_valid": kind + "b_valid", "mem_write": kind + "b_write",
            "mem_addr": kind + "b_addr", "mem_wdata": kind + "b_wdata",
            "mem_wstrb": kind + "b_mask", "mem_rsp_ready": kind + "b_rsp_ready",
            "mem_ready": "back_ready[0]" if instruction else "back_ready[1]",
            "mem_rsp_valid": "back_rsp_valid[0]" if instruction else "back_rsp_valid[1]",
            "mem_rdata": "back_data[63:0]" if instruction else "back_data[127:64]",
            "mem_error": "back_error[0]" if instruction else "back_error[1]",
        }, "#(.LINES(4))")
    unit("hammer_v3_fabric", "fabric", {
        "req_valid": "{1'b0,db_valid,ib_valid}", "req_write": "{1'b0,db_write,ib_write}",
        "req_ready": "back_ready", "req_addr": "{64'b0,db_addr,ib_addr}",
        "req_wdata": "{64'b0,db_wdata,ib_wdata}", "req_wstrb": "{8'b0,db_mask,ib_mask}",
        "req_prot": "9'b0", "rsp_valid": "back_rsp_valid", "rsp_error": "back_error",
        "rsp_decerr": "", "rsp_ready": "{1'b0,db_rsp_ready,ib_rsp_ready}",
        "rsp_rdata": "back_data", "h_imem": "1'b0", "h_dmem": "1'b0",
        "h_write": "1'b0", "h_addr": "32'b0", "h_wdata": "64'b0", "h_wstrb": "8'b0",
        "h_imem_data": "", "h_dmem_data": "", "mem_valid": "mem_valid",
        "mem_ready": "mem_ready", "mem_write": "mem_write", "mem_addr": "mem_addr",
        "mem_wdata": "mem_wdata", "mem_wstrb": "mem_mask", "mem_prot": "mem_prot",
        "mem_rsp_valid": "mem_rsp_valid", "mem_error": "mem_error",
        "mem_decerr": "mem_decerr", "mem_rsp_ready": "mem_rsp_ready", "mem_rdata": "mem_data",
    })
    unit("hammer_v3_axi_master", "axi", {
        "req_valid": "mem_valid", "req_ready": "mem_ready", "req_write": "mem_write",
        "req_addr": "mem_addr", "req_wdata": "mem_wdata", "req_wstrb": "mem_mask",
        "req_prot": "mem_prot", "rsp_valid": "mem_rsp_valid", "rsp_ready": "mem_rsp_ready",
        "rsp_rdata": "mem_data", "rsp_error": "mem_error", "rsp_decerr": "mem_decerr",
        **{name: name for _, _, name in axi if name.startswith("m_mem_axi_")},
    })
    arbitration = """
reg a_live, a_word_q, d_busy;
assign a_ready = atom_ready && !d_busy && !d_valid;
assign d_ready = path_ready && !a_live;
assign d_rsp_valid = path_rsp_valid && !a_live;
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        a_live <= 0;
        a_word_q <= 0;
        d_busy <= 0;
    end else begin
        if (d_valid && d_ready) d_busy <= 1;
        if (d_rsp_valid) d_busy <= 0;
        if (a_start && a_ready) begin
            a_live <= 1;
            a_word_q <= a_word;
        end
        if (a_done) a_live <= 0;
    end
end
"""
    return "module memory_path (\n" + ",\n".join(top) + "\n);\n" + \
        "\n".join(f"wire {width} {name};" for name, width in nets.items()) + \
        "\n" + arbitration + "\n".join(instances) + "\nendmodule\n"


def predict(seed, directory):
    clock = Clock()
    model = MemoryExecution(clock, seed, image(), cache_lines=4)
    satp = (8 << 60) | (0x80010000 >> 12)
    events, requests = [], []
    # Each independent requester advances only after its own predicted reply.
    # These first edges are frozen before compiling or launching the DUT.
    programs = (
        [(0x400000 + 4 * index, "fetch", 4, 0) for index in range(6)],
        [(0x800001, "store", 1, 42), (0x800001, "load", 1, 0),
         (0x800008, "store", 8, 0xFFEEDDCCBBAA9988), (0x800008, "load", 8, 0),
         (0x800080, "load", 8, 0), (0x800008, "load", 8, 0),
         (0xA00000, "load", 8, 0),
         (0x800008, "store", 8, 0x123456789ABCDEF0),
         (0, "clean", 8, 0), (0x800008, "load", 8, 0),
         (0, "invalidate", 8, 0), (0x800008, "load", 8, 0),
         (0x80300008, "amoadd", 8, 5), (0x80300008, "lr", 8, 0),
         (0x80300008, "sc", 8, 0xFFEEDDCCBBAA9988), (0x80300008, "sc", 8, 7),
         (0x8030000C, "lr", 4, 0), (0x80300008, "sc", 4, 7),
         (0x8030000C, "lr", 4, 0), (0x8030000C, "sc", 4, 0xFEDCBA98),
         (0x80300008, "lr", 8, 0), (0x80300008, "sc-invalidated", 8, 7),
         (0x8030000C, "amomin", 4, 0x80000000), (0x800008, "load", 8, 0)],
    )

    def issue(port, index, edge):
        address, access, width, value = programs[port][index]
        maintenance = access in ("clean", "invalidate")
        atomic = access in ("amoadd", "lr", "sc", "sc-invalidated", "amomin")
        operation = {"amoadd": 0, "lr": 2, "sc": 3, "sc-invalidated": 3, "amomin": 16}.get(access)
        command = 4 + operation if atomic else {"clean": 2, "invalidate": 3}.get(access, 0)
        requests.append((port, edge, address, width, int(access == "store"), value, command,
                         int(access == "sc-invalidated")))

        def received(reply):
            events.append((port, index, reply.edge, reply.data, int(reply.error),
                           int(reply.page_fault)))
            if index + 1 < len(programs[port]):
                issue(port, index + 1, reply.edge + 2)
        if maintenance:
            model.maintenance.submit(0, edge, (False, access == "invalidate"), received)
        elif atomic:
            if access == "sc-invalidated":
                model.invalidate_reservation(edge)
            kind = "load" if operation == 2 else "store" if operation == 3 else "atomic"
            model.atomic_physical.submit(
                0, edge, AtomicRequest(TranslationRequest(address, kind, 0, 0, 3),
                                       width, value, operation), received)
        else:
            request = TranslationRequest(address, access, satp, 0, 0)
            model.ports[port].submit(0, edge, (request, width, value), received)
    for port in (0, 1):
        issue(port, 0, 32)
    clock.run(100000)
    if len(events) != sum(map(len, programs)) or model.translation.pte_reads < 6 or \
            not model.dcache.writebacks or not any(event[-1] for event in events) or \
            model.backing.ram.memory[0x300008:0x300010] != \
            bytes.fromhex("f0debc9a78563412") or \
            model.dcache.hits < 2:
        raise AssertionError("Missing simultaneous walks, dirty eviction or page fault")
    if events[-1][3] != 0x80000000BBAA9988 or \
            sum(event[0] == 1 and event[3] == 1 for event in events) != 3:
        raise AssertionError("Atomic old data, failed SC or byte-preserving AMO comparison failed")
    (directory / "requests.txt").write_text(
        "".join(" ".join(map(str, record)) + "\n" for record in sorted(requests, key=lambda x: x[1])))
    (directory / "expected.txt").write_text(
        "".join(" ".join(map(str, record)) + "\n" for record in sorted(events, key=lambda x: x[2])))
    return events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    (out / "memory_path.sv").write_text(wrapper())
    for name, address, data in image():
        (out / (name + ".bin")).write_bytes(data)
    for seed in SEEDS:
        directory = out / str(seed)
        directory.mkdir()
        predict(seed, directory)
    frozen_paths = [out / "memory_path.sv", out / "tables.bin", out / "code.bin",
                    *(path for seed in SEEDS for path in (out / str(seed)).iterdir())]
    frozen = {path.relative_to(out).as_posix(): digest(path) for path in frozen_paths}
    records = []

    def run(argv):
        index = len(records)
        record = {"argv": list(map(str, argv)), "cwd": ".", "started_unix": time.time()}
        records.append(record)
        try:
            with (out / f"{index}.stdout.log").open("wb") as so, (
                out / f"{index}.stderr.log"
            ).open("wb") as se:
                record["exit_code"] = subprocess.run(
                    record["argv"], cwd=ROOT, stdout=so, stderr=se, check=False).returncode
            if record["exit_code"]:
                raise AssertionError(f"Memory-path tool command {index} failed: {relative}")
        finally:
            record["ended_unix"] = time.time()
            (out / "commands.json").write_bytes(canonical_json(records))
        return out / f"{index}.stdout.log"

    obj = out / "compile-obj"
    try:
        run(["verilator", "-O3", "--cc", "--exe", "--build", "-j", "4", "-Wno-fatal",
             "--top-module", "memory_path", "--Mdir", obj.relative_to(ROOT),
             "-CFLAGS", "-O3 -std=c++17",
             *[path.relative_to(ROOT) for path in sorted((ROOT / "rtl").glob("*.sv"))],
             (out / "memory_path.sv").relative_to(ROOT),
             Path(*([".."] * len(obj.relative_to(ROOT).parts))) /
             "tests/system_memory_probe.cpp", "-MAKEFLAGS", "OPT_FAST=-O3"])
        executable = out / "memory-path"
        shutil.copyfile(obj / "Vmemory_path", executable)
        executable.chmod(0o755)
        for seed in SEEDS:
            directory = out / str(seed)
            actual = run([executable.relative_to(ROOT), seed, directory.relative_to(ROOT),
                          relative])
            if actual.read_bytes() != (directory / "expected.txt").read_bytes():
                raise AssertionError(f"MEMORY_PATH_TIMING_VALUE_COMPARISON seed={seed}; "
                                     f"actual={actual.relative_to(ROOT)} "
                                     f"expected={(directory / 'expected.txt').relative_to(ROOT)}")
        if frozen != {path: digest(out / path) for path in frozen}:
            raise AssertionError("RTL execution changed frozen memory-path predictions")
        (out / "summary.json").write_bytes(canonical_json({
            "scope": "public-pin memory-path timing/value diagnostic; no core/Linux",
            "seeds": list(SEEDS), "responses_compared": 90, "frozen_inputs": frozen,
            "maintenance": "dirty clean retains line; invalidate/refill preserves stored bytes",
            "atomics": "physical atomic-unit/cache path; not core atomic-translation timing",
            "dut_execution": True, "full_system_timed_oracle": False,
        }))
    finally:
        for pattern in ("*.o", "*.a", "*.gch"):
            for path in obj.glob(pattern):
                path.unlink()
    print("COMPARED 90 frozen cache/maintenance/physical-atomic/PTW/fabric response edges "
          "and values for seeds 11/29/47; no core/Linux acceptance")


if __name__ == "__main__":
    main()
