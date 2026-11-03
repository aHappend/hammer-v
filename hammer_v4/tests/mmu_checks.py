#!/usr/bin/env python3
"""Independent public-port Sv39 walks, faults, backpressure and scoped fences.

Expected PTE addresses and translations come from the architectural walk in
architecture.py. No RTL state, replacement pointers or hierarchy is observed.
This compact subsystem test does not qualify as a complete Linux timed oracle.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from architecture import PageFault, walk


MASK = (1 << 64) - 1
ROOT_PPN = 0x81000
SATP = (8 << 60) | ROOT_PPN
VA = 0x12345678
PA = 0x82000


class PhysicalReadFault(Exception):
    pass


def page_tables(va=VA, ppn=PA, level=0, flags=0xCF, nonleaf=1):
    memory = {}
    table = ROOT_PPN
    for current in (2, 1, 0):
        address = table * 4096 + ((va >> (12 + 9 * current)) & 511) * 8
        if current == level:
            memory[address] = (ppn << 10) | flags
            break
        table += 1
        memory[address] = (table << 10) | nonleaf
    return memory


def scenarios():
    commands = []
    coverage = Counter()

    def reset():
        commands.append([0] * 12)

    def translate(memory, *, channel=1, va=VA, satp=SATP, status=0,
                  privilege=1, access=1, bypass=0, bus_error=None,
                  cached=None, drain_fence=False, cancel=False, label):
        reads = []
        effective = ((status >> 11) & 3) if (
            channel == 1 and privilege == 3 and status & (1 << 17)
        ) else privilege

        def read(address):
            error = address == bus_error
            reads.append((address, memory.get(address, 0), int(error)))
            if error:
                raise PhysicalReadFault
            return memory.get(address, 0)

        physical = page_fault = access_fault = 0
        if bypass or effective == 3 or satp >> 60 == 0:
            access_fault = int(va >> 56 != 0)
            physical = va & ((1 << 56) - 1) if not access_fault else 0
        elif cached is not None:
            physical = cached
        else:
            try:
                physical = walk(
                    read, va, satp, ("fetch", "load", "store", "atomic")[access],
                    effective, bool(status & (1 << 18)), bool(status & (1 << 19)),
                ).physical
            except PageFault:
                page_fault = 1
            except PhysicalReadFault:
                access_fault = 1
        commands.append([
            4 if cancel else 3 if drain_fence else 1,
            channel, satp, status, privilege, va, access, bypass,
            physical, page_fault, access_fault, len(reads),
        ])
        commands.extend([*record, *([0] * 9)] for record in reads)
        coverage[label] += 1
        if cancel:
            coverage["cancelled_walks"] += 1
            coverage["pte_reads"] += 1
            return
        if drain_fence:
            coverage["fences"] += 1
            coverage["fences_with_outstanding_walk"] += 1
        coverage["translations"] += 1
        coverage["pte_reads"] += len(reads)
        coverage["expected_page_faults"] += page_fault
        coverage["expected_access_faults"] += access_fault
        coverage["expected_successes"] += not (page_fault or access_fault)
        coverage["instruction_requests" if channel == 0 else "data_requests"] += 1

    def fence(va_valid=0, asid_valid=0, va=0, asid=0):
        commands.append([2, va_valid, asid_valid, va, asid, *([0] * 7)])
        coverage["fences"] += 1

    for level, ppn in ((0, PA), (1, 0x82000), (2, 0x80000)):
        for channel, access in ((0, 0), (1, 1), (1, 2), (1, 3)):
            reset()
            translate(page_tables(ppn=ppn, level=level), channel=channel,
                      access=access, label=f"aligned_leaf_level_{level}")
    for va in (0, (1 << 38) - 4, (1 << 64) - (1 << 38), MASK - 3):
        reset()
        translate(page_tables(va=va), va=va, label="canonical_boundaries")
    for va in (1 << 38, (1 << 64) - (1 << 38) - 1, 1 << 63):
        for channel in (0, 1):
            reset()
            translate({}, va=va, channel=channel, access=0 if channel == 0 else 1,
                      label="noncanonical_no_walk")
    for level in (1, 2):
        reset()
        translate(page_tables(ppn=PA + 1, level=level), label="misaligned_superpage")
    for flags in (0, 1, 0xC5, 0x0F, 0x4F, 0xC3, 0xC9, 0xDF):
        for channel, access in ((0, 0), (1, 1), (1, 2), (1, 3)):
            reset()
            translate(page_tables(flags=flags), channel=channel, access=access,
                      label="pte_permissions_ad")
    for bit in (4, 6, 7, 54, 63):
        reset()
        memory = page_tables()
        memory[min(memory)] |= 1 << bit
        translate(memory, label="reserved_nonleaf")
    for bit in (54, 63):
        reset()
        memory = page_tables()
        memory[max(memory)] |= 1 << bit
        translate(memory, label="reserved_leaf")
    for depth in (0, 1, 2):
        reset()
        memory = page_tables()
        translate(memory, bus_error=sorted(memory)[depth], label="pte_bus_error")
    for privilege, status, flags, access in (
        (0, 0, 0xDF, 1), (0, 0, 0xCF, 1),
        (1, 0, 0xDF, 1), (1, 1 << 18, 0xDF, 1),
        (1, 1 << 18, 0xDF, 0), (1, 0, 0xC9, 1),
        (1, 1 << 19, 0xC9, 1), (1, 1 << 19, 0xC9, 2),
        (3, (1 << 17) | (1 << 11), 0xCF, 1),
        (3, (1 << 17) | (0 << 11), 0xDF, 1),
        (3, (1 << 17) | (0 << 11), 0xCF, 1),
    ):
        reset()
        translate(page_tables(flags=flags), privilege=privilege, status=status,
                  access=access, label="sum_mxr_mprv")
    for channel, privilege, status, bypass, satp in (
        (1, 3, 0, 0, SATP), (0, 3, (1 << 17), 0, SATP),
        (1, 1, 0, 1, SATP), (0, 1, 0, 1, SATP),
        (1, 1, 0, 0, 0), (0, 1, 0, 0, 0),
    ):
        for va in (0x80200000, 1 << 56):
            reset()
            translate({}, channel=channel, privilege=privilege, status=status,
                      bypass=bypass, satp=satp, va=va,
                      access=0 if channel == 0 else 1, label="bare_bypass_bounds")

    # Keep one resident mapping so tests make no assumptions about replacement.
    # Changes are to the external PTE memory, never to the translation cache.
    for channel in (0, 1):
        for level, ppn in ((0, PA), (1, 0x82000), (2, 0x80000)):
            for global_mapping in (False, True):
                reset()
                flags = 0xCF | (0x20 if global_mapping else 0)
                memory = page_tables(level=level, ppn=ppn, flags=flags)
                kwargs = {"channel": channel, "access": 0 if channel == 0 else 1}
                translate(memory, label="cache_initial_fill", **kwargs)
                cached_pa = ppn * 4096 + VA % (4096 * 512 ** level)
                translate({}, cached=cached_pa, label="cache_hit_no_walk", **kwargs)
                # An ASID-selective fence preserves global entries.
                fence(1, 1, VA, 0)
                if global_mapping:
                    translate({}, cached=cached_pa,
                              label="asid_fence_preserves_global", **kwargs)
                else:
                    translate(memory, label="asid_fence_invalidates_local", **kwargs)
                fence(1, 0, VA + 64, 0)
                # Any address within the superpage must invalidate that leaf.
                translate(memory, label="va_fence_invalidates_leaf", **kwargs)
                fence()
                translate(memory, label="full_fence_invalidates_leaf", **kwargs)
        reset()
        kwargs = {"channel": channel, "access": 0 if channel == 0 else 1}
        memory = page_tables(nonleaf=0x21)
        translate(memory, label="ancestor_global_fill", **kwargs)
        fence(1, 1, VA, 0)
        translate({}, cached=PA * 4096 + (VA & 4095),
                  label="ancestor_global_preserved", **kwargs)
        fence()
        translate(memory, label="ancestor_global_full_invalidation", **kwargs)
        reset()
        translate(page_tables(), satp=SATP | (7 << 44), label="nonzero_asid", **kwargs)
        fence(1, 1, VA, 8)
        translate({}, satp=SATP | (7 << 44), cached=PA * 4096 + (VA & 4095),
                  label="other_asid_preserved", **kwargs)
        fence(1, 1, VA, 7)
        translate(page_tables(), satp=SATP | (7 << 44),
                  label="matching_asid_invalidated", **kwargs)
        # satp writes perform the documented conservative full invalidation.
        translate(page_tables(), satp=SATP, label="satp_change_invalidation", **kwargs)
        reset()
        translate(page_tables(), drain_fence=True,
                  label="fence_drains_held_response", **kwargs)
        translate(page_tables(), label="draining_fence_requires_fresh_walk", **kwargs)
        reset()
        translate(page_tables(), cancel=True, label="reset_cancels_ptw", **kwargs)
        translate(page_tables(), label="reset_retry_fresh_walk", **kwargs)
    reset()
    return commands, coverage


TB = r"""`timescale 1ns/1ps
module tb;
  parameter integer ENTRIES=1;
  reg clk=0,rst_n;
  always #5 clk=~clk;
  reg [63:0] satp,mstatus;
  reg [1:0] priv;
  reg i_req_valid,d_req_valid,i_req_bypass,d_req_bypass;
  reg [63:0] i_req_va,d_req_va;
  reg [1:0] d_req_access;
  wire i_req_ready,d_req_ready,i_rsp_valid,d_rsp_valid;
  reg i_rsp_ready,d_rsp_ready;
  wire [55:0] i_rsp_pa,d_rsp_pa;
  wire i_rsp_page_fault,i_rsp_access_fault,d_rsp_page_fault,d_rsp_access_fault;
  reg sfence_valid,sfence_va_valid,sfence_asid_valid;
  reg [63:0] sfence_va;
  reg [15:0] sfence_asid;
  wire sfence_ready;
  wire pt_req_valid,pt_rsp_ready;
  wire [55:0] pt_req_addr;
  wire pt_req_ready = rst_n && !outstanding && cycles%11>=4;
  reg pt_rsp_valid,pt_rsp_error;
  reg [63:0] pt_rsp_rdata;
  reg outstanding;
  reg [55:0] addresses[0:2];
  reg [63:0] ptes[0:2];
  reg errors[0:2];
  integer delay_count,reads,expected_reads,cycles=0;
  integer commands=0,translations=0,fences=0,held=0,cancelled=0,draining=0;
  integer file_handle,fields,index;
  string vector_file;
  reg [63:0] row[0:11];
  reg [63:0] pa_expected;
  reg [63:0] action;
  reg pf_expected,af_expected,channel;
  reg [55:0] held_address;
  reg held_request;
  hammer_v3_mmu #(.ITLB_ENTRIES(ENTRIES),.DTLB_ENTRIES(ENTRIES)) dut(.*);

  task automatic reset_compare;
    begin
      if(i_req_ready !== 0 || d_req_ready !== 0 ||
         i_rsp_valid !== 0 || d_rsp_valid !== 0 ||
         pt_req_valid !== 0 || pt_rsp_ready !== 0 ||
         sfence_ready !== 0 || i_rsp_pa !== 0 || d_rsp_pa !== 0)
        $fatal(1,"MMU_RESET_COMPARISON");
    end
  endtask
  always @(negedge clk) if(!rst_n) reset_compare;
  always @(posedge clk) begin
    cycles=cycles+1;
    if(cycles>200000) $fatal(1,"MMU compact edge bound exhausted");
    if(!rst_n) reset_compare;
  end
  always @(posedge clk or negedge rst_n) begin
    if(!rst_n) begin
      outstanding<=0; pt_rsp_valid<=0; pt_rsp_error<=0; pt_rsp_rdata<=0;
      delay_count<=0; reads<=0; held_request<=0; held_address<=0;
    end else begin
      if(held_request && (pt_req_valid !== 1 || pt_req_addr !== held_address))
        $fatal(1,"MMU_PTE_REQUEST_STABILITY");
      held_request<=pt_req_valid && !pt_req_ready;
      held_address<=pt_req_addr;
      if(pt_req_valid && pt_req_ready) begin
        if(reads>=expected_reads || pt_req_addr !== addresses[reads])
          $fatal(1,"MMU_PTE_ADDRESS_COMPARISON command=%0d read=%0d actual=%h edge=%0d",
                 commands,reads,pt_req_addr,cycles);
        outstanding<=1; delay_count<=1+(cycles%7);
        pt_rsp_rdata<=ptes[reads]; pt_rsp_error<=errors[reads];
        reads<=reads+1;
      end
      if(outstanding && !pt_rsp_valid) begin
        if(delay_count==0) pt_rsp_valid<=1;
        else delay_count<=delay_count-1;
      end
      if(pt_rsp_valid && pt_rsp_ready) begin
        outstanding<=0; pt_rsp_valid<=0;
      end
    end
  end
  task automatic compare_response;
    begin
      if(channel) begin
        if(d_rsp_valid !== 1 || d_rsp_pa !== pa_expected ||
           d_rsp_page_fault !== pf_expected || d_rsp_access_fault !== af_expected ||
           i_rsp_valid !== 0)
          $fatal(1,"MMU_TRANSLATION_COMPARISON command=%0d data actual=%h pf=%b af=%b expected=%h pf=%b af=%b edge=%0d",
                 commands,d_rsp_pa,d_rsp_page_fault,d_rsp_access_fault,
                 pa_expected,pf_expected,af_expected,cycles);
      end else if(i_rsp_valid !== 1 || i_rsp_pa !== pa_expected ||
                  i_rsp_page_fault !== pf_expected || i_rsp_access_fault !== af_expected ||
                  d_rsp_valid !== 0)
        $fatal(1,"MMU_TRANSLATION_COMPARISON command=%0d instruction actual=%h pf=%b af=%b expected=%h pf=%b af=%b edge=%0d",
               commands,i_rsp_pa,i_rsp_page_fault,i_rsp_access_fault,
               pa_expected,pf_expected,af_expected,cycles);
      if(reads != expected_reads || outstanding !== 0)
        $fatal(1,"MMU_PTE_READ_COUNT_COMPARISON");
    end
  endtask
  initial begin
    rst_n=0; satp=0; mstatus=0; priv=1;
    i_req_valid=0;d_req_valid=0;i_req_bypass=0;d_req_bypass=0;
    i_req_va=0;d_req_va=0;d_req_access=1;i_rsp_ready=0;d_rsp_ready=0;
    sfence_valid=0;sfence_va_valid=0;sfence_asid_valid=0;sfence_va=0;sfence_asid=0;
    expected_reads=0;
    #1;reset_compare;
    @(posedge clk);reset_compare;
    if(!$value$plusargs("vectors=%s",vector_file)) $fatal(1,"missing vectors");
    file_handle=$fopen(vector_file,"r");
    if(!file_handle) $fatal(1,"cannot read MMU vectors");
    while(!$feof(file_handle)) begin
      fields=$fscanf(file_handle,"%h %h %h %h %h %h %h %h %h %h %h %h\n",
        row[0],row[1],row[2],row[3],row[4],row[5],
        row[6],row[7],row[8],row[9],row[10],row[11]);
      if(fields==12) begin
        commands=commands+1;
        @(negedge clk);
        if(row[0]==0) begin
          #1;
          rst_n=0; satp=0; reads=0;
          repeat(2) @(negedge clk);
          #1;
          rst_n=1;
        end else if(row[0]==1 || row[0]==3 || row[0]==4) begin : transaction
          action=row[0];
          channel=row[1];satp=row[2];mstatus=row[3];priv=row[4];
          i_req_va=row[5];d_req_va=row[5];d_req_access=row[6];
          i_req_bypass=row[7];d_req_bypass=row[7];
          pa_expected=row[8];pf_expected=row[9];af_expected=row[10];
          expected_reads=row[11];reads=0;
          if(expected_reads>3) $fatal(1,"malformed PTE count");
          for(index=0;index<expected_reads;index=index+1) begin
            fields=$fscanf(file_handle,"%h %h %h %h %h %h %h %h %h %h %h %h\n",
              row[0],row[1],row[2],row[3],row[4],row[5],
              row[6],row[7],row[8],row[9],row[10],row[11]);
            if(fields!=12) $fatal(1,"malformed PTE vector");
            addresses[index]=row[0];ptes[index]=row[1];errors[index]=row[2];
          end
          #1;
          while(i_req_ready !== 1 || d_req_ready !== 1) @(negedge clk);
          if(channel) d_req_valid=1; else i_req_valid=1;
          @(posedge clk);
          if(channel ? d_req_ready !== 1 : i_req_ready !== 1)
            $fatal(1,"MMU_REQUEST_ACCEPTANCE");
          @(negedge clk);i_req_valid=0;d_req_valid=0;
          if(action==3 || action==4) begin
            while(outstanding !== 1) @(negedge clk);
            if(reads!=1 || pt_rsp_valid !== 0)
              $fatal(1,"MMU_OUTSTANDING_WALK_PRECONDITION");
            if(action==4) begin
              #1;rst_n=0;satp=0;
              #1;reset_compare;
              repeat(2) @(negedge clk);
              #1;rst_n=1;
              cancelled=cancelled+1;
              disable transaction;
            end
            sfence_valid=1;sfence_va_valid=0;sfence_asid_valid=0;
            draining=draining+1;
          end
          while(channel ? d_rsp_valid !== 1 : i_rsp_valid !== 1) @(negedge clk);
          repeat(4) begin
            compare_response;
            if(action==3 && (sfence_ready !== 0 ||
               i_req_ready !== 0 || d_req_ready !== 0))
              $fatal(1,"MMU_FENCE_DRAIN_COMPARISON edge=%0d",cycles);
            @(posedge clk);compare_response;
            @(negedge clk);
            held=held+1;
          end
          if(channel) d_rsp_ready=1; else i_rsp_ready=1;
          @(negedge clk);i_rsp_ready=0;d_rsp_ready=0;
          translations=translations+1;
          if(action==3) begin
            while(sfence_ready !== 1) @(negedge clk);
            @(negedge clk);sfence_valid=0;
            while(i_req_ready !== 1 || d_req_ready !== 1) @(negedge clk);
            fences=fences+1;
          end
        end else if(row[0]==2) begin
          sfence_va_valid=row[1];sfence_asid_valid=row[2];
          sfence_va=row[3];sfence_asid=row[4];sfence_valid=1;
          while(sfence_ready !== 1) begin
            #1;
            if(i_req_ready !== 0 || d_req_ready !== 0)
              $fatal(1,"MMU_FENCE_ADMISSION_COMPARISON");
            @(negedge clk);
          end
          @(negedge clk);sfence_valid=0;
          while(i_req_ready !== 1 || d_req_ready !== 1) @(negedge clk);
          fences=fences+1;
        end else $fatal(1,"unknown MMU vector command");
      end else if(!(fields==0 && $feof(file_handle)))
        $fatal(1,"malformed non-EOF MMU vector");
    end
    if(translations<100 || fences<40 || held!=translations*4 ||
       cancelled!=2 || draining!=2)
      $fatal(1,"missing MMU coverage");
    $display("COMPARED MMU translations=%0d fences=%0d held_responses=%0d cancelled_walks=%0d draining_fences=%0d edges=%0d",
             translations,fences,held,cancelled,draining,cycles);
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
    relative, rtl = Path(args.out), Path(args.rtl)
    for name, path in (("--out", relative), ("--rtl", rtl)):
        if path.is_absolute() or ".." in path.parts or (
            path != Path("rtl") and path.parts[:1] != ("build",)
        ):
            parser.error(f"{name} must be a project-relative build/ path or rtl")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    vectors, coverage = scenarios()
    (out / "mmu.vectors").write_text(
        "".join(" ".join(f"{value:x}" for value in row) + "\n" for row in vectors)
    )
    (out / "tb.sv").write_text(TB)
    sources = [rtl / name for name in (
        "hammer_v3_mmu.sv", "hammer_v3_tlb.sv",
        "hammer_v3_ptw.sv", "hammer_v3_page_leaf.sv",
    )]
    records = []
    try:
        for entries in (1, 16):
            directory = out / f"entries-{entries}"
            directory.mkdir()
            commands = []
            if args.simulator in ("iverilog", "both"):
                commands.extend([
                    ["iverilog", "-g2012", "-Wall", "-s", "tb", "-P", f"tb.ENTRIES={entries}",
                     "-o", directory / "sim.vvp", *sources, out / "tb.sv"],
                    ["vvp", directory / "sim.vvp", f"+vectors={out / 'mmu.vectors'}"],
                ])
            if args.simulator in ("verilator", "both"):
                commands.extend([
                    ["verilator", "--binary", "--timing", "--build", "-j", "4", "-Wno-fatal",
                     "--top-module", "tb", f"-GENTRIES={entries}",
                     "--Mdir", directory / "compile-obj", *sources, out / "tb.sv"],
                    [directory / "compile-obj/Vtb", f"+vectors={out / 'mmu.vectors'}"],
                ])
            for index, command in enumerate(commands):
                argv = [str(arg) for arg in command]
                record = {"argv": argv, "cwd": ".", "started_unix": time.time()}
                with (directory / f"{index}.stdout.log").open("wb") as so, (
                    directory / f"{index}.stderr.log"
                ).open("wb") as se:
                    result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
                record.update(ended_unix=time.time(), exit_code=result.returncode)
                records.append(record)
                (out / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
                if result.returncode:
                    raise AssertionError(f"MMU command failed: {relative}/entries-{entries}/{index}")
                if index % 2:
                    text = (directory / f"{index}.stdout.log").read_text()
                    observed = re.search(
                        r"COMPARED MMU translations=(\d+) fences=(\d+) held_responses=(\d+) "
                        r"cancelled_walks=(\d+) draining_fences=(\d+) edges=(\d+)", text
                    )
                    expected = (
                        coverage["translations"], coverage["fences"],
                        4 * coverage["translations"], coverage["cancelled_walks"],
                        coverage["fences_with_outstanding_walk"],
                    )
                    if not observed or tuple(map(int, observed.groups()[:5])) != expected:
                        raise AssertionError("Incomplete functional MMU comparisons")
                    print(f"entries={entries} {text}", end="", flush=True)
    finally:
        for directory in out.glob("entries-*/compile-obj"):
            for pattern in ("*.o", "*.a", "*.gch"):
                for path in directory.glob(pattern):
                    path.unlink()
    (out / "summary.json").write_text(json.dumps({
        "scope": "public MMU/PTW/TLB subsystem, not full Linux timed acceptance",
        "entries": [1, 16], "simulator": args.simulator, "coverage_per_run": coverage,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
