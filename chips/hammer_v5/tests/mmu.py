"""Sv39 architectural walk oracle and real PTW transaction comparisons."""
import random
import re
import shutil

from evidence import ROOT, digest


def translate(va, root, privilege, access, sum_enabled, mxr, memory, errors=()):
    sign = (va >> 38) & 1
    if va >> 39 != ((1 << 25) - 1 if sign else 0):
        return 0, 1, 0, 0, 2, 0, []
    addresses = []
    inherited_global = False
    table = root
    for level in (2, 1, 0):
        address = (table << 12) + (((va >> (12 + 9 * level)) & 511) * 8)
        addresses.append(address)
        if address in errors:
            return 0, 0, 1, 0, level, 0, addresses
        pte = memory.get(address, 0)
        flags, ppn = pte & 255, (pte >> 10) & ((1 << 44) - 1)
        valid, read, write, execute, user, global_page, accessed, dirty = (
            bool(flags & (1 << bit)) for bit in range(8))
        if not valid or (write and not read) or pte >> 54:
            return 0, 1, 0, 0, level, 0, addresses
        if not read and not execute:
            if user or accessed or dirty or level == 0:
                return 0, 1, 0, 0, level, 0, addresses
            inherited_global |= global_page
            table = ppn
            continue
        permission = (execute if access == 0 else read or (mxr and execute) if access == 1
                      else write if access == 2 else read and write)
        privilege_allowed = user if privilege == 0 else (
            not user or (sum_enabled and access != 0)) if privilege == 1 else True
        page_size = 1 << (12 + 9 * level)
        aligned = (ppn << 12) & (page_size - 1) == 0
        if (not permission or not privilege_allowed or not aligned or not accessed or
                (access in (2, 3) and not dirty)):
            return 0, 1, 0, 0, level, 0, addresses
        pa = (ppn << 12) | (va & (page_size - 1))
        return pa, 0, 0, ppn, level, flags | (32 if inherited_global else 0), addresses
    raise AssertionError("Sv39 walk exceeded three levels")


TB = r"""
module walk_tb;
reg clk=0;
always #5 clk=~clk;
reg rst_n,req_valid=0,rsp_ready=0;
reg [63:0] req_va=0;
reg [43:0] req_root_ppn=0;
reg [15:0] req_asid=0;
reg [1:0] req_access=0,req_priv=0;
reg req_sum=0,req_mxr=0;
wire req_ready,rsp_valid,rsp_page_fault,rsp_access_fault;
wire [55:0] rsp_pa;
wire [43:0] rsp_ppn;
wire [1:0] rsp_level;
wire [7:0] rsp_flags;
wire [63:0] rsp_va;
wire [15:0] rsp_asid;
wire mem_req_valid,mem_rsp_ready;
wire [55:0] mem_req_addr;
reg mem_req_ready=0,mem_rsp_valid=0,mem_rsp_error=0;
reg [63:0] mem_rsp_rdata=0;
hammer_v3_ptw dut(.*);
integer f,n,walks,level,page,access_error,flags,compared=0,lookups=0,j,k,waited;
reg [63:0] va,root,asid,access,privilege,sum_enabled,mxr,pa,ppn;
reg [63:0] addresses[0:2],ptes[0:2],errors[0:2];
reg [1023:0] cases;
task reset_check;
begin
 if({req_ready,rsp_valid,rsp_pa,rsp_page_fault,rsp_access_fault,rsp_ppn,
     rsp_level,rsp_flags,rsp_va,rsp_asid,mem_req_valid,mem_req_addr,mem_rsp_ready}
      !== 252'b0) $fatal(1,"PTW RESET");
end
endtask
always @(posedge clk or negedge clk) if(!rst_n) reset_check();
initial begin
 rst_n=0; #0; reset_check(); #21; rst_n=1;
 if(!$value$plusargs("cases=%s",cases)) cases="walks.txt";
 f=$fopen(cases,"r"); if(!f) $fatal(1,"missing independent Sv39 walk cases");
 while(!$feof(f)) begin
  n=$fscanf(f,"%h %h %h %d %d %d %d %h %d %d %h %d %h %d %h %h %d %h %h %d %h %h %d\n",
    va,root,asid,access,privilege,sum_enabled,mxr,pa,page,access_error,ppn,level,flags,
    walks,addresses[0],ptes[0],errors[0],addresses[1],ptes[1],errors[1],
    addresses[2],ptes[2],errors[2]);
  if(n!=23) $fatal(1,"malformed independent Sv39 case");
  @(negedge clk); req_va=va; req_root_ppn=root[43:0]; req_asid=asid[15:0];
  req_access=access[1:0]; req_priv=privilege[1:0];
  req_sum=sum_enabled[0]; req_mxr=mxr[0]; req_valid=1;
  #1; if(req_ready !== 1) $fatal(1,"PTW missing idle ready");
  @(posedge clk); if(rsp_valid !== 0) $fatal(1,"PTW premature response");
  #1; req_valid=0;
  for(j=0;j<walks;j=j+1) begin
   waited=0;
   while(mem_req_valid !== 1) begin
    @(negedge clk); waited=waited+1;
    if(waited>100) $fatal(1,"PTW missing page-table read");
   end
   repeat(2) begin
    if(mem_req_addr !== addresses[j][55:0] || rsp_valid !== 0)
     $fatal(1,"PTW ADDRESS MISMATCH case=%d level=%d expected=%h observed=%h",
       compared,j,addresses[j],mem_req_addr);
    @(negedge clk);
   end
   mem_req_ready=1;
   @(posedge clk); #1; mem_req_ready=0;
   if(mem_req_valid !== 0 || mem_rsp_ready !== 1) $fatal(1,"PTW transfer boundary");
   repeat(2) @(negedge clk);
   mem_rsp_rdata=ptes[j]; mem_rsp_error=errors[j][0]; mem_rsp_valid=1;
   @(posedge clk); #1;
   mem_rsp_rdata=0; mem_rsp_error=0; mem_rsp_valid=0; lookups=lookups+1;
  end
  waited=0;
  while(rsp_valid !== 1) begin
   @(negedge clk); waited=waited+1;
   if(mem_req_valid !== 0 || waited>100) $fatal(1,"PTW unexpected/missing walk");
  end
  repeat(3) begin
   if(rsp_pa !== pa[55:0] || rsp_page_fault !== (page!=0) ||
      rsp_access_fault !== (access_error!=0) || rsp_ppn !== ppn[43:0] ||
      rsp_level !== level[1:0] || rsp_flags !== flags[7:0] ||
      rsp_va !== va || rsp_asid !== asid[15:0] || req_ready !== 0)
    $fatal(1,"PTW MISMATCH case=%d expected_pa=%h observed=%h faults=%b",
      compared,pa,rsp_pa,{rsp_page_fault,rsp_access_fault});
   @(negedge clk);
  end
  rsp_ready=1;
  @(posedge clk); if(rsp_valid !== 1) $fatal(1,"PTW missing transfer");
  #1; rsp_ready=0;
  if(rsp_valid !== 0 || req_ready !== 1 || rsp_pa !== 0)
   $fatal(1,"PTW duplicated/stale response");
  compared=compared+1;
 end
 $fclose(f);
 $display("SUMMARY PTW compared=%d page_table_reads=%d",compared,lookups);
 $finish;
end
initial begin #50000000; $fatal(1,"PTW CYCLE LIMIT 5000000"); end
endmodule
"""


def walk_cases():
    rows = []
    rng = random.Random(43)

    def build(flags, level, privilege, access, sum_enabled, mxr,
              va=0x400123, misaligned=False, nonleaf_extra=0, error_level=None):
        root, target = 0x81000, 0x80000 if level else 0x81234
        if misaligned:
            target |= 1
        memory, error_addresses = {}, set()
        table = root
        for depth in (2, 1, 0):
            address = (table << 12) + (((va >> (12 + 9 * depth)) & 511) * 8)
            memory[address] = ((target << 10) | flags) if depth == level else (
                ((table + 1) << 10) | 1 | nonleaf_extra)
            if depth == error_level:
                error_addresses.add(address)
            if depth == level:
                break
            table += 1
        pa, page, error, ppn, actual_level, actual_flags, addresses = translate(
            va, root, privilege, access, sum_enabled, mxr, memory, error_addresses)
        beats = [(address, memory.get(address, 0), int(address in error_addresses))
                 for address in addresses]
        beats += [(0, 0, 0)] * (3 - len(beats))
        rows.append((va, root, rng.randrange(65536), access, privilege, sum_enabled,
                     mxr, pa, page, error, ppn, actual_level, actual_flags, len(addresses),
                     *(value for beat in beats for value in beat)))

    for level in range(3):
        for privilege in (0, 1):
            for access in range(4):
                flags = 0xDF if privilege == 0 else 0xCF
                build(flags, level, privilege, access, 0, 0)
                build(flags, level, privilege, access, 0, 0,
                      va=0xFFFFFFC000001123)
                build(flags, level, privilege, access, 0, 0,
                      va=0x8000000000)
                build(flags, level, privilege, access, 0, 0, misaligned=True)
                build(flags, level, privilege, access, 0, 0, error_level=level)
                build(flags, level, privilege, access, 0, 0, nonleaf_extra=32)
                if level < 2:
                    build(flags, level, privilege, access, 0, 0, nonleaf_extra=16)
    for flags in range(256):
        for level in range(3):
            for privilege in (0, 1):
                for access in range(4):
                    for sum_enabled in (0, 1):
                        for mxr in (0, 1):
                            build(flags, level, privilege, access, sum_enabled, mxr)
    return rows


def mmu_probe(ev):
    rows = walk_cases()
    tb = ev.directory / "walk_tb.sv"
    tb.write_text(TB)
    hexadecimal = {0, 1, 2, 7, 10, 12, 14, 15, 17, 18, 20, 21}
    for name, cases in (("walks.txt", rows), ("walk-smoke.txt", rows[:128])):
        path = ev.directory / name
        path.write_text("".join(
            " ".join(f"{value:x}" if i in hexadecimal else str(value)
                     for i, value in enumerate(row)) + "\n" for row in cases))
        ev.record.setdefault("generated_sha256", {})[ev.relative(path)] = digest(path)
    ev.record["generated_sha256"][ev.relative(tb)] = digest(tb)
    sources = [ROOT / "rtl/hammer_v3_ptw.sv", ROOT / "rtl/hammer_v3_page_leaf.sv"]
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "walk_tb", "-o",
            ev.relative(ev.directory / "walk.vvp"), ev.relative(tb),
            *map(ev.relative, sources)], "walk-compile")
    output = ev.run(["vvp", "./walk.vvp", "+cases=walk-smoke.txt"],
                    "walk-icarus", cwd=ev.directory)
    if not re.search(r"SUMMARY PTW compared=\s*128\b", output):
        raise AssertionError("compact Sv39 PTW comparisons incomplete")
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "walk_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "walk-sim",
            ev.relative(tb), *map(ev.relative, sources)], "walk-verilator-compile")
    try:
        output = ev.run(["./compile-obj/walk-sim"], "walk-verilator", cwd=ev.directory)
        if not re.search(rf"SUMMARY PTW compared=\s*{len(rows)}\b", output):
            raise AssertionError("compiled Sv39 PTW comparisons incomplete")
        ev.record["observed"] = {"icarus_compared": 128, "compiled_compared": len(rows),
                                 "flags": 256, "leaf_levels": [0, 1, 2],
                                 "privileges": [0, 1], "sum_mxr": "all combinations",
                                 "accesses": [0, 1, 2, 3]}
    finally:
        shutil.rmtree(objects)
