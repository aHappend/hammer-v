"""Independent architectural vector-state and commit-disposition comparisons."""
import random
import shutil

from evidence import ROOT, digest
from reference import bf16_dot, int8_dot, rms


TB = r"""
module vector_tb;
reg clk=0;
always #5 clk=~clk;
reg rst_n;
reg req_valid=0,rsp_ready=0,commit_valid=0,abort_valid=0;
reg [31:0] req_insn=0;
reg [63:0] req_rs1_data=0,req_rs2_data=0;
wire req_ready,rsp_valid,rsp_illegal,rsp_mem_error,rsp_page_fault;
wire [63:0] rsp_data,rsp_tval;
wire [3:0] event_macs;
wire mem_req_valid,mem_req_write,mem_rsp_ready;
reg mem_req_ready=0,mem_rsp_valid=0,mem_rsp_error=0,mem_rsp_page_fault=0;
wire [63:0] mem_req_addr,mem_req_wdata;
wire [7:0] mem_req_wstrb;
reg [63:0] mem_rsp_rdata=0;
hammer_v5_vector dut(.*);
task reset_check;
begin
 if ({req_ready,rsp_valid,rsp_illegal,rsp_mem_error,rsp_page_fault,
      rsp_data,rsp_tval,event_macs,mem_req_valid,mem_req_write,
      mem_rsp_ready,mem_req_addr,mem_req_wdata,mem_req_wstrb} !== 276'b0)
  $fatal(1,"VECTOR RESET");
end
endtask
always @(posedge clk or negedge clk) if(!rst_n) reset_check();
integer file,status,kind,expected_flags,dispose,macs,mem_kind,compared=0;
integer stall,age,j;
reg [63:0] expected,expected_store,loaded,expected_tval;
reg [1023:0] cases;
task response_check;
begin
 if(rsp_valid !== 1'b1 || rsp_data !== expected ||
    {rsp_illegal,rsp_mem_error,rsp_page_fault} !== expected_flags[2:0] ||
    rsp_tval !== expected_tval || req_ready !== 1'b0)
  $fatal(1,"VECTOR MISMATCH case=%d insn=%h expected=%h/%b/%h observed=%h/%b/%h",
    compared,req_insn,expected,expected_flags[2:0],expected_tval,
    rsp_data,{rsp_illegal,rsp_mem_error,rsp_page_fault},rsp_tval);
end
endtask
initial begin
 rst_n=0; #0; reset_check(); #21; rst_n=1;
 if(!$value$plusargs("cases=%s",cases)) cases="vector.txt";
 file=$fopen(cases,"r");
 if(!file) $fatal(1,"VECTOR missing independent cases");
 while(!$feof(file)) begin
  status=$fscanf(file,"%h %h %h %h %h %d %d %h %d %h %d %d\n",
    req_insn,req_rs1_data,req_rs2_data,loaded,expected,
    expected_flags,mem_kind,expected_store,dispose,expected_tval,macs,stall);
  if(status!=12) $fatal(1,"VECTOR malformed case");
  @(negedge clk); #1;
  if(req_ready !== 1'b1) $fatal(1,"VECTOR missing idle readiness");
  req_valid=1;
  @(posedge clk);
  if(rsp_valid !== 1'b0 || event_macs !== 0) $fatal(1,"VECTOR premature result");
  #1; req_valid=0;
  if(req_ready !== 1'b0) $fatal(1,"VECTOR accepted but still ready");
  if(mem_kind!=0) begin
   if(mem_req_valid !== 1'b1 || mem_req_addr !== req_rs1_data ||
      mem_req_write !== (mem_kind==2) ||
      mem_req_wdata !== expected_store ||
      mem_req_wstrb !== (mem_kind==2 ? 8'hff : 8'h00))
    $fatal(1,"VECTOR MEMORY MISMATCH case=%d expected_store=%h observed=%h addr=%h",
      compared,expected_store,mem_req_wdata,mem_req_addr);
   repeat(3) begin
    @(posedge clk); #1;
    if(mem_req_valid !== 1'b1 || mem_req_addr !== req_rs1_data ||
       mem_req_wdata !== expected_store || rsp_valid !== 0)
     $fatal(1,"VECTOR memory request unstable");
   end
   @(negedge clk); mem_req_ready=1;
   @(posedge clk); #1; mem_req_ready=0;
   if(mem_req_valid !== 0 || mem_rsp_ready !== 1)
    $fatal(1,"VECTOR memory request duplicated");
   repeat(2) @(negedge clk);
   mem_rsp_valid=1; mem_rsp_rdata=loaded;
   mem_rsp_error=expected_flags[1]; mem_rsp_page_fault=expected_flags[0];
   @(posedge clk); #1;
   mem_rsp_valid=0; mem_rsp_rdata=0; mem_rsp_error=0; mem_rsp_page_fault=0;
  end
  age=0;
  while(rsp_valid !== 1'b1) begin
   @(posedge clk); #1; age=age+1;
   if(age>30) $fatal(1,"VECTOR missing response");
   if(event_macs !== 0) $fatal(1,"VECTOR uncommitted MAC event");
  end
  if(expected_flags==0 && (req_insn[14:12]==1 || req_insn[14:12]==3) && age!=6)
   $fatal(1,"VECTOR INT8 latency mismatch E%0d",age);
  if(expected_flags==0 && req_insn[14:12]==2 && age!=12)
   $fatal(1,"VECTOR BF16 latency mismatch E%0d",age);
  response_check();
  for(j=0;j<stall;j=j+1) begin
   @(posedge clk); #1; response_check();
   if(event_macs !== 0) $fatal(1,"VECTOR uncommitted MAC event");
  end
  @(negedge clk); rsp_ready=1;
  @(posedge clk); response_check();
  #1; rsp_ready=0;
  if(rsp_valid !== 0 || req_ready !== 0 || event_macs !== 0)
   $fatal(1,"VECTOR completed result not awaiting disposition");
  repeat(2) begin
   @(posedge clk); #1;
   if(req_ready !== 0 || rsp_valid !== 0 || event_macs !== 0)
    $fatal(1,"VECTOR architectural update before disposition");
  end
  @(negedge clk); commit_valid=(dispose==1); abort_valid=(dispose==0);
  @(posedge clk);
  if(event_macs !== macs[3:0])
   $fatal(1,"COUNTER MISMATCH VECTOR expected=%d observed=%d",macs,event_macs);
  #1; commit_valid=0; abort_valid=0;
  if(req_ready !== 1 || rsp_valid !== 0 || event_macs !== 0)
   $fatal(1,"VECTOR disposition failed");
  compared=compared+1;
 end
 $fclose(file);
 if(compared==0) $fatal(1,"VECTOR empty comparison");
 $display("SUMMARY VECTOR compared=%0d",compared);
 $finish;
end
initial begin #5000000; $fatal(1,"VECTOR CYCLE LIMIT 500000"); end
endmodule
"""


def cases(seed=17, count=100):
    rng = random.Random(seed)
    registers = [0] * 8
    rows = []

    def operation(op, a=0, b=0, rd=0, loaded=0, source=0, flags=0,
                  dispose=1, malformed=0):
        insn = (b << 20) | (a << 15) | (op << 12) | (rd << 7) | 11 | malformed
        mem_kind = 0
        expected = store = tval = macs = 0
        if flags & 3:
            tval = source
        if not (flags & 4) and op in (0, 4) and source & 7 == 0:
            mem_kind = 1 if op == 0 else 2
            if op == 4:
                store = registers[b]
        if flags == 0:
            if op == 0:
                expected = loaded
                if dispose:
                    registers[rd] = loaded
            elif op == 1:
                expected = int8_dot(registers[a], registers[b])
                macs = 8 if dispose else 0
            elif op == 2:
                expected = bf16_dot(registers[a], registers[b])
                macs = 4 if dispose else 0
            elif op == 3:
                expected = rms(registers[a], loaded)
                macs = 8 if dispose else 0
        rows.append((insn, source, loaded if op == 3 else rng.getrandbits(64),
                     loaded, expected, flags, mem_kind, store, dispose,
                     tval, macs, rng.randrange(5)))

    for index in range(8):
        operation(4, a=31, b=index, source=0x10000000)
        operation(0, a=31, rd=index, source=0x10000000,
                  loaded=rng.getrandbits(64))
    for index in range(8):
        for flags, dispose in ((0, 0), (1, 1), (2, 1)):
            operation(0, a=31, rd=index, source=0x10000000,
                      loaded=rng.getrandbits(64), flags=flags, dispose=dispose)
            operation(4, a=31, b=index, source=0x10000000)
        operation(0, a=31, rd=index, source=0x10000001, flags=2)
        operation(4, a=31, b=index, source=0x10000000)
    for op in range(8):
        operation(op, flags=4, malformed=1 << 25)
    operation(0, rd=8, flags=4)
    operation(0, b=1, flags=4)
    operation(1, a=8, flags=4)
    operation(2, b=8, flags=4)
    operation(3, a=8, flags=4)
    operation(4, b=8, flags=4)
    operation(4, rd=1, flags=4)
    for _ in range(count):
        a, b, rd = rng.randrange(8), rng.randrange(8), rng.randrange(32)
        if rng.randrange(5) == 0:
            operation(0, a=31, rd=a, source=0x10000000, loaded=rng.getrandbits(64))
        for op in (1, 2, 3):
            operation(op, a=a, b=b, rd=rd, loaded=rng.getrandbits(64),
                      dispose=int(rng.randrange(5) != 0))
    return rows


def vector_probe(ev):
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.version("make")
    ev.version("g++")
    rows = cases()
    table = ev.directory / "vector.txt"
    table.write_text("".join(
        f"{insn:08x} {rs1:016x} {rs2:016x} {loaded:016x} {expected:016x} "
        f"{flags} {mem_kind} {store:016x} {dispose} {tval:016x} {macs} {stall}\n"
        for insn, rs1, rs2, loaded, expected, flags, mem_kind, store, dispose,
        tval, macs, stall in rows))
    tb = ev.directory / "vector_tb.sv"
    tb.write_text(TB)
    sources = [ROOT / "rtl" / name for name in (
        "hammer_v5_vector.sv", "hammer_v5_int8.sv", "hammer_v5_bf16.sv",
        "hammer_v5_bf16_mul.sv", "hammer_v5_fp32_add.sv", "hammer_v5_fp32_round.sv")]
    ev.record.setdefault("generated_sha256", {}).update(
        {ev.relative(p): digest(p) for p in (table, tb)})
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "vector_tb", "-o",
            ev.relative(ev.directory / "vector.vvp"), ev.relative(tb),
            *map(ev.relative, sources)], "vector-icarus-compile")
    summary = f"SUMMARY VECTOR compared={len(rows)}"
    text = ev.run(["vvp", "./vector.vvp"], "vector-icarus-run", cwd=ev.directory)
    if summary not in text:
        raise AssertionError("missing vector-state comparisons")
    ev.record["observed"] = {"icarus_compared": len(rows)}
    ev.save()
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "vector_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "vector-sim",
            ev.relative(tb), *map(ev.relative, sources)], "vector-verilator-compile")
    text = ev.run(["./compile-obj/vector-sim"], "vector-verilator-run", cwd=ev.directory)
    if summary not in text:
        raise AssertionError("missing compiled vector-state comparisons")
    ev.record["observed"]["verilator_compared"] = len(rows)
    shutil.rmtree(objects)
