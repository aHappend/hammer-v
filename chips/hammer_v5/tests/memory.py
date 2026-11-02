"""Public-port unified L2 comparisons against independent byte memory."""
import random
import shutil

from evidence import ROOT, digest


TB = r"""
module memory_tb;
parameter integer SETS=1, PREFETCH=0;
reg clk=0;
always #5 clk=~clk;
reg rst_n;
reg req_valid=0, rsp_ready=0;
reg [1:0] req_cmd=0;
reg [63:0] req_addr=0,req_wdata=0;
reg [7:0] req_wstrb=0;
wire req_ready,rsp_valid,rsp_error;
wire [63:0] rsp_rdata;
wire mem_valid,mem_write,mem_rsp_ready;
reg mem_ready=0,mem_rsp_valid=0,mem_error=0;
wire [63:0] mem_addr,mem_wdata;
wire [7:0] mem_wstrb;
reg [63:0] mem_rdata=0;
reg prefetch_block=1;
wire event_l2_access,event_l2_hit;
hammer_v5_l2 #(.L2_SETS(SETS),.PREFETCH_ENABLE(PREFETCH)) dut(.*);
reg [7:0] memory[0:32767];
reg pending=0, pending_write=0, pending_error=0;
reg [63:0] pending_addr=0,pending_data=0;
reg [7:0] pending_mask=0;
integer delay_left=0, bus_reads=0,bus_writes=0,fail_kind=0;
reg [31:0] random_state=32'h12345678;
integer k,b;
task reset_check;
begin
 if ({req_ready,rsp_valid,rsp_error,rsp_rdata,mem_valid,mem_write,
      mem_addr,mem_wdata,mem_wstrb,mem_rsp_ready,
      event_l2_access,event_l2_hit} !== 208'b0)
  $fatal(1,"L2 RESET");
end
endtask
always @(posedge clk or negedge clk) if (!rst_n) reset_check();
always @(negedge clk) begin
 random_state=random_state ^ (random_state<<13);
 random_state=random_state ^ (random_state>>17);
 random_state=random_state ^ (random_state<<5);
 mem_ready=rst_n && !pending && !mem_rsp_valid && random_state[0];
end
always @(posedge clk) begin
 if (!rst_n) begin
  pending<=0; mem_rsp_valid<=0; mem_error<=0; mem_rdata<=0;
 end else begin
  if (mem_rsp_valid && mem_rsp_ready) begin
   mem_rsp_valid<=0; mem_error<=0; mem_rdata<=0;
  end
  if (mem_valid && mem_ready) begin
   if (pending || mem_rsp_valid) $fatal(1,"L2 duplicate downstream request");
   if ((^mem_addr) === 1'bx || mem_addr<64'h80000000 ||
       mem_addr>=64'h80008000 || mem_addr[2:0]!=0)
    $fatal(1,"L2 invalid downstream address %h",mem_addr);
   pending<=1; pending_addr<=mem_addr-64'h80000000;
   pending_write<=mem_write; pending_data<=mem_wdata; pending_mask<=mem_wstrb;
   pending_error<=fail_kind==(mem_write ? 2 : 1);
   if (fail_kind==(mem_write ? 2 : 1)) fail_kind=0;
   delay_left<=1+random_state[3:1];
   if (mem_write) bus_writes=bus_writes+1;
   else bus_reads=bus_reads+1;
  end
  if (pending) begin
   if (delay_left>0) delay_left<=delay_left-1;
   else begin
    pending<=0; mem_rsp_valid<=1; mem_error<=pending_error;
    mem_rdata<=0;
    if (!pending_error) begin
     if (pending_write) begin
      for (b=0;b<8;b=b+1)
       if (pending_mask[b]) memory[pending_addr+b]<=pending_data[b*8+:8];
     end else begin
      for (b=0;b<8;b=b+1) mem_rdata[b*8+:8]<=memory[pending_addr+b];
     end
    end
   end
  end
 end
end
integer file,status,cmd,mask,expected_error,inject,stall,expected_hit;
integer compared=0,age,j,lookups=0,hits=0,reads_before;
integer demand_events=0,hit_events=0;
reg [63:0] address,value,expected;
reg [1023:0] cases;
always @(posedge clk) if (rst_n) begin
 if (event_l2_access === 1'b1) demand_events=demand_events+1;
 else if (event_l2_access !== 1'b0) $fatal(1,"L2 unknown demand event");
 if (event_l2_hit === 1'b1) hit_events=hit_events+1;
 else if (event_l2_hit !== 1'b0) $fatal(1,"L2 unknown hit event");
end
initial begin
 rst_n=0;
 for(k=0;k<32768;k=k+1) memory[k]=(k*37+11)&255;
 #0; reset_check();
 #21; rst_n=1;
 if (!$value$plusargs("cases=%s",cases)) cases="memory.txt";
 file=$fopen(cases,"r");
 if(!file) $fatal(1,"L2 missing independent cases");
 while(!$feof(file)) begin
  status=$fscanf(file,"%d %h %h %h %h %d %d %d %d\n",
    cmd,address,value,mask,expected,expected_error,inject,stall,expected_hit);
  if(status!=9) $fatal(1,"L2 malformed case");
  @(negedge clk); #1;
  req_valid=1; req_cmd=cmd; req_addr=address; req_wdata=value; req_wstrb=mask;
  fail_kind=inject; reads_before=bus_reads;
  while(req_ready !== 1'b1) @(negedge clk);
  @(posedge clk);
  if(rsp_valid !== 1'b0) $fatal(1,"L2 response at acceptance");
  #1; req_valid=0;
  if(req_ready !== 1'b0 || rsp_valid !== 1'b0) $fatal(1,"L2 accept boundary");
  age=0;
  while(rsp_valid !== 1'b1) begin
   @(posedge clk); #1; age=age+1;
   if(age>1000) $fatal(1,"L2 missing response");
   if(rsp_valid !== 1'b0 && rsp_valid !== 1'b1) $fatal(1,"L2 active X valid");
  end
  if(rsp_error !== (expected_error!=0) || rsp_rdata !== expected)
   $fatal(1,"MEMORY MISMATCH case=%d cmd=%d addr=%h expected=%h/%d observed=%h/%b",
      compared,cmd,address,expected,expected_error,rsp_rdata,rsp_error);
  if(expected_hit==1 && cmd==0 &&
      (age!=3 || bus_reads!=reads_before))
   $fatal(1,"L2 resident hit did not meet E3/no-downstream contract age=%d",age);
  for(j=0;j<stall;j=j+1) begin
   @(posedge clk); #1;
   if(rsp_valid !== 1'b1 || rsp_rdata !== expected ||
      rsp_error !== (expected_error!=0) || req_ready !== 1'b0)
    $fatal(1,"L2 response unstable");
  end
  @(negedge clk); rsp_ready=1;
  @(posedge clk);
  if(rsp_valid !== 1'b1) $fatal(1,"L2 missing transfer");
  #1; rsp_ready=0;
  if(rsp_valid !== 1'b0 || rsp_rdata !== 0 || rsp_error !== 0)
   $fatal(1,"L2 duplicate/inactive response");
  if(cmd<2) begin
   lookups=lookups+1;
   if(expected_hit==1) hits=hits+1;
  end
  if(demand_events!=lookups || hit_events!=hits)
   $fatal(1,"COUNTER MISMATCH L2 lookups=%d/%d hits=%d/%d",
      demand_events,lookups,hit_events,hits);
  compared=compared+1;
 end
 $fclose(file);
 if(compared==0 || hits==0 || bus_reads==0 || bus_writes==0)
  $fatal(1,"L2 empty required coverage");
 $display("SUMMARY L2 compared=%0d lookups=%0d hits=%0d reads=%0d writes=%0d",
   compared,lookups,hits,bus_reads,bus_writes);
 $finish;
end
initial begin #5000000; $fatal(1,"L2 CYCLE LIMIT 500000"); end
endmodule
"""


def cases(sets, seed, count):
    rng = random.Random(seed)
    backing = bytearray((i * 37 + 11) & 255 for i in range(32768))
    tags = [[None] * 4 for _ in range(sets)]
    replacement = [0] * sets
    rows = []

    def access(cmd, offset=0, value=0, mask=0, error=0, inject=0):
        line, index = offset >> 5, (offset >> 5) & (sets - 1)
        resident = line in tags[index]
        hit = int(resident) if cmd < 2 else 0
        expected = 0
        if cmd < 2:
            if not resident:
                if None in tags[index]:
                    way = tags[index].index(None)
                else:
                    way = replacement[index]
                tags[index][way] = None
                if inject != 1:
                    tags[index][way] = line
                    replacement[index] = (way + 1) & 3
            else:
                way = tags[index].index(line)
            if cmd == 1:
                if error:
                    tags[index][way] = None
                else:
                    for lane in range(8):
                        if (mask >> lane) & 1:
                            backing[offset + lane] = (value >> (8 * lane)) & 255
            elif not error:
                expected = int.from_bytes(backing[offset:offset + 8], "little")
        elif cmd == 3:
            tags[:] = [[None] * 4 for _ in range(sets)]
        rows.append((cmd, 0x80000000 + offset, value, mask, expected,
                     error, inject, rng.randrange(5), hit))

    stride = sets * 32
    for line in range(4):
        access(0, line * stride)
    for line in range(4):
        access(0, line * stride)
    access(0, 4 * stride)
    access(0, stride)
    access(0, 0)
    for mask in range(256):
        access(1, 8, rng.getrandbits(64), mask)
        access(0, 8)
    access(2)
    access(0, 8)
    access(3)
    access(0, 8)
    access(0, 7 * stride, error=1, inject=1)
    access(0, 7 * stride)
    access(1, 8, rng.getrandbits(64), 255, error=1, inject=2)
    access(0, 8)
    access(0, 32760)
    for _ in range(count):
        offset = rng.randrange(4096) * 8
        if rng.randrange(3):
            access(0, offset)
        else:
            access(1, offset, rng.getrandbits(64), rng.randrange(256))
    return rows


def l2_probe(ev, count=200):
    sources = [ROOT / "rtl/hammer_v5_l2.sv"]
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.version("make")
    ev.version("g++")
    observations = []
    for sets in (1, 64):
        directory = ev.directory / f"sets-{sets}"
        directory.mkdir()
        rows = cases(sets, 17, count)
        table = directory / "memory.txt"
        table.write_text("".join(
            f"{cmd} {addr:016x} {value:016x} {mask:02x} {expected:016x} "
            f"{error} {inject} {stall} {hit}\n"
            for cmd, addr, value, mask, expected, error, inject, stall, hit in rows))
        tb = directory / "memory_tb.sv"
        tb.write_text(TB.replace("SETS=1, PREFETCH=0", f"SETS={sets}, PREFETCH=0"))
        ev.record.setdefault("generated_sha256", {}).update(
            {ev.relative(p): digest(p) for p in (tb, table)})
        label = f"l2-{sets}"
        ev.run(["iverilog", "-g2012", "-Wall", "-s", "memory_tb", "-o",
                ev.relative(directory / "memory.vvp"), ev.relative(tb),
                *map(ev.relative, sources)], label + "-compile")
        text = ev.run(["vvp", "./memory.vvp"], label + "-icarus", cwd=directory)
        summary = f"SUMMARY L2 compared={len(rows)} "
        if summary not in text:
            raise AssertionError("missing L2 independent comparison count")
        objects = directory / "compile-obj"
        ev.run(["verilator", "--binary", "--timing", "--top-module", "memory_tb",
                "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "memory-sim",
                ev.relative(tb), *map(ev.relative, sources)], label + "-verilator-compile")
        text = ev.run(["./compile-obj/memory-sim"], label + "-verilator", cwd=directory)
        if summary not in text:
            raise AssertionError("missing compiled L2 independent comparison count")
        shutil.rmtree(objects)
        observations.append({"sets": sets, "seed": 17, "compared": len(rows)})
        ev.record["observed"] = observations
        ev.save()
