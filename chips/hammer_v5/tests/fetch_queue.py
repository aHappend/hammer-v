"""Source-extracted fetch-storage cone checked against a public transaction FIFO."""
import re
import shutil

from evidence import ROOT, digest


def extract_cone():
    source = (ROOT / "rtl/hammer_v5_core.sv").read_text()
    declarations = re.search(
        r"    typedef struct packed \{\n        logic \[63:0\] pc, pred;\n.*?"
        r"    reg queue_release;", source, re.S)
    sequential = re.search(
        r"    integer queue_slot;\n    always @\(posedge clk or negedge rst_n\).*?"
        r"(?=    always @\(posedge clk or negedge rst_n\))", source, re.S)
    head = re.search(
        r"    assign queue_head_bits = .*?;\n    always @\* queue_head = .*?;", source)
    if not all((declarations, sequential, head)):
        raise AssertionError("fetch queue source extraction boundaries changed")
    return r"""
module fetch_storage (
 input wire clk, rst_n, running, queue_flush, queue_push, queue_pop,
 input wire [63:0] fetch_context, predicted_next, i_rsp_tval,
 input wire [63:0] i_rsp_rdata,
 input wire [31:0] i_rsp_insn_raw,
 input wire [2:0] i_rsp_insn_bytes,
 input wire i_rsp_error, i_rsp_page_fault, i_rsp_illegal,
 output wire [261:0] head, output wire empty, full, released);
""" + declarations[0] + "\n" + head[0] + "\n" + sequential[0] + r"""
 assign head = queue_head_bits;
 assign empty = queue_count == 0;
 assign full = queue_count == 4;
 assign released = queue_release;
endmodule
"""


TB = r"""
module fetch_storage_tb;
 reg clk=0, rst_n;
 always #5 clk=~clk;
 reg running=1,queue_flush=0,queue_push=0,queue_pop=0;
 reg [63:0] fetch_context=0,predicted_next=0,i_rsp_tval=0,i_rsp_rdata=0;
 reg [31:0] i_rsp_insn_raw=0;
 reg [2:0] i_rsp_insn_bytes=0;
 reg i_rsp_error=0,i_rsp_page_fault=0,i_rsp_illegal=0;
 wire [261:0] head;
 wire empty,full,released;
 fetch_storage dut(.*);
 reg [261:0] expected[0:3];
 integer size=0,compared=0,simultaneous=0,resets=0,redirects=0,stalls=0;
 integer enqueues=0,dequeues=0,full_seen=0,i,j;
 reg [31:0] rng=32'd17;
 reg [261:0] payload,held;
 task check;
 begin
  if(empty !== (size==0) || full !== (size==4))
   $fatal(1,"QUEUE occupancy mismatch");
  if(size>0) begin
   if(head !== expected[0]) $fatal(1,"QUEUE payload mismatch comparison=%d",compared);
   compared=compared+1;
  end
  if(!rst_n && released !== 1'b0) $fatal(1,"QUEUE reset release leakage");
 end
 endtask
 always @(posedge clk or negedge clk) if(!rst_n) begin
  if({empty,full,released} !== 3'b100 || head !== 262'b0)
   $fatal(1,"QUEUE asynchronous reset leakage");
 end
 task step(input bit push,input bit pop,input bit flush,input bit reset);
 begin
  @(negedge clk);
  check();
  #1;
  queue_push=push;queue_pop=pop;queue_flush=flush;rst_n=!reset;
  rng=rng^(rng<<13);rng=rng^(rng>>17);rng=rng^(rng<<5);
  fetch_context={rng,~rng};predicted_next={~rng,rng};
  i_rsp_rdata={32'h12345678,rng^32'hf00d4567};
  i_rsp_insn_raw=rng^32'h89abcdef;i_rsp_insn_bytes=rng[0]?2:4;
  i_rsp_error=rng[1];i_rsp_page_fault=rng[2];i_rsp_illegal=rng[3];
  i_rsp_tval={rng^32'hffffffff,rng^32'h76543210};
  payload={fetch_context,predicted_next,i_rsp_rdata[31:0],i_rsp_insn_raw,
           i_rsp_insn_bytes,i_rsp_error,i_rsp_page_fault,i_rsp_illegal,i_rsp_tval};
  if(reset) begin size=0;resets=resets+1;end
  #1;
  if(reset) check();
  @(posedge clk);
  check();
  if(reset || flush || !running) begin
   if(flush && size>0) redirects=redirects+1;
   size=0;
  end else begin
   if(pop) begin
    if(size==0) $fatal(1,"invalid empty pop fixture");
    for(j=0;j<size-1;j=j+1) expected[j]=expected[j+1];
    size=size-1;dequeues=dequeues+1;
   end
   if(push) begin
    if(size==4) $fatal(1,"invalid full push fixture");
    expected[size]=payload;size=size+1;enqueues=enqueues+1;
   end
   if(push && pop) simultaneous=simultaneous+1;
   if(!push && !pop && size>0) stalls=stalls+1;
  end
  #1;check();
  if(size==4) begin
   full_seen=full_seen+1;
   if(released !== 1'b0 && released !== 1'b1) $fatal(1,"unknown release");
  end
 end
 endtask
 initial begin
  rst_n=0;
  // This extracted internal cone has no public reset-output gates.
  #1;check();
  #10;
  step(0,0,0,0);
  for(i=0;i<4;i=i+1) step(1,0,0,0);
  step(0,0,0,0);
  if(released !== 1'b1) $fatal(1,"full queue did not release");
  for(i=0;i<128;i=i+1) step(1,1,0,0);
  for(i=0;i<4;i=i+1) step(0,1,0,0);
  if(released !== 1'b0) $fatal(1,"drained queue did not stop release");
  step(1,0,0,0);step(1,0,0,0);step(0,0,1,0);
  step(1,0,0,0);step(0,0,0,0);step(0,0,0,1);
  step(0,0,0,0);
  for(i=0;i<20000;i=i+1) begin
   if(i%257==0) step(0,0,0,1);
   else if(i%113==0) step(0,0,1,0);
   else step(size<4 && rng[4],size>0 && rng[5],0,0);
  end
  while(size>0) step(0,1,0,0);
  if(compared<1000 || simultaneous<128 || resets<2 ||
     redirects<2 || stalls<10 || full_seen<10 || enqueues<1000 || dequeues<1000)
   $fatal(1,"QUEUE missing witnessed coverage");
  $display("SUMMARY compared=%0d simultaneous=%0d reset=%0d redirect=%0d stalled=%0d enqueues=%0d dequeues=%0d full=%0d",
    compared,simultaneous,resets,redirects,stalls,enqueues,dequeues,full_seen);
  $finish;
 end
 initial begin #5000000;$fatal(1,"QUEUE compact cycle ceiling");end
endmodule
"""


def fetch_queue_probe(ev):
    source = ev.directory / "fetch-storage.sv"
    tb = ev.directory / "fetch-storage-tb.sv"
    lowered = ev.directory / "fetch-storage-lowered.v"
    script = ev.directory / "fetch-storage.ys"
    source.write_text(extract_cone())
    tb.write_text(TB)
    script.write_text(
        f"read_verilog -sv {ev.relative(source)}\n"
        "hierarchy -check -top fetch_storage\nproc\nopt\ncheck -assert\n"
        f"write_verilog -noattr {ev.relative(lowered)}\n")
    ev.record.setdefault("generated_sha256", {}).update({
        ev.relative(path): digest(path) for path in (source, tb, script)})
    for tool, flags in (("iverilog", ("-V",)), ("vvp", ("-V",)),
                        ("verilator", ("--version",)), ("yosys", ("-V",))):
        ev.version(tool, flags)
    ev.run(["yosys", "-Q", "-T", "-s", ev.relative(script)], "queue-lower")
    observations = []
    for name, rtl in (("direct", source), ("lowered", lowered)):
        binary = ev.directory / f"queue-{name}.vvp"
        ev.run(["iverilog", "-g2012", "-Wall", "-s", "fetch_storage_tb",
                "-o", ev.relative(binary), ev.relative(tb), ev.relative(rtl)],
               f"queue-{name}-compile")
        observed = ev.run(["vvp", ev.relative(binary)], f"queue-{name}-run")
        observations.append(observed.strip())
        objects = ev.directory / f"queue-{name}-obj"
        try:
            ev.run(["verilator", "--binary", "--timing", "-j", "2", "-Wno-fatal",
                    "--top-module", "fetch_storage_tb", "--Mdir", ev.relative(objects),
                    ev.relative(tb), ev.relative(rtl)], f"queue-{name}-verilate")
            observed = ev.run([ev.relative(objects / "Vfetch_storage_tb")],
                              f"queue-{name}-compiled-run")
            observations.append(observed.split("\n- ", 1)[0].strip())
        finally:
            if objects.is_dir():
                shutil.rmtree(objects)
    if len(set(observations)) != 1 or not observations[0].startswith("SUMMARY compared="):
        raise AssertionError("fetch storage direct/lowered simulator disagreement")
    ev.record["fetch_storage_cone"] = {
        "source": "rtl/hammer_v5_core.sv", "source_sha256": digest(ROOT / "rtl/hammer_v5_core.sv"),
        "extraction": "verbatim declarations, head read and entire sequential block",
        "oracle": "transaction FIFO with shifting contents; no DUT hierarchical reads",
        "summary": observations[0], "matched_variants": 4,
        "scope": "storage cone boundaries, not a claim of full CPU fetch control coverage",
    }
    ev.save()
