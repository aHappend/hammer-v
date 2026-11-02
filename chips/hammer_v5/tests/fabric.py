"""Independent public-pin arbitration, memory masks and error classification."""
import shutil

from evidence import ROOT, digest


TB = r"""
module fabric_tb;
reg clk=0,rst_n;
always #5 clk=~clk;
reg [2:0] req_valid=0,req_write=0,req_demand=0,rsp_ready=0;
wire [2:0] req_ready,rsp_valid,rsp_error,rsp_decerr;
reg [191:0] req_addr=0,req_wdata=0;
reg [23:0] req_wstrb=0;
reg [8:0] req_prot=0;
wire [191:0] rsp_rdata;
reg h_imem=0,h_dmem=0,h_write=0;
reg [31:0] h_addr=0;
reg [63:0] h_wdata=0;
reg [7:0] h_wstrb=0;
wire [63:0] h_imem_data,h_dmem_data;
wire mem_valid,mem_write,mem_demand,mem_rsp_ready;
reg mem_ready=0,mem_rsp_valid=0,mem_error=0,mem_decerr=0;
wire [63:0] mem_addr,mem_wdata;
wire [7:0] mem_wstrb;
wire [2:0] mem_prot;
reg [63:0] mem_rdata=0;
hammer_v5_fabric #(.IMEM_WORDS(1),.DMEM_WORDS(1)) dut(.*);
integer accepted[0:2],completed[0:2];
integer cycles=0,total=0,next_owner=0,owner=-1,ordinal=0,age=0;
integer expected_owner,n,lane,stalls=0,back_stalls=0,errors=0,decode_errors=0;
integer request_stall=0,response_stall=0;
reg [7:0] bytes[0:23];
reg [63:0] expected_data=0,address=0,value=0,back_data=0;
reg [7:0] mask=0;
reg write=0,demand=0;
reg [2:0] protection=0;
reg expected_error=0,expected_decode=0,back_pending=0,back_response=0;
reg running=0;
task reset_check;
begin
 if({req_ready,rsp_valid,rsp_error,rsp_decerr,rsp_rdata,mem_valid,mem_write,
     mem_addr,mem_wdata,mem_wstrb,mem_prot,mem_demand,mem_rsp_ready} !== 347'b0)
  $fatal(1,"fabric reset output leakage");
end
endtask
always @(posedge clk or negedge clk) if(!rst_n) reset_check();
always @(negedge clk) if(rst_n && running) begin
 for(n=0;n<3;n=n+1) begin
  req_valid[n]=accepted[n]<24;
  req_addr[n*64 +: 64]=64'h80000000+n*8;
  req_wdata[n*64 +: 64]=64'h89abcdef01234567 ^ (n*64'h1111111111111111) ^ accepted[n];
  req_write[n]=n!=0 && (accepted[n]&1)!=0;
  req_wstrb[n*8 +: 8]=(accepted[n]*19+n*3)&255;
  req_prot[n*3 +: 3]=n;
  req_demand[n]=n!=2 || (accepted[n]&1)==0;
 end
 rsp_ready=response_stall==0 ? 0 : 7;
 mem_ready=request_stall>=2 && !back_pending && !back_response;
 mem_rsp_valid=back_response;
 mem_error=back_response && expected_error;
 mem_decerr=back_response && expected_decode;
 mem_rdata=back_response && !expected_error ? back_data : 0;
end
always @(posedge clk) if(rst_n && running) begin
 cycles=cycles+1;
 if((^req_ready)===1'bx || (^rsp_valid)===1'bx || (^mem_valid)===1'bx)
  $fatal(1,"fabric active X handshake");
 if(req_ready!=0) begin
  if(owner!=-1 || (req_ready & (req_ready-1))!=0)
   $fatal(1,"fabric multiple outstanding or multiple admissions");
  expected_owner=next_owner;
  if(!req_valid[expected_owner]) begin
   expected_owner=(expected_owner+1)%3;
   if(!req_valid[expected_owner]) expected_owner=(expected_owner+1)%3;
  end
  if(req_ready !== (3'b001<<expected_owner))
   $fatal(1,"fabric deterministic fairness mismatch");
  owner=expected_owner; ordinal=accepted[owner];
  request_stall=0; response_stall=0;
  address=req_addr[owner*64 +: 64]; value=req_wdata[owner*64 +: 64];
  mask=req_wstrb[owner*8 +: 8]; write=req_write[owner];
  protection=req_prot[owner*3 +: 3]; demand=req_demand[owner];
  expected_error=owner==2 && (ordinal==5 || ordinal==7);
  expected_decode=owner==2 && ordinal==7;
  expected_data=0;
  if(!write && !expected_error)
   for(lane=0;lane<8;lane=lane+1) expected_data[lane*8 +: 8]=bytes[owner*8+lane];
  next_owner=(owner+1)%3; accepted[owner]=accepted[owner]+1;
 end
 if(mem_valid) begin
  if(owner==-1 || mem_addr!==address || mem_wdata!==value || mem_wstrb!==mask ||
     mem_write!==write || mem_prot!==protection || mem_demand!==demand)
   $fatal(1,"fabric downstream payload/mask/protection/demand mismatch");
  if(!mem_ready) begin
   back_stalls=back_stalls+1; request_stall=request_stall+1;
  end
 end
 if(mem_valid && mem_ready) begin
  if(back_pending || back_response) $fatal(1,"fabric duplicated downstream request");
  back_pending=1; age=0; back_data=expected_data;
  if(write && !expected_error)
   for(lane=0;lane<8;lane=lane+1)
    if(mask[lane]) bytes[owner*8+lane]=value[lane*8 +: 8];
 end
 if(mem_rsp_valid && mem_rsp_ready) back_response=0;
 if(rsp_valid!=0) begin
  if(owner==-1 || rsp_valid!==(3'b001<<owner) ||
     rsp_error!==((3'b001<<owner)&{3{expected_error}}) ||
     rsp_decerr!==((3'b001<<owner)&{3{expected_decode}}))
   $fatal(1,"fabric response owner/error/decode classification mismatch");
  for(n=0;n<3;n=n+1)
   if(rsp_rdata[n*64 +: 64] !== (n==owner ? expected_data : 64'b0))
    $fatal(1,"fabric public byte-memory response mismatch");
  if(!rsp_ready[owner]) begin
   stalls=stalls+1; response_stall=response_stall+1;
  end
  else begin
   completed[owner]=completed[owner]+1; total=total+1;
   if(expected_error) errors=errors+1;
   if(expected_decode) decode_errors=decode_errors+1;
   owner=-1;
  end
 end
 #1;
 if(back_pending) begin
  age=age+1;
  if(age==4) begin back_pending=0; back_response=1; end
 end
 if(cycles>10000) $fatal(1,"fabric cycle bound");
end
initial begin
 rst_n=0; #0; reset_check();
 for(n=0;n<3;n=n+1) begin accepted[n]=0; completed[n]=0; end
 for(n=0;n<24;n=n+1) bytes[n]=n;
 #21; rst_n=1;
 // Reset an accepted request while its external acceptance is stalled.
 @(negedge clk); req_valid=1; req_addr[63:0]=64'h80000000;
 @(posedge clk); #1; req_valid=0;
 @(posedge clk); #1;
 if(mem_valid!==1) $fatal(1,"fabric reset probe did not reach stalled issue");
 rst_n=0; #1; reset_check(); #19; rst_n=1;
 repeat(3) begin @(posedge clk); #1;
  if(rsp_valid!==0 || mem_valid!==0) $fatal(1,"fabric response survived reset");
 end
 running=1;
 while(total<72) @(negedge clk);
 running=0; req_valid=0; rsp_ready=0;
 for(n=0;n<3;n=n+1)
  if(accepted[n]!=24 || completed[n]!=24) $fatal(1,"fabric contender starved");
 if(stalls==0 || back_stalls==0 || errors!=2 || decode_errors!=1)
  $fatal(1,"fabric coverage missing rsp_stalls=%0d back_stalls=%0d errors=%0d decode=%0d",
   stalls,back_stalls,errors,decode_errors);
 $display("SUMMARY FABRIC compared=72 contenders=3 errors=2 decode_errors=1 response_stalls=%0d downstream_stalls=%0d reset=1",
  stalls,back_stalls);
 $finish;
end
endmodule
"""


def fabric_probe(ev):
    tb = ev.directory / "fabric_tb.sv"
    tb.write_text(TB)
    ev.record.setdefault("generated_sha256", {})[ev.relative(tb)] = digest(tb)
    sources = [ROOT / "rtl" / name for name in (
        "hammer_v5_fabric.sv", "hammer_v5_imem.sv", "hammer_v5_dmem.sv", "hammer_v5_ram.sv")]
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "fabric_tb", "-o",
            ev.relative(ev.directory / "fabric.vvp"), ev.relative(tb),
            *map(ev.relative, sources)], "fabric-compile")
    summary = "SUMMARY FABRIC compared=72 contenders=3 errors=2 decode_errors=1"
    text = ev.run(["vvp", "./fabric.vvp"], "fabric-icarus", cwd=ev.directory)
    if summary not in text:
        raise AssertionError("fabric arbitration comparisons incomplete")
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "fabric_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "fabric-sim",
            ev.relative(tb), *map(ev.relative, sources)], "fabric-verilator-compile")
    try:
        text = ev.run(["./compile-obj/fabric-sim"], "fabric-verilator", cwd=ev.directory)
        if summary not in text:
            raise AssertionError("compiled arbitration comparisons incomplete")
        ev.record["observed"] = {"compared": 72, "contenders": 3,
                                 "errors": 2, "decode_errors": 1}
    finally:
        shutil.rmtree(objects)
