"""Public CSR checks with an independent address/privilege/event model."""
import random
import shutil

from evidence import ROOT, digest


TB = r"""
module counter_tb;
reg clk=0;
always #5 clk=~clk;
reg rst_n,csr_valid=0,csr_commit=0,csr_read=0,csr_write=0,retire=0;
reg [11:0] csr_addr=0;
reg [2:0] csr_op=1;
reg [63:0] csr_src=0,mtime=64'h123456789abcdef0;
reg [1:0] event_l1_access=0,event_l1_hit=0,return_kind=0,trap_target=0;
reg event_l2_access=0,event_l2_hit=0,return_commit=0,trap_enter=0;
reg [3:0] event_vector_macs=0;
reg irq_msip=0,irq_mtip=0,irq_meip=0,irq_seip=0;
reg [63:0] trap_epc=0,trap_cause=0,trap_tval=0;
wire [63:0] csr_rdata,return_pc,mstatus,mie,mip,medeleg,mideleg;
wire [63:0] mtvec,stvec,mepc,sepc,satp;
wire csr_illegal,vector_user_enable,return_illegal;
wire [1:0] priv;
hammer_v5_csr dut(.*);
integer f,n,compared=0,expected_illegal,expected_priv,expected_enable;
reg [63:0] expected_pre,expected_post;
reg [63:0] input_fields[0:17];
task reset_check;
begin
 if({csr_rdata,csr_illegal,vector_user_enable,return_illegal,return_pc,
     priv,mstatus,mie,mip,medeleg,mideleg,mtvec,stvec,mepc,sepc,satp} !== 773'b0)
  $fatal(1,"CSR RESET");
end
endtask
always @(posedge clk or negedge clk) if(!rst_n) reset_check();
initial begin
 rst_n=0; #0; reset_check(); #29; rst_n=1;
 f=$fopen("counters.txt","r");
 if(!f) $fatal(1,"missing independent CSR scenarios");
 while(!$feof(f)) begin
  @(negedge clk);
  n=$fscanf(f,"%d %d %h %d %h %d %d %d %d %d %d %d %d %d %d %h %h %d %h %h %d %d %d\n",
    input_fields[0],input_fields[1],input_fields[2],input_fields[3],
    input_fields[4],input_fields[5],input_fields[6],input_fields[7],
    input_fields[8],input_fields[9],input_fields[10],input_fields[11],
    input_fields[12],input_fields[13],input_fields[14],input_fields[15],
    input_fields[16],input_fields[17],
    expected_pre,expected_post,expected_illegal,expected_priv,expected_enable);
  if(n!=23) $fatal(1,"malformed CSR scenario n=%0d",n);
  csr_valid=input_fields[0][0]; csr_commit=input_fields[1][0];
  csr_addr=input_fields[2][11:0]; csr_op=input_fields[3][2:0];
  csr_src=input_fields[4]; csr_read=input_fields[5][0];
  csr_write=input_fields[6][0]; retire=input_fields[7][0];
  event_l1_access=input_fields[8][1:0]; event_l1_hit=input_fields[9][1:0];
  event_l2_access=input_fields[10][0]; event_l2_hit=input_fields[11][0];
  event_vector_macs=input_fields[12][3:0]; return_kind=input_fields[13][1:0];
  return_commit=input_fields[14][0]; trap_epc=input_fields[15];
  trap_target=input_fields[16][1:0]; trap_enter=input_fields[17][0];
  #1;
  if(csr_rdata !== expected_pre || csr_illegal !== (expected_illegal!=0))
   $fatal(1,"CSR MISMATCH case=%0d addr=%h before expected=%h/%0d observed=%h/%b op=%d priv=%d write=%b",
     compared,csr_addr,expected_pre,expected_illegal,csr_rdata,csr_illegal,
     csr_op,priv,csr_write);
  @(posedge clk);
  if(csr_rdata !== expected_pre) $fatal(1,"CSR sampling not pre-edge");
  #1;
  if(csr_rdata !== expected_post || priv !== expected_priv[1:0] ||
     vector_user_enable !== (expected_enable!=0))
   $fatal(1,"CSR MISMATCH case=%0d addr=%h after expected=%h/%0d/%0d observed=%h/%d/%b",
     compared,csr_addr,expected_post,expected_priv,expected_enable,
     csr_rdata,priv,vector_user_enable);
  compared=compared+1;
 end
 $fclose(f);
 if(compared==0) $fatal(1,"empty CSR comparison");
 $display("SUMMARY CSR compared=%0d",compared);
 $finish;
end
initial begin #5000000; $fatal(1,"CSR CYCLE LIMIT 500000"); end
endmodule
"""


def scenarios():
    mask = (1 << 64) - 1
    state = {0xB00: 0, 0xB02: 0, 0x306: 0, 0x106: 0, 0x320: 0,
             0x800: 0, 0x341: 0, 0x141: 0, 0x300: 0}
    state.update({0xB03 + i: 0 for i in range(4)})
    state.update({0x323 + i: i + 1 for i in range(4)})
    privilege = 3
    rows = []
    coverage = {key: 0 for key in (
        "write_priority", "rollover", "inhibition", "denied_alias",
        "supervisor_alias", "user_alias", "selectors", "epc_bit_one",
        "vxctl_denied", "retirement", "cycle")}

    def query(address, write):
        denied = (privilege < ((address >> 8) & 3) or
                  (write and address >> 10 == 3) or
                  (address == 0x800 and privilege == 0 and write))
        if 0xC00 <= address <= 0xC06:
            bit = 1 << (address & 7)
            denied |= privilege != 3 and (not state[0x306] & bit or
                                         (privilege == 0 and not state[0x106] & bit))
        if address in state:
            value = state[address]
            if address == 0x300:
                value |= (2 << 32) | (2 << 34)
        elif address in (0xC00, 0xC02, 0xC03, 0xC04, 0xC05, 0xC06):
            value = state[address - 0x100]
        elif address == 0xC01:
            value = 0x123456789ABCDEF0
        else:
            denied = True
            value = 0
        return value, int(denied)

    def cycle(address=0xB03, src=0, write=False, op=1, commit=True,
              events=(0, 0, 0, 0, 0), retired=0, target=None, return_kind=0):
        nonlocal privilege
        raw, illegal = query(address, write)
        before = 0 if illegal else raw
        old = state.copy()
        if not old[0x320] & 1:
            state[0xB00] = (old[0xB00] + 1) & mask
        if not old[0x320] & 4:
            state[0xB02] = (old[0xB02] + retired) & mask
        for i in range(4):
            event = old[0x323 + i]
            if not old[0x320] & (1 << (i + 3)):
                amount = events[event - 1] if event else 0
                state[0xB03 + i] = (old[0xB03 + i] + amount) & mask
        if write and commit and not illegal and target is None and not return_kind:
            value = src if op == 1 else raw | src if op == 2 else raw & ~src & mask
            if address in (0x306, 0x106):
                value &= 127
            elif address == 0x320:
                value &= 0x7D
            elif 0x323 <= address <= 0x326:
                value = value if value <= 5 else 0
            elif address == 0x800:
                value &= 1
            elif address in (0x341, 0x141):
                value &= ~1
            elif address == 0x300:
                allowed = sum(1 << bit for bit in
                              (1, 3, 5, 7, 8, 11, 12, 17, 18, 19, 20, 21, 22))
                value &= allowed
                if (value >> 11) & 3 == 2:
                    value &= ~(3 << 11)
            state[address] = value
        if target is not None:
            state[0x141 if target == 1 else 0x341] = 0x1236
            if target == 3:
                status = state[0x300]
                state[0x300] = (status & ~((3 << 11) | (1 << 7) | (1 << 3))) | (
                    privilege << 11) | (((status >> 3) & 1) << 7)
            else:
                status = state[0x300]
                state[0x300] = (status & ~((1 << 8) | (1 << 5) | (1 << 1))) | (
                    (privilege == 1) << 8) | (((status >> 1) & 1) << 5)
            privilege = target
        elif return_kind:
            if return_kind == 1 and privilege == 3:
                privilege = (state[0x300] >> 11) & 3
                status = state[0x300]
                state[0x300] = (status & ~((3 << 11) | (1 << 3))) | (
                    ((status >> 7) & 1) << 3) | (1 << 7)
                if privilege != 3:
                    state[0x300] &= ~(1 << 17)
            elif return_kind == 2 and privilege >= 1:
                privilege = (state[0x300] >> 8) & 1
                status = state[0x300]
                state[0x300] = (status & ~((1 << 8) | (1 << 1) | (1 << 17))) | (
                    ((status >> 5) & 1) << 1) | (1 << 5)
        after, after_illegal = query(address, write)
        rows.append((1, int(commit), address, op, src, 1, int(write), retired,
                     *events, return_kind, int(bool(return_kind)), 0x1237,
                     target or 0, int(target is not None), before,
                     0 if after_illegal else after, illegal, privilege, state[0x800]))
        return before

    def set_csr(address, value, **kwargs):
        cycle(address, value, write=True, **kwargs)

    # Halt autonomous cycle/retirement updates except their directed tests.
    set_csr(0x320, 0x7D)
    for event in range(6):
        for i in range(4):
            set_csr(0x323 + i, event)
            set_csr(0xB03 + i, 0)
        set_csr(0x320, 0)
        for i in range(4):
            cycle(0xB03 + i, events=(2, 1, 1, 1, 8))
        set_csr(0x320, 0x7D)
        for i in range(4):
            cycle(0xB03 + i)
        coverage["selectors"] += 1
    for i in range(4):
        set_csr(0x323 + i, 5)
        set_csr(0xB03 + i, mask - 3)
    set_csr(0x320, 0)
    cycle(events=(0, 0, 0, 0, 8))
    coverage["rollover"] += 4
    for i in range(4):
        set_csr(0xB03 + i, 123, events=(0, 0, 0, 0, 8))
        coverage["write_priority"] += 1
    set_csr(0x320, 0x7D)
    for i in range(4):
        cycle(0xB03 + i, events=(2, 2, 1, 1, 8))
        coverage["inhibition"] += 1
    set_csr(0xB00, mask)
    set_csr(0xB02, mask)
    set_csr(0x320, 0)
    cycle(0xB00, retired=1)
    cycle(0xB02)
    coverage["cycle"] += 1
    coverage["retirement"] += 1
    set_csr(0x320, 0x7D)
    set_csr(0x341, 0x1237)
    cycle(0x341)
    set_csr(0x141, 0x4567)
    cycle(0x141)
    coverage["epc_bit_one"] += 2
    set_csr(0x800, 1)
    for target in (1, 0):
        set_csr(0x306, 0)
        set_csr(0x106, 0)
        set_csr(0x300, target << 11)
        cycle(0xC03, return_kind=1)
        for i in range(3, 7):
            cycle(0xC00 + i)
            coverage["denied_alias"] += 1
        cycle(0xC03, target=3)
        set_csr(0x306, 127)
        set_csr(0x106, 127)
        set_csr(0x300, target << 11)
        cycle(0xC03, return_kind=1)
        for i in range(3, 7):
            cycle(0xC00 + i)
            coverage["supervisor_alias" if target == 1 else "user_alias"] += 1
        cycle(0xC03, src=10, write=True)
        if target == 0:
            cycle(0x800, src=0, write=True)
            coverage["vxctl_denied"] += 1
        cycle(0xC03, target=3)
    rng = random.Random(17)
    for _ in range(1000):
        index = rng.randrange(4)
        kind = rng.randrange(4)
        events = (rng.randrange(3), rng.randrange(3), rng.randrange(2),
                  rng.randrange(2), rng.choice((0, 4, 8)))
        if kind == 0:
            set_csr(0x323 + index, rng.randrange(6), events=events)
        elif kind == 1:
            set_csr(0xB03 + index, rng.getrandbits(64), events=events)
        elif kind == 2:
            set_csr(0x320, rng.randrange(128), events=events)
        else:
            cycle(0xB03 + index, events=events, retired=rng.randrange(2))
    if any(value == 0 for value in coverage.values()):
        raise AssertionError("missing required CSR scenario construction")
    return rows, coverage


def counter_probe(ev):
    rows, coverage = scenarios()
    tb = ev.directory / "counter_tb.sv"
    tb.write_text(TB)
    table = ev.directory / "counters.txt"
    hexadecimal = {2, 4, 15, 16, 18, 19}
    table.write_text("".join(
        " ".join(f"{v:x}" if i in hexadecimal else str(v) for i, v in enumerate(row)) + "\n"
        for row in rows))
    ev.record.setdefault("generated_sha256", {}).update(
        {ev.relative(path): digest(path) for path in (tb, table)})
    ev.version("iverilog", ("-V",))
    ev.version("vvp", ("-V",))
    ev.version("verilator")
    ev.run(["iverilog", "-g2012", "-Wall", "-s", "counter_tb", "-o",
            ev.relative(ev.directory / "counter.vvp"), ev.relative(tb),
            "rtl/hammer_v5_csr.sv"], "counter-compile")
    summary = f"SUMMARY CSR compared={len(rows)}"
    text = ev.run(["vvp", "./counter.vvp"], "counter-icarus", cwd=ev.directory)
    if summary not in text:
        raise AssertionError("CSR comparisons incomplete")
    objects = ev.directory / "compile-obj"
    ev.run(["verilator", "--binary", "--timing", "--top-module", "counter_tb",
            "-Wno-fatal", "--Mdir", ev.relative(objects), "-o", "counter-sim",
            ev.relative(tb), "rtl/hammer_v5_csr.sv"], "counter-verilator-compile")
    try:
        text = ev.run(["./compile-obj/counter-sim"], "counter-verilator", cwd=ev.directory)
        if summary not in text:
            raise AssertionError("compiled CSR comparisons incomplete")
        ev.record["observed"] = {"compared": len(rows), "directed_scenarios": coverage}
    finally:
        if objects.is_dir():
            shutil.rmtree(objects)
