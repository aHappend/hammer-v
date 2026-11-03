"""Real top-level accelerator ownership and self-modifying-code fence checks."""
import json
import shutil

from boot import HARNESS, compile_model
from compressed import iword, sword
from evidence import digest


def workload():
    code = bytearray()

    def emit(word):
        code.extend(word.to_bytes(4, "little"))

    def constant(rd, value):
        result = bytearray(iword(0x13, rd, 0, 0, value >> 55).to_bytes(4, "little"))
        for shift in (44, 33, 22, 11, 0):
            result.extend(iword(0x13, rd, 1, rd, 11).to_bytes(4, "little"))
            result.extend(iword(0x13, rd, 6, rd, (value >> shift) & 2047).to_bytes(4, "little"))
        return result

    code.extend(constant(8, 0x80100000))
    code.extend(constant(9, 0x1122334455667788))
    emit(sword(8, 9, 3, 0))
    emit(iword(3, 10, 3, 8, 0))
    emit(iword(0x13, 13, 0, 0, 0))
    pointer = len(code)
    code.extend(constant(5, 0))
    arm = 0x80000000 + len(code)
    emit(iword(0x13, 12, 0, 0, 1))
    for _ in range(400):
        emit(0x13)
    emit(iword(3, 11, 3, 8, 0))
    emit(sword(8, 9, 3, 8))
    code.extend(constant(9, 0x00008067 << 32 | iword(0x13, 12, 0, 0, 2)))
    calls = [len(code)]
    emit(0)
    emit(sword(5, 9, 3, 0))
    emit(0x0FF0000F)
    emit(0x0000100F)
    emit(0x12000073)
    calls.append(len(code))
    emit(0)
    end = 0x80000000 + len(code)
    code.extend(b"\x02\x90")
    while len(code) & 7:
        code.extend(b"\x01\x00")
    target = 0x80000000 + len(code)
    code[pointer:pointer + 44] = constant(5, target)
    for position in calls:
        jump = target - (0x80000000 + position)
        word = ((jump >> 20) & 1) << 31 | ((jump >> 1) & 1023) << 21 | (
            (jump >> 11) & 1) << 20 | ((jump >> 12) & 255) << 12 | (1 << 7) | 0x6F
        code[position:position + 4] = word.to_bytes(4, "little")
    emit(iword(0x13, 12, 0, 0, 1))
    emit(0x00008067)
    if len(code) > 2048:
        raise AssertionError("self-modifying code must retain its warmed instruction-cache set")
    return code, arm, target, end


def coherence_probe(ev):
    code, arm, target, end = workload()
    image = ev.directory / "coherence.bin"
    image.write_bytes(code)
    empty = ev.directory / "empty.bin"
    empty.write_bytes(b"")
    ev.record.setdefault("generated_sha256", {})[ev.relative(image)] = digest(image)
    text = HARNESS.replace(
        "uint64_t cycles=0,retired=0",
        "unsigned target_hits=0,acc_phase=0,hold=0; bool acc_aw=false,acc_w=false,"
        "acc_read_done=false,acc_write_done=false;\n uint64_t cycles=0,retired=0")
    text = text.replace("d.start=!reset;", "d.start=!reset && retired==0;")
    text = text.replace("d.clk=0; d.eval();", r"""
   d.s_acc_axi_awvalid=!reset && acc_phase==1 && !acc_aw;
   d.s_acc_axi_awaddr=d.s_acc_axi_awvalid?0x80100000ULL:0;
   d.s_acc_axi_awid=3; d.s_acc_axi_awlen=0; d.s_acc_axi_awsize=3;
   d.s_acc_axi_awburst=1;
   d.s_acc_axi_wvalid=!reset && acc_phase==1 && !acc_w;
   d.s_acc_axi_wdata=d.s_acc_axi_wvalid?0x8877665544332211ULL:0;
   d.s_acc_axi_wstrb=d.s_acc_axi_wvalid?0x5a:0;
   d.s_acc_axi_wlast=d.s_acc_axi_wvalid;
   d.s_acc_axi_bready=acc_phase==2 && hold>=5;
   d.s_acc_axi_arvalid=!reset && acc_phase==5;
   d.s_acc_axi_araddr=d.s_acc_axi_arvalid?0x80100008ULL:0;
   d.s_acc_axi_arid=7; d.s_acc_axi_arlen=0; d.s_acc_axi_arsize=3;
   d.s_acc_axi_arburst=1;
   d.s_acc_axi_rready=acc_phase==6 && hold>=5;
   d.clk=0; d.eval();
   bool sa=d.s_acc_axi_awvalid && d.s_acc_axi_awready;
   bool sw=d.s_acc_axi_wvalid && d.s_acc_axi_wready;
   bool sb=d.s_acc_axi_bvalid && d.s_acc_axi_bready;
   bool sr=d.s_acc_axi_arvalid && d.s_acc_axi_arready;
   bool sd=d.s_acc_axi_rvalid && d.s_acc_axi_rready;
   if(d.s_acc_axi_bvalid) {
    if(acc_phase!=2 || d.s_acc_axi_bid!=3 || d.s_acc_axi_bresp)
     throw std::runtime_error("accelerator write response classification");
    hold++;
   }
   if(d.s_acc_axi_rvalid) {
    if(acc_phase!=6 || d.s_acc_axi_rid!=7 || !d.s_acc_axi_rlast ||
       d.s_acc_axi_rresp || d.s_acc_axi_rdata!=0x1122334455667788ULL ||
       memory.word(0x80100008ULL)!=0x1122334455667788ULL)
     throw std::runtime_error("CPU dirty writes not coherently visible to accelerator");
    hold++;
   }
""")
    text = text.replace("isa.compare(d,cycles);", "isa.compare(d,cycles);\n" +
                        f"if(d.retire_pc==0x{arm:x}ULL) acc_phase=1;\n" +
                        f"if(d.retire_pc==0x{target:x}ULL) {{\n"
                        " if(d.retire_rd_data!=(target_hits?2:1)) "
                        'throw std::runtime_error("FENCE.I observed stale self-modified code");\n'
                        " target_hits++;\n"
                        "}\n"
                        "if(d.retire_mem_valid && d.retire_mem_write && "
                        "d.retire_mem_addr==0x80100008ULL) {\n"
                        ' if(!acc_write_done) throw std::runtime_error("CPU resumed before accelerator write completion");\n'
                        " acc_phase=5;\n}\n")
    text = text.replace("d.clk=1; d.eval(); context.timeInc(10);", r"""
   d.clk=1; d.eval(); context.timeInc(10);
   if(sa) acc_aw=true;
   if(sw) acc_w=true;
   if(acc_phase==1 && acc_aw && acc_w) {acc_phase=2;hold=0;}
   if(sb) {
    uint64_t value=0x8877665544332211ULL;
    for(unsigned lane=0;lane<8;lane++) if((0x5a>>lane)&1)
     isa.bytes.write(0x80100000ULL+lane,value>>(8*lane));
    if(memory.word(0x80100000ULL)!=isa.bytes.word(0x80100000ULL))
     throw std::runtime_error("accelerator success acknowledged before write-through completion");
    acc_write_done=true;acc_phase=3;hold=0;
   }
   if(sr) {acc_phase=6;hold=0;}
   if(sd) {acc_read_done=true;acc_phase=7;}
""")
    text = text.replace("traps++;", f"traps++;\nif(d.trap_pc!=0x{end:x}ULL || "
                        "d.trap_cause!=3 || d.trap_interrupt || target_hits!=2 || "
                        "!acc_read_done || !acc_write_done) "
                        'throw std::runtime_error("coherence/fence coverage or final trap");\n'
                        "done=true;")
    text = text.replace("if(!sretired)", 'if(goal!="coherence" && !sretired)')
    parameters = {"IMEM_WORDS": 32, "DMEM_WORDS": 1, "BTB_ENTRIES": 1,
                  "ICACHE_LINES": 64, "DCACHE_LINES": 1,
                  "ITLB_ENTRIES": 1, "DTLB_ENTRIES": 1, "L2_SETS": 1}
    objects = compile_model(ev, text, parameters)
    try:
        ev.run(["./compile-obj/boot-sim", image.name, empty.name, empty.name,
                "1000000", "coherence"], "coherence-run", cwd=ev.directory)
        ev.record["observed"] = json.loads((ev.directory / "boot-observed.json").read_text())
        ev.record["coherence"] = {"cpu_to_accelerator": 1, "accelerator_to_cpu": 1,
                                  "masked_write": 0x5A, "fence_i_code_versions": [1, 2],
                                  "fence": 1, "sfence_vma": 1, "parameters": parameters}
    finally:
        shutil.rmtree(objects)
