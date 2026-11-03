"""Genuine firmware layout and public-pin RTL boot experiments."""
import json
import os
import shutil
import struct
import tarfile

from evidence import ROOT, digest, remaining_seconds, stamp
from integration import ports

MODEL_FLAGS = ("-O3",)
BUILD_FLAGS = ("-MAKEFLAGS", "OPT_FAST=-O3 OPT_SLOW=-O3 OPT_GLOBAL=-O3")
SCHEDULER_CONFIG = """`verilator_config
split_var -module "hammer_v3_plic" -var "rank"
"""


def scheduler_configuration(ev):
    configuration = ev.directory / "scheduler.vlt"
    configuration.write_text(SCHEDULER_CONFIG)
    ev.record.setdefault("generated_sha256", {})[ev.relative(configuration)] = digest(configuration)
    return configuration


def boot_specialization(ev):
    """Expose the existing boot stimulus constants to the compiler, with pin guards."""
    source = ROOT / "rtl/hammer_v5_top.sv"
    interface = ports(source)
    dynamic = {
        "clk", "rst_n", "start", "m_mem_axi_awready", "m_mem_axi_wready",
        "m_mem_axi_arready", "m_mem_axi_rvalid", "m_mem_axi_rdata",
        "m_mem_axi_rlast", "m_mem_axi_bvalid",
    }
    constants = {name: int(name == "uart_rx") for direction, _, name in interface
                 if direction == "input" and name not in dynamic}
    declarations = [f"    {direction} wire {width} {name}"
                    for direction, width, name in interface]
    parameters = source.read_text().split("#(", 1)[1].split(") (", 1)[0]
    import re
    names = re.findall(r"parameter integer (\w+)\s*=", parameters)
    if not names or not dynamic <= {name for _, _, name in interface}:
        raise AssertionError("boot specialization no longer matches top interface")
    connections = [f".{name}(" + (("'1" if constants[name] else "'0")
                    if name in constants else name) + ")" for _, _, name in interface]
    guards = " ||\n        ".join(
        f"({name} !== " + ("'1" if value else "'0") + ")"
        for name, value in constants.items())
    wrapper = ev.directory / "boot-specialization.sv"
    wrapper.write_text(
        "module hammer_v5_boot_model #(" + parameters + ") (\n" +
        ",\n".join(declarations) + "\n);\n"
        "    always @* if (" + guards + ")\n"
        '        $fatal(1,"BOOT STIMULUS CONSTANT CHANGED");\n'
        "    hammer_v5_top #(" + ",".join(f".{name}({name})" for name in names) +
        ") dut (\n        " + ",\n        ".join(connections) + ");\nendmodule\n")
    ev.record.setdefault("generated_sha256", {})[ev.relative(wrapper)] = digest(wrapper)
    ev.record["boot_stimulus_constants"] = constants
    ev.save()
    return wrapper


def firmware_layout(ev, directory):
    elf = directory / "opensbi.elf"
    ev.version("riscv64-unknown-elf-readelf")
    for flag, label in (("-S", "sections"), ("-l", "segments"), ("-s", "symbols")):
        ev.run(["riscv64-unknown-elf-readelf", "-W", flag, ev.relative(elf)],
               "firmware-" + label)
    data = elf.read_bytes()
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise AssertionError("firmware must be little-endian ELF64")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    elf_type, machine, _, entry, phoff, shoff, _, _, phsize, phnum, shsize, shnum, _ = header
    if machine != 243:
        raise AssertionError("firmware is not RISC-V ELF")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize)
                for i in range(shnum)]
    symbols = {}
    for section in sections:
        if section[1] not in (2, 11):
            continue
        strings = sections[section[6]]
        table = data[strings[4]:strings[4] + strings[5]]
        for off in range(section[4], section[4] + section[5], section[9]):
            name, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, off)
            end = table.find(b"\0", name)
            symbols[table[name:end].decode()] = value
    names = ("_fw_start", "_fw_rw_start", "_fw_end",
             "__rel_dyn_start", "__rel_dyn_end")
    if any(name not in symbols for name in names[:3]):
        raise AssertionError("firmware missing required layout symbols")
    start, split, end = (symbols[name] for name in names[:3])
    span = split - start
    if start != 0x80000000 or entry != start or span <= 0 or span & (span - 1):
        raise AssertionError("firmware entry or power-of-two RX separation incorrect")
    if start & (span - 1) or not split <= end < 0x80200000:
        raise AssertionError("firmware PMP alignment or Linux overlap")
    relocation_symbols = [name in symbols for name in names[3:]]
    if all(relocation_symbols):
        if not start <= symbols[names[3]] <= symbols[names[4]] <= split:
            raise AssertionError("firmware relocations fall outside RX region")
    elif any(relocation_symbols) or elf_type != 2 or any(
            section[1] in (4, 9, 11) and section[5] for section in sections):
        raise AssertionError("nonempty/PIE relocations lack required boundary symbols")
    # GNU ld omits unreferenced PROVIDE symbols for the empty non-PIE section.
    for section in sections:
        _, _, flags, address, _, size, _, _, _, _ = section
        if not flags & 2 or size == 0:
            continue
        if not start <= address <= address + size <= end:
            raise AssertionError("allocated firmware section outside image")
        if flags & 1 and address < split:
            raise AssertionError("writable section precedes RX/RW split")
        if not flags & 1 and address + size > split:
            raise AssertionError("read-only section crosses RX/RW split")
    segments = []
    for i in range(phnum):
        kind, flags, offset, va, pa, filesz, memsz, alignment = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phsize)
        if kind != 1:
            continue
        if va != pa or not start <= pa <= pa + memsz <= end:
            raise AssertionError("firmware load segment outside declared image")
        if flags & 2 and pa < split:
            raise AssertionError("writable firmware load segment precedes RX/RW split")
        if not flags & 2 and pa + memsz > split:
            raise AssertionError("read-only firmware load segment crosses RX/RW split")
        if filesz > memsz or offset + filesz > len(data):
            raise AssertionError("invalid firmware load segment")
        segments.append({"flags": flags, "address": pa, "file_bytes": filesz,
                         "memory_bytes": memsz, "alignment": alignment})
    if not segments:
        raise AssertionError("firmware has no load segments")
    result = {"symbols": {name: symbols[name] for name in names if name in symbols},
              "elf_type": elf_type, "relocation_bounds_present": all(relocation_symbols),
              "rx_span": span, "segments": segments, "entry": entry}
    ev.record["firmware_layout"] = result
    ev.save()
    return result


def checked_images(ev, directory):
    directory = (ROOT / directory).resolve()
    directory.relative_to(ROOT)
    receipt_path = directory / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    if receipt["exit"] != 0:
        raise AssertionError("cannot consume unsuccessful software build")
    for name, expected in receipt["inputs"].items():
        if digest(ROOT / name) != expected:
            raise AssertionError(f"stale software input: {name}")
    for name, expected in receipt["outputs"].items():
        if digest(ROOT / name) != expected:
            raise AssertionError(f"corrupt software artifact: {name}")
    if not directory.is_relative_to(ev.directory):
        snapshot = ev.directory / ("boot-inputs-" + stamp())
        snapshot.mkdir()
        inputs, outputs = {}, {}
        for name, expected in receipt["inputs"].items():
            remaining_seconds()
            captured = ev.directory / "sources/software" / (ROOT / name).name
            if not captured.is_file() or digest(captured) != expected:
                captured = snapshot / ("input-" + expected)
                if not captured.exists():
                    shutil.copyfile(ROOT / name, captured)
            if digest(captured) != expected:
                raise AssertionError(f"software input snapshot mismatch: {name}")
            inputs[ev.relative(captured)] = expected
        for name, expected in receipt["outputs"].items():
            remaining_seconds()
            target = snapshot / (ROOT / name).name
            if target.exists():
                raise AssertionError("ambiguous software output snapshot basename")
            shutil.copy2(ROOT / name, target)
            if digest(target) != expected:
                raise AssertionError(f"software output snapshot mismatch: {name}")
            outputs[ev.relative(target)] = expected
        producer = snapshot / "producer-receipt.json"
        shutil.copyfile(receipt_path, producer)
        logs = {}
        paths = {receipt.get("stdout"), receipt.get("stderr")}
        for tool in receipt.get("tools", {}).values():
            paths.update((tool.get("stdout"), tool.get("stderr")))
        for name in sorted(path for path in paths if path):
            target = snapshot / ("producer-" + (ROOT / name).name)
            shutil.copyfile(ROOT / name, target)
            logs[ev.relative(target)] = digest(target)
        receipt = {
            "kind": "verifier-boot-input-snapshot", "exit": 0,
            "start": ev.record["start"], "end": stamp(),
            "producer_receipt": {"path": ev.relative(producer), "sha256": digest(producer)},
            "inputs": inputs, "outputs": outputs, "producer_logs_sha256": logs,
        }
        receipt_path = snapshot / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
        directory = snapshot
    manifest = json.loads((directory / "images.json").read_text())
    for image in manifest["images"]:
        if digest(directory / image["file"]) != image["sha256"]:
            raise AssertionError("boot image checksum mismatch")
    ev.record["software_build"] = {
        "receipt": ev.relative(receipt_path), "sha256": digest(receipt_path),
        "images": manifest["images"], "inputs": receipt["inputs"],
    }
    ev.save()
    firmware_layout(ev, directory)
    return directory, manifest


def firmware_diagnosis(ev, images):
    directory, _ = checked_images(ev, images)
    ev.version("riscv64-unknown-elf-addr2line")
    ev.version("riscv64-unknown-elf-objdump")
    ev.run(["riscv64-unknown-elf-addr2line", "-f", "-e",
            ev.relative(directory / "opensbi.elf"), "0x8000dde0", "0x80002ff2"],
           "boot-tail-functions")
    for start, end, label in (
            ("0x8000dd80", "0x8000de80", "caller"),
            ("0x80002fe0", "0x80003030", "comparison")):
        ev.run(["riscv64-unknown-elf-objdump", "-d",
                "--start-address=" + start, "--stop-address=" + end,
                ev.relative(directory / "opensbi.elf")], "boot-tail-" + label)


def custom_fault_expectations(ev, directory):
    ev.version("riscv64-unknown-elf-nm")
    text = ev.run(["riscv64-unknown-elf-nm", "--defined-only", "-n",
                   ev.relative(directory / "init.elf")], "init-symbols")
    names = ("hammer_try_misaligned_vload", "fault_handler")
    symbols = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in names:
            if parts[2] in symbols or parts[1] not in ("t", "T"):
                raise AssertionError("ambiguous/non-executable custom-fault symbol")
            symbols[parts[2]] = int(parts[0], 16)
    if set(symbols) != set(names):
        raise AssertionError("missing independent custom-fault ELF symbols")
    data = (directory / "init.elf").read_bytes()
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise AssertionError("userland must be little-endian ELF64")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    if header[0] != 2 or header[1] != 243:
        raise AssertionError("fault PC requires the pinned static RISC-V executable")
    pc = symbols[names[0]]
    instructions = []
    for index in range(header[9]):
        kind, flags, offset, va, _, filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, header[4] + index * header[8])
        if kind == 1 and flags & 1 and va <= pc <= va + filesz - 4:
            instructions.append(struct.unpack_from("<I", data, offset + pc - va)[0])
    if instructions != [0x0005000B]:
        raise AssertionError("misalignment symbol is not vload vr0,(a0)")
    manifest = json.loads((ROOT / "software/boot_manifest.json").read_text())
    linux, = (source for source in manifest["sources"] if source["version"] == "6.6.1")
    archive = ROOT / "software" / linux["file"]
    if digest(archive) != linux["sha256"]:
        raise AssertionError("pinned Linux fault ABI source checksum mismatch")
    with tarfile.open(archive, "r:xz") as source:
        member = source.extractfile(linux["root"] + "/arch/riscv/kernel/traps.c")
        if member is None:
            raise AssertionError("pinned Linux traps.c missing")
        traps = member.read().decode()
    normalized = " ".join(traps.split())
    if ('DO_ERROR_INFO(do_trap_load_misaligned, SIGBUS, BUS_ADRALN, ' not in normalized or
            'do_trap_error(regs, signo, code, regs->epc, "Oops - " str);' not in normalized):
        raise AssertionError("pinned Linux load-misalignment SIGBUS ABI changed")
    result = {"symbols": symbols, "init_sha256": digest(directory / "init.elf"),
              "linux_version": linux["version"], "linux_sha256": linux["sha256"],
              "cause": 4, "signal": 7, "si_code": 1, "si_addr_is_epc": True,
              "ucontext_gpr_offset": 176}
    path = ev.directory / "custom-fault-expectations.json"
    path.write_text(json.dumps(result, indent=2) + "\n")
    pcs = ev.directory / "custom-fault-pcs.txt"
    pcs.write_text(f"{pc:x} {symbols[names[1]]:x}\n")
    for generated in (path, pcs):
        ev.record.setdefault("generated_sha256", {})[ev.relative(generated)] = digest(generated)
    ev.record["custom_fault_contract"] = result
    ev.save()


HARNESS = r"""
#include "Vhammer_v5_top.h"
#include "verilated.h"
#include <array>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <climits>
#include <set>
#include <map>

static volatile std::sig_atomic_t stop_requested=0;
__BOOT_SUPPORT__
__ISA_ORACLE__
struct Record {uint64_t cycle,pc,next,data; uint32_t insn; unsigned rd,priv;};
int main(int argc,char **argv) {
 std::signal(SIGTERM, [](int) {stop_requested=1;});
 VerilatedContext context; context.threads(1); context.commandArgs(argc,argv);
 Vhammer_v5_top d(&context);
 Memory memory;
 ISA isa;
 CustomFaultObserver custom_fault;
 std::deque<Record> tail;
 uint64_t cycles=0,retired=0,reads=0,writes=0,sretired=0,uretired=0;
 uint64_t translated=0,custom=0,traps=0;
 uint64_t retirement_hash=14695981039346656037ULL;
 uint64_t last_pc=0,mtimer=0,stimer=0,timer_calls=0,time_reads=0;
 std::map<uint64_t,uint64_t> pc_samples;
 std::map<std::pair<uint64_t,uint64_t>,uint64_t> phase_samples;
 auto wall_start=std::chrono::steady_clock::now();
 std::ofstream uart("uart.txt",std::ios::binary), milestones("milestones.txt"),
               diagnostic("retirement-tail.txt"), counters("counter-reads.txt"),
               uart_events("uart-events.txt"), ecalls("user-ecalls.txt"),
               pids("user-pids.txt");
 std::ofstream timing("timekeeping-events.txt");
 auto profile=[&]() {
  std::ofstream samples("pc-samples.txt");
  for(const auto &entry:pc_samples)
   samples<<std::hex<<entry.first<<std::dec<<" "<<entry.second<<"\n";
  std::ofstream phases("boot-phase-samples.txt");
  for(const auto &entry:phase_samples)
   phases<<entry.first.first<<" "<<std::hex<<entry.first.second<<std::dec
    <<" "<<entry.second<<"\n";
  double seconds=std::chrono::duration<double>(
      std::chrono::steady_clock::now()-wall_start).count();
  std::ofstream report("boot-profile.json");
  report<<"{\"cycles\":"<<cycles<<",\"seconds\":"<<seconds
   <<",\"cycles_per_second\":"<<(seconds>0?cycles/seconds:0)
   <<",\"m_timer_traps\":"<<mtimer<<",\"s_timer_traps\":"<<stimer
   <<",\"sbi_timer_calls\":"<<timer_calls<<",\"time_reads\":"<<time_reads
   <<",\"sample_period_cycles\":1024}\n";
 };
 std::set<uint64_t> observed_pids;
 bool getpid_pending=false;
 uint64_t getpid_return_pc=0;
 try {
  if(argc!=6) throw std::runtime_error("usage: sim firmware kernel dtb cycles goal");
  memory.load(argv[1],0x80000000); memory.load(argv[2],0x80200000);
  memory.load(argv[3],0x87e00000);
  isa.bytes.load(argv[1],0x80000000); isa.bytes.load(argv[2],0x80200000);
  isa.bytes.load(argv[3],0x87e00000);
  uint64_t limit=std::stoull(argv[4]);
  std::string goal=argv[5],line;
  if(goal=="userland") custom_fault.load();
  bool aw=false,wd=false,read_pending=false,write_pending=false;
  uint64_t awaddr=0,wdata=0,rdata=0; unsigned wmask=0,rdelay=0,bdelay=0;
  uint32_t rng=17;
  unsigned divisor=1,lcr=0,uart_state=0,uart_bit=0,uart_data=0,bit_cycles=16;
  uint64_t sample_cycle=0; bool last_tx=true,done=false;
  auto next_heartbeat=std::chrono::steady_clock::now()+std::chrono::seconds(30);
__INITIALIZE_INPUTS__
  d.uart_rx=1;
  for(cycles=0;cycles<limit && !done && !stop_requested;cycles++) {
   bool reset=cycles<4;
   rng^=rng<<13; rng^=rng>>17; rng^=rng<<5;
   d.rst_n=!reset; d.start=!reset;
   d.m_mem_axi_awready=!reset && !aw && !write_pending && ((rng&3)!=0);
   d.m_mem_axi_wready=!reset && !wd && !write_pending && ((rng&12)!=0);
   d.m_mem_axi_arready=!reset && !read_pending && ((rng&48)!=0);
   d.m_mem_axi_rvalid=!reset && read_pending && rdelay==0;
   d.m_mem_axi_rdata=d.m_mem_axi_rvalid ? rdata : 0;
   d.m_mem_axi_rlast=d.m_mem_axi_rvalid;
   d.m_mem_axi_bvalid=!reset && write_pending && bdelay==0;
   d.clk=0; d.eval();
   bool accept_aw=d.m_mem_axi_awvalid && d.m_mem_axi_awready;
   bool accept_w=d.m_mem_axi_wvalid && d.m_mem_axi_wready;
   bool accept_ar=d.m_mem_axi_arvalid && d.m_mem_axi_arready;
   bool accept_r=d.m_mem_axi_rvalid && d.m_mem_axi_rready;
   bool accept_b=d.m_mem_axi_bvalid && d.m_mem_axi_bready;
   uint64_t captured_aw=d.m_mem_axi_awaddr,captured_ar=d.m_mem_axi_araddr;
   uint64_t captured_w=d.m_mem_axi_wdata;
   unsigned captured_mask=d.m_mem_axi_wstrb;
   if(accept_aw && (d.m_mem_axi_awlen!=0 || d.m_mem_axi_awsize!=3 ||
       d.m_mem_axi_awburst!=1 || d.m_mem_axi_awid!=0 || (captured_aw&7)))
    throw std::runtime_error("AXI write geometry");
   if(accept_w && !d.m_mem_axi_wlast) throw std::runtime_error("AXI missing WLAST");
   if(accept_ar && (d.m_mem_axi_arlen!=0 || d.m_mem_axi_arsize!=3 ||
       d.m_mem_axi_arburst!=1 || d.m_mem_axi_arid!=0 || (captured_ar&7)))
    throw std::runtime_error("AXI read geometry");
   if(!reset && d.retire_valid) {
    retired++;
    for(uint64_t value: {uint64_t(d.retire_pc),uint64_t(d.retire_next_pc),
                        uint64_t(d.retire_insn),uint64_t(d.retire_rd),
                        uint64_t(d.retire_rd_we),uint64_t(d.retire_rd_data),
                        uint64_t(d.retire_priv)})
     retirement_hash=(retirement_hash^value)*1099511628211ULL;
    last_pc=d.retire_pc;
    if((d.retire_insn>>20)==0xc01 && (d.retire_insn&127)==0x73 &&
       ((d.retire_insn>>12)&7) && d.retire_rd_we) {
     if(++time_reads<=16)
      timing<<"TIME "<<cycles<<" "<<d.retire_rd_data<<"\n";
    }
    if(d.retire_priv==0 && getpid_pending && d.retire_pc==getpid_return_pc) {
     if(!isa.x[10] || isa.x[10]>0x100000ULL)
      throw std::runtime_error("invalid actual U getpid return");
     observed_pids.insert(isa.x[10]);
     pids<<cycles<<" "<<isa.x[10]<<"\n"; getpid_pending=false;
    }
    custom_fault.retirement(d,isa.x,cycles);
    isa.compare(d,cycles);
    if(d.retire_priv==0 && (d.retire_insn&127)==0x73 &&
       ((d.retire_insn>>12)&7) && d.retire_rd_we) {
     unsigned address=d.retire_insn>>20;
     if(address>=0xc00 && address<=0xc06)
      counters<<cycles<<" "<<std::hex<<address<<" "<<d.retire_rd_data<<std::dec<<"\n";
    }
    tail.push_back({cycles,d.retire_pc,d.retire_next_pc,d.retire_rd_data,
                    d.retire_insn,d.retire_rd,d.retire_priv});
    if(tail.size()>32) tail.pop_front();
    if(d.retire_priv==1 && ++sretired==1)
     milestones<<"S_MODE cycle="<<cycles<<" pc="<<std::hex<<d.retire_pc<<std::dec<<"\n";
    if(d.retire_priv==0 && ++uretired==1)
     milestones<<"U_MODE cycle="<<cycles<<" pc="<<std::hex<<d.retire_pc<<std::dec<<"\n";
    if(d.retire_priv<3 && d.retire_pc>=0xffffffc000000000ULL) {
     if(++translated==1) milestones<<"HIGH_VA_RETIRED cycle="<<cycles<<"\n";
    }
    if(d.retire_priv==0 && (d.retire_insn&127)==11) {
     if(++custom==1) milestones<<"U_CUSTOM cycle="<<cycles<<"\n";
    }
    if(d.retire_mem_valid && d.retire_mem_write &&
       d.retire_mem_addr>=0x10010000 && d.retire_mem_addr<0x10010008) {
     unsigned offset=d.retire_mem_addr&7;
     unsigned byte=(d.retire_mem_wdata>>(offset*8))&255;
     if(offset==3) lcr=byte;
     if((lcr&128) && offset==0) divisor=(divisor&0xff00)|byte;
     if((lcr&128) && offset==1) divisor=(divisor&255)|(byte<<8);
    }
   }
   if(!reset && d.trap_valid) {
    traps++;
    custom_fault.trap(d,isa.x,cycles,uretired!=0);
    uint64_t cause=d.trap_cause&0x7fffffffffffffffULL;
    if(d.trap_interrupt && cause==7) mtimer++;
    if(d.trap_interrupt && cause==5) stimer++;
    if(!d.trap_interrupt && d.trap_cause==9 &&
       (isa.x[17]==0 || (isa.x[17]==0x54494d45 && isa.x[16]==0))) {
     if(++timer_calls<=16)
      timing<<"SET_TIMER "<<cycles<<" "<<isa.x[10]<<"\n";
    }
    if(!d.trap_interrupt && d.trap_cause==8) {
     ecalls<<cycles<<" "<<isa.x[17]<<" "<<isa.x[10]<<"\n";
     if(isa.x[17]==172) {getpid_pending=true;getpid_return_pc=d.trap_pc+4;}
    }
    if(traps<=16) milestones<<"TRAP cycle="<<cycles<<" pc="<<std::hex<<d.trap_pc
     <<" cause="<<d.trap_cause<<" tval="<<d.trap_tval<<std::dec<<"\n";
   }
   if(d.boot_error) throw std::runtime_error("boot loader error");
   d.clk=1; d.eval(); context.timeInc(10);
   if(reset) {aw=wd=read_pending=write_pending=false;}
   else {
    if(accept_r) read_pending=false;
    else if(read_pending && rdelay) rdelay--;
    if(accept_b) write_pending=false;
    else if(write_pending && bdelay) bdelay--;
    if(accept_aw) {aw=true; awaddr=captured_aw;}
    if(accept_w) {wd=true; wdata=captured_w; wmask=captured_mask;}
    if(aw && wd) {
     memory.masked_word(awaddr,wdata,wmask);
     writes++; aw=wd=false; write_pending=true; bdelay=1+((rng>>6)&3);
    }
    if(accept_ar) {
     rdata=memory.word(captured_ar); reads++; read_pending=true; rdelay=1+((rng>>8)&3);
    }
   }
   bool tx=d.uart_tx;
   if(!reset && !uart_state && last_tx && !tx) {
    if((lcr&3)!=3 || (lcr&12))
     throw std::runtime_error("boot UART requires actual 8N1 programming");
    bit_cycles=16*(divisor ? divisor : 1);
    uart_state=1; sample_cycle=cycles+bit_cycles/2; uart_data=uart_bit=0;
   }
   if(uart_state && cycles==sample_cycle) {
    if(uart_state==1) {
     if(tx) throw std::runtime_error("UART false start");
     uart_state=2; sample_cycle+=bit_cycles;
    } else if(uart_state==2) {
     uart_data|=unsigned(tx)<<uart_bit++;
     sample_cycle+=bit_cycles;
     if(uart_bit==8) uart_state=3;
    } else {
     if(!tx) throw std::runtime_error("UART stop-bit error");
     char c=char(uart_data); uart.put(c); line+=c; uart_state=0;
     if(c=='\n') {
      uart_events<<cycles<<" "<<line;
      if(line.find("HV5 FAIL")!=std::string::npos ||
         line.find("Kernel panic")!=std::string::npos)
       throw std::runtime_error("genuine software reported failure: "+line);
      if(goal=="userland" && line.find("HV5 DONE")!=std::string::npos) done=true;
      if(goal=="linux" && line.find("Linux version")!=std::string::npos) done=true;
      line.clear();
     }
     if(line.size()>4096) throw std::runtime_error("UART line bound");
    }
   }
   last_tx=tx;
   if((cycles&1023)==0) {
    pc_samples[last_pc]++;
    phase_samples[{cycles/50000000,last_pc}]++;
    auto now=std::chrono::steady_clock::now();
    if(now>=next_heartbeat) {
     std::cout<<"PROGRESS boot cycles="<<cycles<<" retired="<<retired
      <<" reads="<<reads<<" S="<<sretired<<" U="<<uretired<<std::endl;
     uart.flush(); milestones.flush(); custom_fault.output.flush();
     profile();
     next_heartbeat=now+std::chrono::seconds(30);
    }
   }
   if(context.gotFinish()) throw std::runtime_error("RTL terminated before boot goal");
  }
  uart.flush(); milestones.flush();
  std::ofstream result("boot-observed.json");
  result<<"{\"cycles\":"<<cycles<<",\"retired\":"<<retired<<",\"dram_reads\":"<<reads
   <<",\"dram_writes\":"<<writes<<",\"s_retired\":"<<sretired<<",\"u_retired\":"<<uretired
   <<",\"high_va_retired\":"<<translated<<",\"u_custom\":"<<custom
   <<",\"traps\":"<<traps<<",\"integer_checks\":"<<isa.checked
   <<",\"m_mode_load_checks\":"<<isa.loads<<",\"m_mode_store_checks\":"<<isa.stores
   <<",\"user_pid_count\":"<<observed_pids.size()
   <<",\"retirement_hash\":"<<retirement_hash
   <<",\"goal_reached\":"<<(done?"true":"false")<<"}\n";
  if(!done) throw std::runtime_error(stop_requested
      ? "RTL boot cancelled by owning invocation timeout"
      : "bounded RTL boot goal not reached");
  if(!sretired) throw std::runtime_error("banner without actual S-mode retirement");
  if(goal=="userland" && (!uretired || !custom || !translated))
   throw std::runtime_error("userland marker without public architectural milestones");
  if(goal=="userland") custom_fault.complete();
  for(const auto &r:tail) diagnostic<<"cycle="<<r.cycle<<" pc="<<std::hex<<r.pc
   <<" next="<<r.next<<" insn="<<r.insn<<" rd="<<r.rd<<" data="<<r.data
   <<" priv="<<r.priv<<std::dec<<"\n";
  std::cout<<"SUMMARY genuine RTL boot goal="<<goal<<" cycles="<<cycles
   <<" retired="<<retired<<std::endl;
  d.final(); return 0;
 } catch(const std::exception &e) {
  uart.flush(); milestones.flush(); custom_fault.output.flush();
  profile();
  for(const auto &r:tail) diagnostic<<"cycle="<<r.cycle<<" pc="<<std::hex<<r.pc
   <<" next="<<r.next<<" insn="<<r.insn<<" rd="<<r.rd<<" data="<<r.data
   <<" priv="<<r.priv<<std::dec<<"\n";
  std::cerr<<"BOOT EXPERIMENT FAILED: "<<e.what()<<std::endl;
  d.final(); return 1;
 }
}
"""


def compile_model(ev, text=HARNESS, parameters=None):
    interface = ports(ROOT / "rtl/hammer_v5_top.sv")
    initialization = "\n".join(
        f"  d.{name}=0;" for direction, _, name in interface if direction == "input")
    harness = ev.directory / "boot.cpp"
    from rv64 import CPP, decode_image
    from boot_support import CPP as SUPPORT
    table = ev.directory / "decode.bin"
    decode_image(table)
    harness.write_text(text.replace("__INITIALIZE_INPUTS__", initialization)
                      .replace("__ISA_ORACLE__", CPP)
                      .replace("__BOOT_SUPPORT__", SUPPORT))
    ev.record.setdefault("generated_sha256", {})[ev.relative(table)] = digest(table)
    ev.record.setdefault("generated_sha256", {})[ev.relative(harness)] = digest(harness)
    ev.version("verilator")
    ev.version("make")
    ev.version("g++")
    objects = ev.directory / "compile-obj"
    objects.mkdir()
    sources = sorted((ROOT / "rtl").glob("*.sv"))
    ev.run(["verilator", "--cc", "--exe", "--build", "-j", "2", "-Wno-fatal",
            *MODEL_FLAGS,
            *BUILD_FLAGS,
            "--top-module", "hammer_v5_top",
            *[f"-G{name}={value}" for name, value in (parameters or {}).items()],
            "--Mdir", ".", "-o", "boot-sim",
            "../boot.cpp", *[os.path.relpath(p, objects) for p in sources]],
           "boot-compile", cwd=objects)
    return objects


def boot_probe(ev, images, cycles=100000000, goal="linux", prefetch=1, parameters=None):
    directory, _ = checked_images(ev, images)
    ev.record["scope"] = {
        "top": "hammer_v5_top", "public_pin_only": True, "goal": goal,
        "cycle_bound": cycles, "prefetch": prefetch,
        "parameters": parameters or {},
        "not_full_linux_acceptance": goal != "userland",
    }
    if goal == "userland":
        custom_fault_expectations(ev, directory)
    objects = compile_model(ev, parameters={**(parameters or {}), "PREFETCH_ENABLE": prefetch})
    try:
        ev.run(["./compile-obj/boot-sim",
                os.path.relpath(directory / "opensbi.bin", ev.directory),
                os.path.relpath(directory / "Image", ev.directory),
                os.path.relpath(directory / "hammer_v5.dtb", ev.directory),
                str(cycles), goal], "boot-run", cwd=ev.directory, timeout_s=None)
        ev.record["observed"] = json.loads((ev.directory / "boot-observed.json").read_text())
        if goal == "userland":
            from userland import compare_userland
            ev.record["userland_comparisons"] = compare_userland(ev.directory)
    finally:
        observed = ev.directory / "boot-observed.json"
        if observed.is_file():
            try:
                ev.record["observed"] = json.loads(observed.read_text())
            except json.JSONDecodeError as error:
                ev.record["observed_parse_error"] = str(error)
            ev.save()
        if objects.is_dir():
            shutil.rmtree(objects)
