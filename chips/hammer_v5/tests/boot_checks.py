"""Disposable host-model checks; no synthetic fixture is Linux/RTL evidence."""
from boot_support import CPP
from evidence import digest


HOST_CHECK = r"""
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
__BOOT_SUPPORT__
static unsigned checks=0,rejections=0;
static void check(bool condition,const char *message) {
 if(!condition) throw std::runtime_error(message);
 checks++;
}
template<class F> void reject(F action,const std::string &message) {
 try {action();}
 catch(const std::runtime_error &error) {
  if(std::string(error.what()).find(message)==std::string::npos) throw;
  rejections++; return;
 }
 throw std::runtime_error("host checker accepted disposable defect: "+message);
}
struct Pins {
 unsigned retire_priv=0,retire_insn=0x3003,retire_rd_we=1;
 bool retire_mem_valid=true,retire_mem_write=false,trap_interrupt=false;
 uint64_t retire_pc=0,retire_mem_addr=0,retire_rd_data=0,trap_pc=0,trap_cause=0,trap_tval=0;
};
static void fault_scenario(unsigned defect) {
 CustomFaultObserver observer;
 observer.pc=0x10100; observer.handler=0x10500;
 Pins p;
 std::array<uint64_t,32> x{};
 x[10]=0x3fffffe001ULL;
 p.trap_pc=observer.pc; p.trap_cause=4; p.trap_tval=x[10];
 if(defect==1) p.trap_pc+=4;
 if(defect==2) p.trap_cause=6;
 if(defect==3) p.trap_tval=observer.pc;
 observer.trap(p,x,10,true);
 if(defect==4) {
  p.retire_pc=observer.pc;
  observer.retirement(p,x,11);
 }
 p.retire_pc=observer.handler;
 x[10]=7; x[11]=0x20000; x[12]=0x21000;
 observer.retirement(p,x,20);
 p.retire_pc+=4;
 for(unsigned field=0;field<4;field++) {
  if(defect==9 && field==3) continue;
  p.retire_mem_addr=field==0?x[11]+8:field==1?x[11]+16:
                    x[12]+176+(field==3?80:0);
  p.retire_rd_data=field==0?1:field==3?0x3fffffe001ULL:observer.pc;
  p.retire_insn=field==0?0x2003:0x3003;
  if(defect==5+field) p.retire_rd_data^=4;
  observer.retirement(p,x,21+field);
 }
 p.trap_pc=0x10600; p.trap_cause=8; p.trap_tval=0; x[17]=139;
 observer.trap(p,x,25,true);
 observer.complete();
}
int main() {
 try {
  Memory memory;
  std::unordered_map<uint64_t,uint8_t> bytes;
  auto compare=[&](uint64_t address) {
   uint64_t expected=0;
   for(unsigned lane=0;lane<8;lane++)
    expected|=uint64_t(bytes[address+lane])<<(lane*8);
   check(memory.word(address)==expected,"host byte/word comparison");
  };
  for(uint64_t a:{Memory::base,Memory::base+4088,Memory::base+4096,Memory::end-8}) {
   compare(a);
   for(unsigned mask=0;mask<256;mask++) {
    uint64_t data=0xfedcba9876543210ULL^(0x0101010101010101ULL*mask);
    memory.masked_word(a,data,mask);
    for(unsigned lane=0;lane<8;lane++)
     if((mask>>lane)&1) bytes[a+lane]=data>>(lane*8);
    compare(a);
   }
  }
  for(unsigned offset=1;offset<8;offset++) compare(Memory::base+4096-offset);
  uint32_t rng=17;
  for(unsigned iteration=0;iteration<20000;iteration++) {
   rng^=rng<<13; rng^=rng>>17; rng^=rng<<5;
   uint64_t a=Memory::base+(rng&8191),data=uint64_t(rng)*0x100000001ULL;
   if(rng&1) {
    memory.write(a,data&255); bytes[a]=data&255;
   } else {
    a&=~7ULL; unsigned mask=(rng>>16)&255;
    memory.masked_word(a,data,mask);
    for(unsigned lane=0;lane<8;lane++)
     if((mask>>lane)&1) bytes[a+lane]=data>>(lane*8);
   }
   compare(a);
  }
  std::vector<uint8_t> image(8205);
  for(unsigned i=0;i<image.size();i++) image[i]=(i*37)^(i>>3);
  {
   std::ofstream out("host-image.bin",std::ios::binary);
   out.write(reinterpret_cast<const char *>(image.data()),image.size());
  }
  for(uint64_t a:{Memory::base+123,Memory::end-image.size()}) {
   memory.load("host-image.bin",a);
   for(unsigned i=0;i<image.size();i++) bytes[a+i]=image[i];
   for(unsigned i=0;i+8<=image.size();i+=7) compare(a+i);
  }
  for(uint64_t a:{Memory::base-1,Memory::end,UINT64_MAX})
   reject([&](){memory.read(a);},"aperture");
  reject([&](){memory.word(Memory::end-7);},"aperture");
  reject([&](){memory.masked_word(Memory::base+1,0,255);},"unaligned");
  memory.masked_word(Memory::end,0,0);
  fault_scenario(0);
  reject([](){fault_scenario(1);},"unique custom misalignment");
  for(unsigned defect:{2,3})
   reject([&](){fault_scenario(defect);},"PC/cause/effective-address");
  reject([](){fault_scenario(4);},"retired instead of trapping");
  for(unsigned defect=5;defect<=8;defect++)
   reject([&](){fault_scenario(defect);},"pinned Linux SIGBUS");
  reject([](){fault_scenario(9);},"all independent ABI field checks");
  CustomFaultObserver missing;
  reject([&](){missing.complete();},"missing independent custom");
  std::cout<<"SUMMARY host-memory compared="<<checks<<" defect_rejections="<<rejections<<"\n";
  return 0;
 } catch(const std::exception &error) {
  std::cerr<<"HOST CHECK FAILED: "<<error.what()<<"\n"; return 1;
 }
}
"""


def boot_support_probe(ev):
    source = ev.directory / "boot-support-check.cpp"
    source.write_text(HOST_CHECK.replace("__BOOT_SUPPORT__", CPP))
    ev.record.setdefault("generated_sha256", {})[ev.relative(source)] = digest(source)
    ev.version("g++")
    binary = ev.directory / "boot-support-check"
    ev.run(["g++", "-std=c++17", "-O3", "-Wall", "-Wextra", "-Werror",
            source.name, "-o", binary.name], "boot-support-compile", cwd=ev.directory)
    try:
        text = ev.run(["./" + binary.name], "boot-support-run", cwd=ev.directory)
        if "SUMMARY host-memory compared=23379 defect_rejections=15" not in text:
            raise AssertionError("host memory/custom-fault checker comparisons incomplete")
        ev.record["boot_support_checks"] = {
            "byte_model_comparisons": 23379, "host_defect_rejections": 15,
            "synthetic_only": True}
        ev.save()
    finally:
        if binary.is_file():
            binary.unlink()
