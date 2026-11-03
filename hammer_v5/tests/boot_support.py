"""Host-only boot memory and public-pin custom-fault observations."""

CPP = r"""
using Page = std::array<uint8_t,4096>;
struct Memory {
 static constexpr uint64_t base=0x80000000ULL,end=0x100000000ULL;
 std::vector<std::unique_ptr<Page>> pages{(end-base)/4096};
 void valid(uint64_t a,unsigned size=1) const {
  if(a<base || a>=end || size>end-a)
   throw std::runtime_error("DRAM address out of inherited aperture");
 }
 uint8_t read(uint64_t a) const {
  valid(a); const auto &p=pages[(a-base)>>12];
  return p ? (*p)[a&4095] : 0;
 }
 void write(uint64_t a,uint8_t v) {
  valid(a); auto &p=pages[(a-base)>>12];
  if(!p) p=std::make_unique<Page>();
  (*p)[a&4095]=v;
 }
 uint64_t word(uint64_t a) const {
  valid(a,8);
  uint64_t v=0;
  if((a&4095)<=4088) {
   const auto &p=pages[(a-base)>>12];
   if(p) for(unsigned i=0;i<8;i++) v|=uint64_t((*p)[(a&4095)+i])<<(8*i);
  } else {
   for(unsigned i=0;i<8;i++) v|=uint64_t(read(a+i))<<(8*i);
  }
  return v;
 }
 void masked_word(uint64_t a,uint64_t data,unsigned mask) {
  if(!mask) return;
  valid(a,8);
  if(a&7) throw std::runtime_error("unaligned AXI backing write");
  auto &p=pages[(a-base)>>12];
  if(!p) p=std::make_unique<Page>();
  for(unsigned i=0;i<8;i++) if((mask>>i)&1) (*p)[(a&4095)+i]=data>>(8*i);
 }
 void load(const std::string &path,uint64_t address) {
  std::ifstream f(path,std::ios::binary);
  if(!f) throw std::runtime_error("missing actual boot image");
  std::array<char,4096> buffer;
  while(f) {
   auto count=4096-(address&4095);
   f.read(buffer.data(),count);
   auto got=f.gcount();
   if(got) {
    valid(address,unsigned(got));
    auto &p=pages[(address-base)>>12];
    if(!p) p=std::make_unique<Page>();
    for(unsigned i=0;i<unsigned(got);i++) (*p)[(address&4095)+i]=uint8_t(buffer[i]);
    address+=got;
   }
  }
  if(!f.eof()) throw std::runtime_error("boot image read error");
 }
};

struct CustomFaultObserver {
 uint64_t pc=0,handler=0,address=0,info=0,context_address=0;
 unsigned traps=0,signals=0,returns=0,fields=0,logged=0;
 bool active=false;
 std::ofstream output{"custom-faults.txt"};
 void load() {
  std::ifstream input("custom-fault-pcs.txt");
  if(!(input>>std::hex>>pc>>handler) || !pc || !handler || pc==handler)
   throw std::runtime_error("missing independent custom-fault ELF symbols");
 }
 template<class D> void retirement(const D &d,const std::array<uint64_t,32> &x,
                                   uint64_t cycle) {
  if(!pc || d.retire_priv!=0) return;
  if(d.retire_pc==pc)
   throw std::runtime_error("misaligned custom load retired instead of trapping");
  if(d.retire_pc==handler && x[10]==7) {
   if(traps!=1 || signals++ || active)
    throw std::runtime_error("SIGBUS without unique custom misalignment trap");
   info=x[11]; context_address=x[12]; active=true;
   output<<"SIGBUS "<<cycle<<" "<<std::hex<<d.retire_pc<<" "<<info<<" "
    <<context_address<<std::dec<<"\n";
  }
  if(!active || (d.retire_insn&127)!=3 || !d.retire_mem_valid ||
     d.retire_mem_write || !d.retire_rd_we) return;
  uint64_t a=d.retire_mem_addr,expected=0;
  unsigned bit=0,f3=(d.retire_insn>>12)&7;
  const char *name="";
  if(a==info+8) {bit=1;expected=1;name="SIGCODE";}
  if(a==info+16) {bit=2;expected=pc;name="SIGADDR";}
  if(a==context_address+176) {bit=4;expected=pc;name="SIGPC";}
  if(a==context_address+176+10*8) {bit=8;expected=address;name="SIGA0";}
  if(!bit) return;
  if((bit==1 ? (f3!=2 && f3!=6) : f3!=3) || d.retire_rd_data!=expected)
   throw std::runtime_error(std::string("pinned Linux SIGBUS ")+name+" mismatch");
  if(!(fields&bit)) output<<name<<" "<<cycle<<" "<<std::hex<<a<<" "
   <<d.retire_rd_data<<std::dec<<"\n";
  fields|=bit;
 }
 template<class D> void trap(const D &d,const std::array<uint64_t,32> &x,
                             uint64_t cycle,bool user_seen) {
  if(!pc || d.trap_interrupt) return;
  if(d.trap_pc==pc) {
   if(traps++ || d.trap_cause!=4 || d.trap_tval!=x[10] || (x[10]&7)!=1)
    throw std::runtime_error("custom misalignment PC/cause/effective-address mismatch");
   address=x[10];
   output<<"MISALIGNED "<<cycle<<" "<<std::hex<<d.trap_pc<<" "<<d.trap_cause
    <<" "<<d.trap_tval<<" "<<x[10]<<std::dec<<"\n";
  }
  if(active && d.trap_cause==8 && x[17]==139) {
   if(fields!=15)
    throw std::runtime_error("SIGBUS returned without all independent ABI field checks");
   returns++; active=false;
   output<<"SIGRETURN "<<cycle<<"\n";
  }
  if(user_seen && d.trap_cause!=8 && d.trap_pc<0x80000000ULL && logged++<64)
   output<<"USER_TRAP "<<cycle<<" "<<std::hex<<d.trap_pc<<" "<<d.trap_cause
    <<" "<<d.trap_tval<<std::dec<<"\n";
 }
 void complete() {
  output.flush();
  if(traps!=1 || signals!=1 || returns!=1 || fields!=15 || active)
   throw std::runtime_error("missing independent custom misalignment/SIGBUS comparisons");
 }
};
"""
