"""Compiled ISA oracle: architectural values, not RTL pipeline/state equations."""
from compressed import decode


def decode_image(path):
    import struct
    path.write_bytes(b"".join(
        struct.pack("<IB", expanded, illegal)
        for expanded, illegal, _ in (decode(c) for c in range(65536))))


CPP = r"""
static uint64_t sext(uint64_t value,unsigned bits) {
 uint64_t sign=1ULL<<(bits-1);
 return (value^sign)-sign;
}
struct ISA {
 std::array<uint64_t,32> x{};
 std::array<uint32_t,65536> expanded{};
 std::array<bool,65536> illegal{};
 Memory bytes;
 uint64_t checked=0,loads=0,stores=0;
 ISA() {
  std::ifstream f("decode.bin",std::ios::binary);
  if(!f) throw std::runtime_error("missing independent RV64C oracle");
  for(unsigned i=0;i<65536;i++) {
   uint8_t b[5]; f.read(reinterpret_cast<char *>(b),5);
   if(!f) throw std::runtime_error("truncated independent RV64C oracle");
   expanded[i]=uint32_t(b[0])|(uint32_t(b[1])<<8)|(uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);
   illegal[i]=b[4];
  }
 }
 void compare(Vhammer_v5_top &d,uint64_t cycle) {
  uint32_t raw=d.retire_insn,insn=raw;
  unsigned length=4;
  if((raw&3)!=3) {
   if(raw>>16 || illegal[raw&65535]) throw std::runtime_error("illegal compressed retirement");
   insn=expanded[raw&65535]; length=2;
  }
  unsigned opcode=insn&127,rd=(insn>>7)&31,f3=(insn>>12)&7;
  unsigned rs1=(insn>>15)&31,rs2=(insn>>20)&31,f7=insn>>25;
  uint64_t a=x[rs1],b=x[rs2],value=0,next=d.retire_pc+length;
  uint64_t imm=sext(insn>>20,12);
  bool known=false,check_next=true;
  auto mismatch=[&](const std::string &kind,uint64_t expected,uint64_t observed) {
   std::cerr<<"ARCHITECTURAL MISMATCH "<<kind<<" cycle="<<std::dec<<cycle
    <<" pc="<<std::hex<<d.retire_pc<<" raw="<<raw<<" expanded="<<insn
    <<" rs1="<<rs1<<"/"<<a<<" rs2="<<rs2<<"/"<<b
    <<" expected="<<expected<<" observed="<<observed<<std::dec<<std::endl;
   throw std::runtime_error("independent RV64 architectural mismatch");
  };
  switch(opcode) {
   case 0x37: value=sext(insn&0xfffff000U,32); known=true; break;
   case 0x17: value=d.retire_pc+sext(insn&0xfffff000U,32); known=true; break;
   case 0x6f: {
    uint64_t offset=((insn>>31)<<20)|(((insn>>12)&255)<<12)|
                    (((insn>>20)&1)<<11)|(((insn>>21)&1023)<<1);
    value=next; next=d.retire_pc+sext(offset,21); known=true; break;
   }
   case 0x67: value=next; next=(a+imm)&~1ULL; known=true; break;
   case 0x63: {
    uint64_t offset=((insn>>31)<<12)|(((insn>>7)&1)<<11)|
                    (((insn>>25)&63)<<5)|(((insn>>8)&15)<<1);
    bool take=f3==0?a==b:f3==1?a!=b:f3==4?int64_t(a)<int64_t(b):
              f3==5?int64_t(a)>=int64_t(b):f3==6?a<b:a>=b;
    if(take) next=d.retire_pc+sext(offset,13);
    break;
   }
   case 0x13:
    known=true;
    switch(f3) {
     case 0:value=a+imm;break;
     case 1:value=a<<((insn>>20)&63);break;
     case 2:value=int64_t(a)<int64_t(imm);break;
     case 3:value=a<imm;break;
     case 4:value=a^imm;break;
     case 5:value=(insn&(1U<<30))?uint64_t(int64_t(a)>>((insn>>20)&63)):
                  a>>((insn>>20)&63);break;
     case 6:value=a|imm;break;
     case 7:value=a&imm;break;
    } break;
   case 0x1b:
    known=true;
    if(f3==0) value=sext(uint32_t(a+imm),32);
    else if(f3==1) value=sext(uint32_t(a)<<((insn>>20)&31),32);
    else if(f3==5) value=sext((insn&(1U<<30))?
      uint32_t(int32_t(a)>>((insn>>20)&31)):uint32_t(a)>>((insn>>20)&31),32);
    else known=false;
    break;
   case 0x33: case 0x3b: {
    known=true;
    bool word=opcode==0x3b;
    unsigned sh=b&(word?31:63);
    uint64_t ua=word?uint32_t(a):a,ub=word?uint32_t(b):b;
    int64_t sa=word?int32_t(a):int64_t(a),sb=word?int32_t(b):int64_t(b);
    if(f7==1) {
     switch(f3) {
      case 0:value=ua*ub;break;
      case 1:value=uint64_t((__int128(sa)*__int128(sb))>>64);break;
      case 2:value=uint64_t((__int128(sa)*__int128(ub))>>64);break;
      case 3:value=uint64_t((__uint128_t(ua)*__uint128_t(ub))>>64);break;
      case 4:value=!sb?~0ULL:sa==INT64_MIN && sb==-1?uint64_t(sa):uint64_t(sa/sb);break;
      case 5:value=!ub?~0ULL:ua/ub;break;
      case 6:value=!sb?uint64_t(sa):sa==INT64_MIN && sb==-1?0:uint64_t(sa%sb);break;
      case 7:value=!ub?ua:ua%ub;break;
     }
    } else {
     switch(f3) {
      case 0:value=(f7==32)?ua-ub:ua+ub;break;
      case 1:value=ua<<sh;break;
      case 2:value=sa<sb;break;
      case 3:value=ua<ub;break;
      case 4:value=ua^ub;break;
      case 5:value=f7==32?uint64_t(sa>>sh):ua>>sh;break;
      case 6:value=ua|ub;break;
      case 7:value=ua&ub;break;
     }
    }
    if(word) value=sext(uint32_t(value),32);
    break;
   }
   case 0x03: {
    uint64_t address=a+imm;
    if(d.retire_mem_addr!=address) mismatch("load address",address,d.retire_mem_addr);
    if(d.retire_priv==3 && address>=0x80000000ULL && address<0x100000000ULL) {
     unsigned size=1U<<(f3&3);
     for(unsigned i=0;i<size;i++) value|=uint64_t(bytes.read(address+i))<<(8*i);
     if(f3<4) value=sext(value,size*8);
     known=true; loads++;
    }
    break;
   }
   case 0x23: {
    uint64_t offset=sext(((insn>>25)<<5)|((insn>>7)&31),12),address=a+offset;
    if(d.retire_mem_addr!=address) mismatch("store address",address,d.retire_mem_addr);
    if(d.retire_priv==3 && address>=0x80000000ULL && address<0x100000000ULL) {
     unsigned size=1U<<f3;
     for(unsigned i=0;i<size;i++) bytes.write(address+i,b>>(8*i));
     stores++;
    }
    break;
   }
   case 0x2f: {
    if(d.retire_priv==3 && a>=0x80000000ULL && a<0x100000000ULL) {
     unsigned size=f3==2?4:8,operation=insn>>27;
     uint64_t old=0;
     for(unsigned i=0;i<size;i++) old|=uint64_t(bytes.read(a+i))<<(8*i);
     value=size==4?sext(old,32):old;
     if(operation==2) {known=true;break;}
     if(operation==3) {value=d.retire_rd_data; if(value!=0 && value!=1)
       mismatch("SC result",0,value); if(value!=0) break; old=b;}
     else if(operation==0) old+=b;
     else if(operation==1) old=b;
     else if(operation==4) old^=b;
     else if(operation==8) old|=b;
     else if(operation==12) old&=b;
     else if(operation==16) old=(size==4?int32_t(old)<int32_t(b):int64_t(old)<int64_t(b))?old:b;
     else if(operation==20) old=(size==4?int32_t(old)>int32_t(b):int64_t(old)>int64_t(b))?old:b;
     else if(operation==24) old=(size==4?uint32_t(old)<uint32_t(b):old<b)?old:b;
     else if(operation==28) old=(size==4?uint32_t(old)>uint32_t(b):old>b)?old:b;
     else throw std::runtime_error("unsupported retired AMO");
     for(unsigned i=0;i<size;i++) bytes.write(a+i,old>>(8*i));
     known=true;
    } break;
   }
   case 0x73: check_next=f3!=0; break;
   case 0x0f: break;
   case 0x0b: break;
   default: throw std::runtime_error("unsupported retired opcode in integer ISA oracle");
  }
  if(check_next && d.retire_next_pc!=next)
   mismatch("next PC",next,d.retire_next_pc);
  if(known) {
   if(bool(d.retire_rd_we)!=(rd!=0))
    mismatch("GPR write enable",rd!=0,d.retire_rd_we);
   if(rd && (d.retire_rd!=rd || d.retire_rd_data!=value))
    mismatch("GPR result",value,d.retire_rd_data);
   checked++;
  }
  if(d.retire_rd_we) x[d.retire_rd]=known?value:d.retire_rd_data;
  x[0]=0;
 }
};
"""
