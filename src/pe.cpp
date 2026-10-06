#include "pe.hpp"
#include <algorithm>
#include <limits>
namespace dre {
namespace {
struct Reader {
 const std::vector<uint8_t>& b;
 void range(size_t o,size_t n) const { if(o>b.size() || n>b.size()-o) throw Error("truncated or out-of-range PE structure"); }
 uint16_t u16(size_t o) const { range(o,2); return static_cast<uint16_t>(uint32_t(b[o]) | (uint32_t(b[o+1])<<8u)); }
 uint32_t u32(size_t o) const { range(o,4); return uint32_t(b[o])|(uint32_t(b[o+1])<<8u)|(uint32_t(b[o+2])<<16u)|(uint32_t(b[o+3])<<24u); }
 uint64_t u64(size_t o) const { return u32(o)|(uint64_t(u32(o+4))<<32u); }
};
struct Section { uint32_t va, size, raw, length; };
}
std::string architecture(uint16_t m) {
 switch(m) {case 0x14c:return "x86";case 0x8664:return "x64";case 0xaa64:return "ARM64";case 0xa641:return "ARM64EC";case 0x1c4:return "ARM32";default:return "unknown";}
}
Pe parse(const std::vector<uint8_t>& bytes) {
 Reader r{bytes}; Pe p;
 if(r.u16(0)!=0x5a4d) throw Error("invalid DOS signature");
 const size_t nt=r.u32(0x3c); r.range(nt,24);
 if(nt<64 || r.u32(nt)!=0x4550) throw Error("invalid NT signature or offset");
 p.machine=r.u16(nt+4); const size_t count=r.u16(nt+6), optSize=r.u16(nt+20), opt=nt+24;
 p.characteristics=r.u16(nt+22);
 if(!count || count>96) throw Error("invalid section count");
 r.range(opt,optSize); const auto magic=r.u16(opt);
 if(magic!=0x10b && magic!=0x20b) throw Error("unsupported optional header");
 p.plus=magic==0x20b; const size_t fixed=p.plus?112:96;
 if((p.machine==0x14c && p.plus) || ((p.machine==0x8664 || p.machine==0xaa64 || p.machine==0xa641) && !p.plus)) throw Error("machine/optional-header format mismatch");
 if(optSize<fixed) throw Error("short optional header");
 p.subsystem=r.u16(opt+68); p.dllCharacteristics=r.u16(opt+70);
 const uint64_t base=p.plus?r.u64(opt+24):r.u32(opt+28);
 const uint32_t headers=r.u32(opt+60), dirs=r.u32(opt+fixed-4);
 if(dirs>16 || dirs>(optSize-fixed)/8) throw Error("invalid directory count");
 const size_t table=opt+optSize; r.range(table,count*40);
 if(headers<table+count*40 || headers>bytes.size()) throw Error("invalid header extent");
 std::vector<Section> sections;
 for(size_t i=0;i<count;++i) {
  const size_t s=table+i*40; Section t{r.u32(s+12),r.u32(s+8),r.u32(s+20),r.u32(s+16)};
  const uint64_t extent=std::max(t.size,t.length);
  if(uint64_t(t.va)+extent>0x100000000ULL || (extent && t.va<headers)) throw Error("invalid section RVA extent");
  if(t.length) {r.range(t.raw,t.length); if(t.raw<headers) throw Error("section overlaps headers");}
  for(const auto& a:sections) {
   if(extent && std::max(uint64_t(t.va),uint64_t(a.va))<std::min(uint64_t(t.va)+extent,uint64_t(a.va)+std::max(a.size,a.length))) throw Error("overlapping virtual sections");
   if(t.length && a.length && std::max(uint64_t(t.raw),uint64_t(a.raw))<std::min(uint64_t(t.raw)+t.length,uint64_t(a.raw)+a.length)) throw Error("overlapping raw sections");
  }
  sections.push_back(t);
 }
 auto map=[&](uint32_t va,size_t n)->size_t {
  if(va<headers && n<=size_t(headers-va)) {r.range(va,n);return va;}
  for(const auto& s:sections) if(va>=s.va && uint64_t(va)-s.va<s.length) {
   const size_t d=size_t(va-s.va); if(n>s.length-d) throw Error("RVA extends beyond raw section");
   const size_t o=size_t(s.raw)+d; r.range(o,n);return o;
  }
  throw Error("RVA has no file-backed mapping");
 };
 auto name=[&](uint32_t va) {
  std::string v;
  for(uint32_t i=0;i<4096;++i) {
   if(va>UINT32_MAX-i) throw Error("name RVA overflow");
   const auto c=bytes[map(va+i,1)]; if(!c) {if(v.empty()) throw Error("empty import name");return v;}
   v.push_back(static_cast<char>(c));
  }
  throw Error("unterminated import name");
 };
 for(const unsigned index:{1u,13u}) {
  if(dirs<=index) continue;
  const size_t d=opt+fixed+size_t(index)*8; const uint32_t va=r.u32(d), size=r.u32(d+4);
  if(!va && !size) continue;
  const size_t stride=index==1?20:32;
  if(!va || size<stride || size>16*1024*1024) throw Error("invalid import directory extent");
  const size_t start=map(va,size); bool terminated=false;
  for(size_t pos=0;pos+stride<=size;pos+=stride) {
   if(p.imports.size()>=4096) throw Error("too many imports");
   const size_t o=start+pos; bool zero=true;
   for(size_t j=0;j<stride;j+=4) zero=zero && r.u32(o+j)==0;
   if(zero) {terminated=true;break;}
   uint32_t n=r.u32(o+(index==1?12:4));
   uint32_t thunk=r.u32(o+(index==1?16:12));
   if(index==13) {
    const uint32_t attr=r.u32(o); if(attr>1) throw Error("invalid delay attributes");
    if(!attr) {if(p.plus || uint64_t(n)<base || uint64_t(n)-base>UINT32_MAX || uint64_t(thunk)<base || uint64_t(thunk)-base>UINT32_MAX) throw Error("invalid legacy delay VA"); n=static_cast<uint32_t>(uint64_t(n)-base);thunk=static_cast<uint32_t>(uint64_t(thunk)-base);}
   }
   if(!thunk) throw Error("import descriptor has no address table");
   map(thunk,p.plus?8:4);
   p.imports.push_back({name(n),index==13});
  }
  if(!terminated) throw Error("unterminated import descriptors");
 }
 // Inspect only the root resource type table; no resource payload is executed.
 if(dirs>2) {
  const size_t d=opt+fixed+16; const auto va=r.u32(d), size=r.u32(d+4);
  if(va || size) {
   if(!va || size<16) throw Error("invalid resource directory");
   const size_t o=map(va,size); const size_t n=size_t(r.u16(o+12))+r.u16(o+14);
   if(n>(size-16)/8) throw Error("invalid resource entries");
   for(size_t i=0;i<n;++i) if(r.u32(o+16+i*8)==24) p.manifest=true;
  }
 }
 return p;
}
}
