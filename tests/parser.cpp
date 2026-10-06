#include "pe.hpp"
#include <iostream>
#include <random>
namespace {
void put(std::vector<uint8_t>& b,size_t o,uint32_t v) {for(size_t i=0;i<4;++i)b.at(o+i)=static_cast<uint8_t>(v>>(i*8));}
std::vector<uint8_t> fixture(uint16_t machine=0x8664) {
 std::vector<uint8_t> b(1024);put(b,0,0x5a4d);put(b,0x3c,128);put(b,128,0x4550);put(b,132,machine|(1u<<16));put(b,148,240|(0x2022u<<16));
 put(b,152,0x20b);put(b,152+60,512);put(b,152+108,16);put(b,392+8,512);put(b,392+12,0x1000);put(b,392+16,512);put(b,392+20,512);
 put(b,152+112+8,0x1000);put(b,152+112+12,40);put(b,512+12,0x1050);put(b,512+16,0x1100);
 const std::string name="example.dll";std::copy(name.begin(),name.end(),b.begin()+592);return b;
}
void require(bool ok,const char* msg) {if(!ok)throw dre::Error(msg);}
void rejects(const std::vector<uint8_t>& b) {try {dre::parse(b);}catch(const dre::Error&){return;}throw dre::Error("malformed fixture accepted");}
}
int main() {
 try {
  auto good=fixture();auto p=dre::parse(good);require(p.machine==0x8664 && p.imports.size()==1 && p.imports[0].name=="example.dll","valid fixture");
  for(size_t n=0;n<good.size();++n) rejects(std::vector<uint8_t>(good.begin(),good.begin()+n));
  auto b=good;put(b,512+12,0xffffffff);rejects(b);
  b=good;put(b,392+20,0xfffffff0);rejects(b);
  b=good;put(b,392+16,0xffffffff);rejects(b);
  b=good;put(b,152+108,0xffffffff);rejects(b);
  b=good;put(b,152+112+12,20);rejects(b);
  b=good;std::fill(b.begin()+592,b.end(),uint8_t{65});rejects(b);
  b=good;put(b,152+112+13*8,0x1080);put(b,152+112+13*8+4,64);put(b,640,1);put(b,644,0x1050);put(b,652,0x1100);p=dre::parse(b);require(p.imports.size()==2 && p.imports[1].delay,"delay fixture");
  put(b,640,2);rejects(b);
  b=good;put(b,152,0x10b);put(b,148,224|(0x2022u<<16));put(b,132,0x14c|(1u<<16));put(b,152+92,16);put(b,152+96+8,0x1000);put(b,152+96+12,40);
  std::copy(good.begin()+392,good.begin()+432,b.begin()+376);p=dre::parse(b);require(!p.plus && p.machine==0x14c,"PE32 fixture");
  b=good;put(b,132,0x8664|(2u<<16));std::copy(good.begin()+392,good.begin()+432,b.begin()+432);rejects(b);
  b=good;put(b,392+12,0xfffffff0);rejects(b);
  b=good;put(b,512+16,0);rejects(b);
  b=good;put(b,152+112+16,0x1080);put(b,152+112+20,32);put(b,640+12,1u<<16);put(b,656,24);require(dre::parse(b).manifest,"embedded manifest type");
  put(b,640+12,0xffffffff);rejects(b);
  b=good;put(b,132,0xaa64|(1u<<16));require(dre::parse(b).machine==0xaa64,"ARM64 metadata");
  std::mt19937 rng(0x445245);size_t accepted=0;
  for(size_t i=0;i<20000;++i) {b=good;for(size_t j=0;j<1+i%16;++j)b[rng()%b.size()]=static_cast<uint8_t>(rng());try{dre::parse(b);++accepted;}catch(const dre::Error&) {}}
  std::cout<<"1024 truncations, targeted malformed cases, PE32/PE32+, delay imports and 20000 deterministic mutations passed; accepted mutations: "<<accepted<<'\n';return 0;
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
