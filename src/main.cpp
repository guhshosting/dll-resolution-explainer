#include "pe.hpp"
#include <windows.h>
#include <algorithm>
#include <iostream>
#include <sstream>
#include <set>
#include <cctype>
namespace {
std::string quote(const std::string& s) {
 std::ostringstream o; o<<'"'; const char* hex="0123456789abcdef";
 for(unsigned char c:s) {if(c=='"'||c=='\\') o<<'\\'<<static_cast<char>(c); else if(c<32 || c>=127) o<<"\\u00"<<hex[static_cast<unsigned>(c)>>4u]<<hex[static_cast<unsigned>(c)&15u]; else o<<static_cast<char>(c);} o<<'"';return o.str();
}
// UTF-8 paths are passed through as Unicode JSON; raw import bytes use byte-preserving escapes.
std::string pathQuote(const std::wstring& p) {
 const auto s=dre::utf8(p); std::string o="\"";
 for(unsigned char c:s) {if(c=='"'||c=='\\') o+='\\'; if(c<32) throw dre::Error("control character in path");o+=static_cast<char>(c);} return o+'"';
}
std::string lower(std::string s) {std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});return s;}
bool simple(const std::string& s) {return !s.empty() && s!="." && s!=".." && s.find_first_of("\\/:<>\"|?*")==std::string::npos && std::all_of(s.begin(),s.end(),[](unsigned char c){return c>=32 && c<127;}) && s.back()!='.' && s.back()!=' ';}
std::wstring winDirectory() {std::wstring p(32768,L'\0'); const UINT n=GetWindowsDirectoryW(p.data(),static_cast<UINT>(p.size()));if(!n || n>=p.size()) throw dre::Error("cannot obtain Windows directory");p.resize(n);return p;}
uint16_t hostMachine() { SYSTEM_INFO i{};GetNativeSystemInfo(&i);switch(i.wProcessorArchitecture){case PROCESSOR_ARCHITECTURE_AMD64:return 0x8664;case PROCESSOR_ARCHITECTURE_INTEL:return 0x14c;case PROCESSOR_ARCHITECTURE_ARM64:return 0xaa64;default:return 0;}}
std::set<std::string> knownDlls(bool& available) {
 HKEY key=nullptr; std::set<std::string> names;
 available=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&key)==ERROR_SUCCESS;
 if(!available) return names;
 struct RegistryClose { HKEY value; ~RegistryClose() { RegCloseKey(value); } } guard{key};
 for(DWORD i=0;i<4096;++i) {std::vector<wchar_t> name(16384),data(16384);DWORD n=16384,bytes=static_cast<DWORD>(data.size()*sizeof(wchar_t)),type=0;
  const LSTATUS status=RegEnumValueW(key,i,name.data(),&n,nullptr,&type,reinterpret_cast<BYTE*>(data.data()),&bytes);
  if(status==ERROR_NO_MORE_ITEMS) break;
  if(status==ERROR_SUCCESS && type==REG_SZ && bytes>=sizeof(wchar_t) && bytes<=data.size()*sizeof(wchar_t) && bytes%2==0 && data[bytes/2-1]==0) {
   try {const auto s=lower(dre::utf8(data.data()));if(simple(s) && s.size()>4 && s.substr(s.size()-4)==".dll") names.insert(s);} catch(const dre::Error&) { available=false; }
  }
 }
 return names;
}
constexpr const char* limitations="Static analysis cannot infer runtime loader flags, loaded modules, DLL redirection, SetDllDirectory, AddDllDirectory, PATH changes, package graphs, activation contexts or runtime current directory. Matching machine architecture does not prove compatibility. No claim is made about the DLL a future process will load.";
struct Candidate {std::wstring path;std::string status,arch,check,warning;};
struct Result {dre::Import imp;std::string classification,resolution;std::vector<Candidate> candidates;std::vector<std::string> findings;};
std::string strings(const std::vector<std::string>& v) {std::string s="[";for(size_t i=0;i<v.size();++i){if(i)s+=',';s+=quote(v[i]);}return s+"]";}
}
int wmain(int argc,wchar_t** argv) {
 bool json=false;
 try {
  std::wstring input,filter;
  for(int i=1;i<argc;++i) {const std::wstring a=argv[i];
   if(a==L"--json") json=true;
   else if(a==L"--help") {std::cout<<"dll-resolution-explainer 1.0.0\nUsage: dll-resolution-explainer [--json] [--dependency NAME] <PE path>\nStatic direct-import inspection; never executes targets. Local non-reparse files only.\nModel: target directory (assumed application directory), architecture-specific system directory, Windows directory. PATH and runtime CWD excluded.\nExit: 0 inspection completed (findings may exist), 1 inspection failure, 2 usage error.\n";return 0;}
   else if(a==L"--version") {std::cout<<"1.0.0\n";return 0;}
   else if(a==L"--dependency") {if(++i==argc) throw dre::Error("--dependency requires a name");filter=argv[i];}
   else if(a.size()>1 && a[0]==L'-') throw dre::Error("unknown option");
   else if(input.empty()) input=a;else throw dre::Error("only one target is accepted");
  }
  if(input.empty()) {if(json) std::cout<<"{\"schema_version\":\"1.0\",\"error\":\"target path required\"}\n";else std::cerr<<"Target path required; use --help.\n";return 2;}
  const auto target=dre::localPath(input); const auto pe=dre::parse(dre::readLocal(target));
  const auto win=winDirectory(); const auto host=hostMachine();
  std::vector<std::wstring> dirs{target.substr(0,target.find_last_of(L'\\'))};
  std::vector<std::string> warnings;
  // A 32-bit inspector deliberately omits System32 to avoid WOW64 redirection claims.
  const bool nativePaths=sizeof(void*)==8;
  if((nativePaths && pe.machine==host) || (host==0x14c && pe.machine==0x14c)) dirs.push_back(win+L"\\System32");
  else if(pe.machine==0x14c && host==0x8664) dirs.push_back(win+L"\\SysWOW64");
  else warnings.push_back("System directory omitted: reliable cross-architecture path modeling unavailable for this inspector/target combination.");
  dirs.push_back(win);
  bool registry=false;const auto known=knownDlls(registry);
  if(!registry) warnings.push_back("KnownDLL registry configuration could not be read.");
  bool externalManifest=false;
  try {dre::readLocal(target+L".manifest");externalManifest=true;} catch(const dre::Error& e) {
   const std::string why=e.what();
   if(why.find("Win32 2)")==std::string::npos && why.find("Win32 3)")==std::string::npos) warnings.push_back("External manifest presence unknown: "+why);
  }
  if(pe.manifest || externalManifest) warnings.push_back("Manifest present: SxS/runtime activation contexts may change resolution; manifest contents are not interpreted.");
  std::vector<Result> results;bool matched=filter.empty();
  for(const auto& imp:pe.imports) {
   if(!filter.empty() && lower(imp.name)!=lower(dre::utf8(filter))) continue;
   matched=true;Result out;out.imp=imp;const auto name=lower(imp.name);
   const bool api=name.rfind("api-ms-",0)==0 || name.rfind("ext-ms-",0)==0;
   const bool k=known.count(name)!=0;
   out.classification=api?"api_set_contract":k?"known_dll_configuration_entry":"ordinary_import";
   if(api) {out.resolution="api_set_contract";out.findings.push_back("Windows loader contract; ordinary same-name file search does not establish its host DLL.");}
   else if(!simple(imp.name)) {out.resolution="runtime_dependent";out.findings.push_back("Non-basename or non-ASCII import name is not probed under the conservative model.");}
   else {
    size_t found=0,uncertain=0;
    for(const auto& dir:dirs) {
     Candidate c; c.path=dir+L"\\"+dre::widen(imp.name);
     try {const auto candidate=dre::parse(dre::readLocal(c.path));c.status="present";c.arch=dre::architecture(candidate.machine);++found;
      if(c.arch=="unknown" || dre::architecture(pe.machine)=="unknown") c.check="unknown";
      else c.check=candidate.machine==pe.machine?"machine_match":"machine_mismatch";
      if(c.check=="machine_mismatch") out.findings.push_back("Architecture mismatch: "+dre::utf8(c.path));
      if(!(candidate.characteristics&0x2000u)) c.warning="Candidate lacks IMAGE_FILE_DLL characteristic.";
     } catch(const dre::Error& e) {c.status="unavailable_or_invalid";c.check="unknown";c.warning=e.what();
      // Only explicit not-found errors establish absence. Never probe with an unsafe second open.
      if(c.warning.find("Win32 2)")!=std::string::npos || c.warning.find("Win32 3)")!=std::string::npos)c.status="absent";else ++uncertain;
     }
     out.candidates.push_back(std::move(c));
    }
    out.resolution=found>1?"multiple_candidates":found?"candidate_under_model":uncertain?"runtime_dependent":"missing_under_model";
    if(found>1) out.findings.push_back("Multiple local candidates exist; modeled location order is not proof of runtime selection.");
    if(k) {out.resolution="known_system_mechanism";out.findings.push_back("Local KnownDLL configuration name match; ordinary candidates do not override KnownDLL behavior. Registry membership does not establish the active architecture-specific object namespace.");}
   }
   results.push_back(std::move(out));
  }
  if(!matched) warnings.push_back("Requested dependency was not found among direct imports.");
  if(json) {
   std::cout<<"{\"schema_version\":\"1.0\",\"tool_version\":\"1.0.0\",\"target\":{\"path\":"<<pathQuote(target)<<",\"architecture\":"<<quote(dre::architecture(pe.machine))<<",\"machine\":"<<pe.machine<<",\"pe_type\":"<<quote(pe.plus?"PE32+":"PE32")<<",\"image_type\":"<<quote(pe.characteristics&0x2000u?"DLL":"EXE")<<",\"subsystem\":"<<pe.subsystem<<",\"characteristics\":"<<pe.characteristics<<",\"dll_characteristics\":"<<pe.dllCharacteristics<<",\"embedded_manifest\":"<<(pe.manifest?"true":"false")<<",\"external_manifest\":"<<(externalManifest?"true":"false")<<"},";
   for(bool delay:{false,true}) {
    std::cout<<(delay?"\"delay_imports\":[":"\"imports\":[");bool first=true;
    for(const auto& out:results) {if(out.imp.delay!=delay) continue;if(!first)std::cout<<',';first=false;
     std::cout<<"{\"name\":"<<quote(out.imp.name)<<",\"kind\":"<<quote(delay?"delay":"normal")<<",\"classification\":"<<quote(out.classification)<<",\"resolution\":"<<quote(out.resolution)<<",\"findings\":"<<strings(out.findings)<<",\"candidates\":[";
     for(size_t i=0;i<out.candidates.size();++i) {if(i)std::cout<<',';const auto& c=out.candidates[i];std::cout<<"{\"path\":"<<pathQuote(c.path)<<",\"status\":"<<quote(c.status)<<",\"architecture\":"<<quote(c.arch)<<",\"architecture_check\":"<<quote(c.check)<<",\"warning\":"<<quote(c.warning)<<'}';}std::cout<<"]}";
    }std::cout<<"],";
   }
   std::cout<<"\"resolution_model\":{\"id\":\"local-static-v1\",\"application_directory_assumption\":\"target parent; DLL host application directory is unknown\",\"path_included\":false,\"runtime_cwd_included\":false,\"locations\":[";
   for(size_t i=0;i<dirs.size();++i){if(i)std::cout<<',';std::cout<<pathQuote(dirs[i]);}
   std::cout<<"]},\"warnings\":"<<strings(warnings)<<",\"limitations\":["<<quote(limitations)<<"]}\n";
  } else {
   std::cout<<"Target: "<<dre::utf8(target)<<"\n"<<dre::architecture(pe.machine)<<" / "<<(pe.plus?"PE32+":"PE32")<<" / "<<(pe.characteristics&0x2000u?"DLL":"EXE")<<"\nModel: target parent, architecture-specific system directory where reliable, Windows directory. PATH and runtime CWD excluded.\n";
   for(const auto& out:results) {std::cout<<"\n"<<quote(out.imp.name)<<(out.imp.delay?" [delay]":" [normal]")<<"\n  "<<out.classification<<"; "<<out.resolution<<"\n";
    for(const auto& c:out.candidates)std::cout<<"  "<<dre::utf8(c.path)<<": "<<c.status<<" "<<c.arch<<" "<<c.check<<(c.warning.empty()?"":"; "+c.warning)<<"\n";
    for(const auto& f:out.findings)std::cout<<"  Finding: "<<f<<"\n";
   }
   for(const auto& w:warnings)std::cout<<"Warning: "<<w<<"\n";
   std::cout<<"\nLimitations: "<<limitations<<"\nFor DLL targets, the target parent is an assumption; the hosting application's directory is unknown.\n";
  }
  return 0;
 } catch(const std::exception& e) {if(json)std::cout<<"{\"schema_version\":\"1.0\",\"tool_version\":\"1.0.0\",\"error\":"<<quote(e.what())<<"}\n";else std::cerr<<"Error: "<<e.what()<<'\n';return 1;}
}
