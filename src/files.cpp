#include "pe.hpp"
#include <windows.h>
#include <cwctype>
#include <memory>
#include <algorithm>
namespace dre {
namespace {
struct Close { void operator()(void* h) const { if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h); } };
using Handle=std::unique_ptr<void,Close>;
struct NativeFileView {
 void* previous=nullptr; bool changed=false;
 NativeFileView() {
#if defined(_M_IX86)
  BOOL wow=FALSE;
  if(!IsWow64Process(GetCurrentProcess(),&wow)) throw Error("cannot determine filesystem redirection state");
  if(wow) {if(!Wow64DisableWow64FsRedirection(&previous)) throw Error("cannot establish native filesystem view");changed=true;}
#endif
 }
 ~NativeFileView() {if(changed) Wow64RevertWow64FsRedirection(previous);}
 NativeFileView(const NativeFileView&)=delete;
 NativeFileView& operator=(const NativeFileView&)=delete;
};
}
std::string utf8(const std::wstring& s) {
 if(s.empty()) return {};
 const int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);
 if(!n) throw Error("invalid Unicode path"); std::string out(static_cast<size_t>(n),'\0');
 WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr); return out;
}
std::wstring widen(const std::string& s) {
 if(s.empty()) return {};
 const int n=MultiByteToWideChar(CP_ACP,0,s.data(),static_cast<int>(s.size()),nullptr,0);
 if(!n) throw Error("cannot decode import name"); std::wstring out(static_cast<size_t>(n),L'\0');
 MultiByteToWideChar(CP_ACP,0,s.data(),static_cast<int>(s.size()),out.data(),n); return out;
}
std::wstring localPath(const std::wstring& input) {
 if(input.empty() || input.size()>32760 || input.find(L'\0')!=std::wstring::npos) throw Error("invalid path");
 if(input[0]==L'\\' || input[0]==L'/' || input.find(L':',2)!=std::wstring::npos) throw Error("network, device, rooted or stream path rejected");
 std::wstring p(32768,L'\0'); const DWORD n=GetFullPathNameW(input.c_str(),static_cast<DWORD>(p.size()),p.data(),nullptr);
 if(!n || n>=p.size()) throw Error("cannot canonicalize path"); p.resize(n);
 if(p.size()<3 || !iswalpha(p[0]) || p[1]!=L':' || p[2]!=L'\\') throw Error("only local drive paths supported");
 for(size_t start=3;start<p.size();) {
  const size_t end=p.find(L'\\',start); const auto part=p.substr(start,end==std::wstring::npos?p.size()-start:end-start);
  if(std::any_of(part.begin(),part.end(),[](wchar_t c){return c<32 || c==L':';})) throw Error("control characters or streams rejected");
  auto stem=part.substr(0,part.find(L'.'));
  std::transform(stem.begin(),stem.end(),stem.begin(),[](wchar_t c){return static_cast<wchar_t>(towupper(c));});
  if(stem==L"CON" || stem==L"PRN" || stem==L"AUX" || stem==L"NUL" || (stem.size()==4 && (stem.substr(0,3)==L"COM" || stem.substr(0,3)==L"LPT") && stem[3]>=L'0' && stem[3]<=L'9')) throw Error("DOS device path rejected");
  if(end==std::wstring::npos)break;start=end+1;
 }
 const std::wstring root=p.substr(0,3); const UINT type=GetDriveTypeW(root.c_str());
 if(type!=DRIVE_FIXED && type!=DRIVE_REMOVABLE && type!=DRIVE_RAMDISK) throw Error("remote or unknown drive rejected");
 return p;
}
std::vector<uint8_t> readLocal(const std::wstring& input) {
 const auto p=localPath(input);
 const NativeFileView view;
 // Pin every ancestor without delete sharing. OPEN_REPARSE_POINT prevents traversal of the inspected component.
 std::vector<Handle> pins;
 for(size_t i=3;i<=p.size();++i) {
  if(i!=3 && i!=p.size() && p[i]!=L'\\') continue;
  const auto part=p.substr(0,i);
  Handle h(CreateFileW(part.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,nullptr));
  if(h.get()==INVALID_HANDLE_VALUE) throw Error("cannot inspect local path (Win32 "+std::to_string(GetLastError())+")");
  FILE_ATTRIBUTE_TAG_INFO info{};
  if(!GetFileInformationByHandleEx(h.get(),FileAttributeTagInfo,&info,sizeof(info)) || (info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)) throw Error("reparse point or unverifiable path rejected");
  pins.push_back(std::move(h));
 }
 Handle h(CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
 if(h.get()==INVALID_HANDLE_VALUE) throw Error("cannot open file (Win32 "+std::to_string(GetLastError())+")");
 FILE_ATTRIBUTE_TAG_INFO info{};
 if(!GetFileInformationByHandleEx(h.get(),FileAttributeTagInfo,&info,sizeof(info)) || (info.FileAttributes&(static_cast<DWORD>(FILE_ATTRIBUTE_REPARSE_POINT)|static_cast<DWORD>(FILE_ATTRIBUTE_DIRECTORY)))) throw Error("not a regular non-reparse file");
 LARGE_INTEGER size{};
 if(!GetFileSizeEx(h.get(),&size) || size.QuadPart<0 || size.QuadPart>512LL*1024*1024) throw Error("file exceeds 512 MiB inspection limit");
 std::vector<uint8_t> bytes(static_cast<size_t>(size.QuadPart));
 size_t done=0;
 while(done<bytes.size()) {DWORD got=0; const DWORD chunk=static_cast<DWORD>(std::min<size_t>(bytes.size()-done,size_t{1024}*1024));
  if(!ReadFile(h.get(),bytes.data()+done,chunk,&got,nullptr) || !got) throw Error("file read failed or changed"); done+=got;
 }
 return bytes;
}
}
