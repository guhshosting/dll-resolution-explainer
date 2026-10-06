#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
namespace dre {
struct Error : std::runtime_error { using runtime_error::runtime_error; };
struct Import { std::string name; bool delay = false; };
struct Pe {
 uint16_t machine=0, subsystem=0, characteristics=0, dllCharacteristics=0;
 bool plus=false, manifest=false;
 std::vector<Import> imports;
};
Pe parse(const std::vector<uint8_t>& bytes);
std::string architecture(uint16_t machine);
std::vector<uint8_t> readLocal(const std::wstring& path);
std::wstring localPath(const std::wstring& path);
std::string utf8(const std::wstring& value);
std::wstring widen(const std::string& value);
}
