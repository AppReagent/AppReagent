#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace area::elf {

struct ElfFunction {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    std::string disassembly;  // human-readable disassembly text
    std::string section;
};

struct ElfInfo {
    std::string filename;
    std::string arch;           // "x86", "x86_64", "arm", "aarch64", "mips"
    std::string type;           // "executable", "shared", "relocatable", "core"
    std::vector<ElfFunction> functions;
    std::vector<std::string> imports;
    std::vector<std::string> exports;
    std::string sections_summary;
    std::string raw_info;
};

// Check if raw file data starts with ELF magic bytes
bool isElf(const std::string& data);

// Disassemble an ELF binary from raw file data.
// Returns structured info with per-function disassembly.
ElfInfo disassemble(const std::string& data, const std::string& filename = "");

} // namespace area::elf
