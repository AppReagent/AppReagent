#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace area::elf {

struct ElfFunction {
    std::string name;
    uint64_t address = 0;
    uint64_t size = 0;
    std::string disassembly;
    std::string section;
};

struct ElfInfo {
    std::string filename;
    std::string arch;
    std::string type;
    std::vector<ElfFunction> functions;
    std::vector<std::string> imports;
    std::vector<std::string> exports;
    std::string sections_summary;
    std::string raw_info;
};

bool isElf(const std::string& data);

ElfInfo disassemble(const std::string& data, const std::string& filename = "");

}  // namespace area::elf
