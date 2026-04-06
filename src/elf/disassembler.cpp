#include "elf/disassembler.h"

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <elf.h>
#include <sstream>

#include <capstone/capstone.h>

namespace area::elf {

bool isElf(const std::string& data) {
    return data.size() >= 4 &&
           data[0] == '\x7f' && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
}

static std::string archString(uint16_t machine) {
    switch (machine) {
        case EM_386:    return "x86";
        case EM_X86_64: return "x86_64";
        case EM_ARM:    return "arm";
        case EM_AARCH64:return "aarch64";
        case EM_MIPS:   return "mips";
        default:        return "unknown";
    }
}

static std::string typeString(uint16_t type) {
    switch (type) {
        case ET_REL:  return "relocatable";
        case ET_EXEC: return "executable";
        case ET_DYN:  return "shared";
        case ET_CORE: return "core";
        default:      return "unknown";
    }
}

static bool mapCapstoneArch(uint16_t machine, cs_arch& arch, cs_mode& mode) {
    switch (machine) {
        case EM_386:
            arch = CS_ARCH_X86; mode = CS_MODE_32; return true;
        case EM_X86_64:
            arch = CS_ARCH_X86; mode = CS_MODE_64; return true;
        case EM_ARM:
            arch = CS_ARCH_ARM; mode = CS_MODE_ARM; return true;
        case EM_AARCH64:
            arch = CS_ARCH_ARM64; mode = CS_MODE_ARM; return true;
        case EM_MIPS:
            arch = CS_ARCH_MIPS; mode = CS_MODE_MIPS32; return true;
        default:
            return false;
    }
}

static std::string disassembleBytes(const uint8_t* code, size_t codeSize,
                                    uint64_t baseAddr, cs_arch arch, cs_mode mode) {
    csh handle;
    if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
        return "; disassembly failed: could not initialize capstone\n";
    }

    cs_insn* insn;
    size_t count = cs_disasm(handle, code, codeSize, baseAddr, 0, &insn);

    std::ostringstream ss;
    for (size_t i = 0; i < count; i++) {
        char addr[32];
        snprintf(addr, sizeof(addr), "  0x%" PRIx64, insn[i].address);
        ss << addr << ":  " << insn[i].mnemonic << "\t" << insn[i].op_str << "\n";
    }

    if (count > 0) cs_free(insn, count);
    cs_close(&handle);

    return ss.str();
}

template<typename Ehdr, typename Shdr, typename Sym>
static ElfInfo disassembleImpl(const uint8_t* data, size_t dataSize,
                               const std::string& filename) {
    ElfInfo info;
    info.filename = filename;

    if (dataSize < sizeof(Ehdr)) {
        info.raw_info = "ELF file too small";
        return info;
    }

    const auto* ehdr = reinterpret_cast<const Ehdr*>(data);
    info.arch = archString(ehdr->e_machine);
    info.type = typeString(ehdr->e_type);

    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0 ||
        ehdr->e_shoff + ehdr->e_shnum * sizeof(Shdr) > dataSize) {
        info.raw_info = info.arch + " " + info.type + " (no section headers)";
        return info;
    }

    const auto* sections = reinterpret_cast<const Shdr*>(data + ehdr->e_shoff);
    uint16_t shnum = ehdr->e_shnum;

    // Section name string table
    const char* shstrtab = nullptr;
    size_t shstrtabSize = 0;
    if (ehdr->e_shstrndx < shnum) {
        const auto& strsect = sections[ehdr->e_shstrndx];
        if (strsect.sh_offset + strsect.sh_size <= dataSize) {
            shstrtab = reinterpret_cast<const char*>(data + strsect.sh_offset);
            shstrtabSize = strsect.sh_size;
        }
    }

    // Find symbol tables and executable sections
    const Shdr* symtab = nullptr;
    const Shdr* symstrtab = nullptr;
    const Shdr* dynsym = nullptr;
    const Shdr* dynstr = nullptr;
    std::vector<const Shdr*> execSections;

    for (uint16_t i = 0; i < shnum; i++) {
        const auto& s = sections[i];

        if (s.sh_type == SHT_SYMTAB) {
            symtab = &s;
            if (s.sh_link < shnum) symstrtab = &sections[s.sh_link];
        }
        if (s.sh_type == SHT_DYNSYM) {
            dynsym = &s;
            if (s.sh_link < shnum) dynstr = &sections[s.sh_link];
        }
        if (s.sh_flags & SHF_EXECINSTR) {
            execSections.push_back(&s);
        }

        if (shstrtab && s.sh_name > 0 && s.sh_name < shstrtabSize) {
            info.sections_summary += std::string(shstrtab + s.sh_name,
                strnlen(shstrtab + s.sh_name, shstrtabSize - s.sh_name)) + " ";
        }
    }

    info.raw_info = "ELF " + info.arch + " " + info.type +
                    ", " + std::to_string(shnum) + " sections";

    // Capstone setup
    cs_arch csArch;
    cs_mode csMode;
    if (!mapCapstoneArch(ehdr->e_machine, csArch, csMode)) {
        info.raw_info += " (unsupported architecture for disassembly)";
        return info;
    }

    // Extract functions from a symbol table
    auto extractFunctions = [&](const Shdr* symSect, const Shdr* strSect,
                                bool isDynamic) {
        if (!symSect || !strSect) return;
        if (symSect->sh_offset + symSect->sh_size > dataSize) return;
        if (strSect->sh_offset + strSect->sh_size > dataSize) return;

        const char* strtab = reinterpret_cast<const char*>(data + strSect->sh_offset);
        size_t numSyms = symSect->sh_size / sizeof(Sym);

        for (size_t i = 0; i < numSyms; i++) {
            const auto* sym = reinterpret_cast<const Sym*>(
                data + symSect->sh_offset + i * sizeof(Sym));

            int stype = ELF64_ST_TYPE(sym->st_info); // same macro for 32/64

            if (stype != STT_FUNC) continue;

            std::string symName;
            if (sym->st_name > 0 && sym->st_name < strSect->sh_size) {
                symName = strtab + sym->st_name;
            }
            if (symName.empty()) continue;

            if (sym->st_shndx == SHN_UNDEF) {
                info.imports.push_back(symName);
                continue;
            }

            if (sym->st_size == 0) continue;

            // Find section and disassemble
            std::string sectName = ".text";
            if (sym->st_shndx < shnum && shstrtab &&
                sections[sym->st_shndx].sh_name < shstrtabSize) {
                auto off = sections[sym->st_shndx].sh_name;
                sectName = std::string(shstrtab + off,
                    strnlen(shstrtab + off, shstrtabSize - off));
            }

            std::string disasm;
            if (sym->st_shndx < shnum) {
                const auto& funcSect = sections[sym->st_shndx];
                if (funcSect.sh_flags & SHF_EXECINSTR &&
                    sym->st_value >= funcSect.sh_addr) {
                    uint64_t fileOffset = funcSect.sh_offset +
                                          (sym->st_value - funcSect.sh_addr);
                    if (fileOffset + sym->st_size <= dataSize &&
                        fileOffset + sym->st_size >= fileOffset) {
                        disasm = disassembleBytes(
                            data + fileOffset, sym->st_size,
                            sym->st_value, csArch, csMode);
                    }
                }
            }

            ElfFunction func;
            func.name = symName;
            func.address = sym->st_value;
            func.size = sym->st_size;
            func.disassembly = disasm;
            func.section = sectName;
            info.functions.push_back(std::move(func));

            if (isDynamic) {
                info.exports.push_back(symName);
            }
        }
    };

    extractFunctions(symtab, symstrtab, false);
    extractFunctions(dynsym, dynstr, true);

    // Deduplicate by address
    std::sort(info.functions.begin(), info.functions.end(),
              [](const ElfFunction& a, const ElfFunction& b) {
                  return a.address < b.address;
              });
    info.functions.erase(
        std::unique(info.functions.begin(), info.functions.end(),
                    [](const ElfFunction& a, const ElfFunction& b) {
                        return a.address == b.address;
                    }),
        info.functions.end());

    // Stripped binary fallback: disassemble entire executable sections
    if (info.functions.empty()) {
        for (const auto* sect : execSections) {
            if (sect->sh_size == 0) continue;
            if (sect->sh_offset + sect->sh_size > dataSize) continue;

            std::string sectName = "section";
            if (shstrtab && sect->sh_name > 0 && sect->sh_name < shstrtabSize) {
                sectName = std::string(shstrtab + sect->sh_name,
                    strnlen(shstrtab + sect->sh_name, shstrtabSize - sect->sh_name));
            }

            size_t maxSize = std::min<size_t>(sect->sh_size, 65536);
            std::string disasm = disassembleBytes(
                data + sect->sh_offset, maxSize,
                sect->sh_addr, csArch, csMode);

            ElfFunction func;
            func.name = sectName;
            func.address = sect->sh_addr;
            func.size = sect->sh_size;
            func.disassembly = disasm;
            func.section = sectName;
            info.functions.push_back(std::move(func));
        }
    }

    // Deduplicate imports
    std::sort(info.imports.begin(), info.imports.end());
    info.imports.erase(std::unique(info.imports.begin(), info.imports.end()),
                       info.imports.end());

    return info;
}

ElfInfo disassemble(const std::string& data, const std::string& filename) {
    if (!isElf(data)) {
        return ElfInfo{.filename = filename, .raw_info = "not an ELF file"};
    }

    const auto* bytes = reinterpret_cast<const uint8_t*>(data.data());
    size_t size = data.size();

    if (size < EI_NIDENT) {
        return ElfInfo{.filename = filename, .raw_info = "ELF too small"};
    }

    uint8_t elfClass = bytes[EI_CLASS];
    if (elfClass == ELFCLASS64) {
        return disassembleImpl<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym>(bytes, size, filename);
    } else if (elfClass == ELFCLASS32) {
        return disassembleImpl<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym>(bytes, size, filename);
    }

    return ElfInfo{.filename = filename, .raw_info = "unknown ELF class"};
}

} // namespace area::elf
