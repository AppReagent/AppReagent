#pragma once

#if __has_include(<elf.h>)
#include <elf.h>
#else

#include <cstdint>

using Elf32_Half = uint16_t;
using Elf32_Word = uint32_t;
using Elf32_Sword = int32_t;
using Elf32_Xword = uint64_t;
using Elf32_Addr = uint32_t;
using Elf32_Off = uint32_t;
using Elf32_Section = uint16_t;

using Elf64_Half = uint16_t;
using Elf64_Word = uint32_t;
using Elf64_Sword = int32_t;
using Elf64_Xword = uint64_t;
using Elf64_Sxword = int64_t;
using Elf64_Addr = uint64_t;
using Elf64_Off = uint64_t;
using Elf64_Section = uint16_t;

#define ELFMAG "\177ELF"
#define SELFMAG 4

enum {
    EI_MAG0 = 0, EI_MAG1 = 1, EI_MAG2 = 2, EI_MAG3 = 3,
    EI_CLASS = 4, EI_DATA = 5, EI_VERSION = 6, EI_OSABI = 7,
    EI_NIDENT = 16,
};
enum { ELFCLASS32 = 1, ELFCLASS64 = 2 };
enum { ELFDATA2LSB = 1, ELFDATA2MSB = 2 };
enum { EV_CURRENT = 1 };
enum { ET_REL = 1, ET_EXEC = 2, ET_DYN = 3, ET_CORE = 4 };

enum {
    EM_386 = 3,
    EM_MIPS = 8,
    EM_ARM = 40,
    EM_X86_64 = 62,
    EM_AARCH64 = 183,
};

enum { SHN_UNDEF = 0 };
enum {
    SHT_NULL = 0, SHT_PROGBITS = 1, SHT_SYMTAB = 2, SHT_STRTAB = 3,
    SHT_RELA = 4, SHT_HASH = 5, SHT_DYNAMIC = 6, SHT_NOTE = 7,
    SHT_NOBITS = 8, SHT_REL = 9, SHT_DYNSYM = 11,
};
enum { SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4 };
enum { STB_LOCAL = 0, STB_GLOBAL = 1, STB_WEAK = 2 };
enum { STT_NOTYPE = 0, STT_OBJECT = 1, STT_FUNC = 2, STT_SECTION = 3 };

inline constexpr unsigned char ELF32_ST_TYPE(unsigned char v) { return v & 0xf; }
inline constexpr unsigned char ELF32_ST_BIND(unsigned char v) { return v >> 4; }
inline constexpr unsigned char ELF32_ST_INFO(unsigned char b, unsigned char t) {
    return static_cast<unsigned char>((b << 4) | (t & 0xf));
}
inline constexpr unsigned char ELF64_ST_TYPE(unsigned char v) { return v & 0xf; }
inline constexpr unsigned char ELF64_ST_BIND(unsigned char v) { return v >> 4; }
inline constexpr unsigned char ELF64_ST_INFO(unsigned char b, unsigned char t) {
    return static_cast<unsigned char>((b << 4) | (t & 0xf));
}

struct Elf32_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry;
    Elf32_Off  e_phoff;
    Elf32_Off  e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
};

struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off  e_phoff;
    Elf64_Off  e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
};

struct Elf32_Shdr {
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
};

struct Elf64_Shdr {
    Elf64_Word  sh_name;
    Elf64_Word  sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr  sh_addr;
    Elf64_Off   sh_offset;
    Elf64_Xword sh_size;
    Elf64_Word  sh_link;
    Elf64_Word  sh_info;
    Elf64_Xword sh_addralign;
    Elf64_Xword sh_entsize;
};

struct Elf32_Sym {
    Elf32_Word    st_name;
    Elf32_Addr    st_value;
    Elf32_Word    st_size;
    unsigned char st_info;
    unsigned char st_other;
    Elf32_Half    st_shndx;
};

struct Elf64_Sym {
    Elf64_Word    st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf64_Half    st_shndx;
    Elf64_Addr    st_value;
    Elf64_Xword   st_size;
};

#endif  // __has_include(<elf.h>)
