#include <gtest/gtest.h>
#include <cstring>
#include <elf.h>

#include "domains/elf/disassembler.h"

// Build a minimal x86-64 ELF binary with one function in memory.
static std::string buildTestElf() {
    // Layout:
    //   0x0000  ELF header (64 bytes)
    //   0x0040  .text section: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret
    //   0x0050  .strtab data: "\0main\0"
    //   0x0060  .shstrtab data: "\0.text\0.symtab\0.strtab\0.shstrtab\0"
    //   0x0090  .symtab data: 2 * Elf64_Sym (null + main)
    //   0x0100  Section header table: 5 * Elf64_Shdr
    //   Total:  0x0240 bytes

    std::string data(0x0240, '\0');
    auto* buf = reinterpret_cast<uint8_t*>(data.data());

    // --- ELF header ---
    Elf64_Ehdr ehdr{};
    memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
    ehdr.e_ident[EI_CLASS]   = ELFCLASS64;
    ehdr.e_ident[EI_DATA]    = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_type    = ET_EXEC;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry   = 0x400040;
    ehdr.e_shoff   = 0x0100;
    ehdr.e_ehsize    = sizeof(Elf64_Ehdr);
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum     = 5;
    ehdr.e_shstrndx  = 4;
    memcpy(buf, &ehdr, sizeof(ehdr));

    // --- .text at 0x40: push rbp; mov rbp,rsp; xor eax,eax; pop rbp; ret ---
    uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3};
    memcpy(buf + 0x40, code, sizeof(code));

    // --- .strtab at 0x50: "\0main\0" (6 bytes) ---
    const char strtab[] = "\0main";
    memcpy(buf + 0x50, strtab, sizeof(strtab));

    // --- .shstrtab at 0x60 ---
    // offsets: 0=\0, 1=.text, 7=.symtab, 15=.strtab, 23=.shstrtab
    const char shstrtab[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
    memcpy(buf + 0x60, shstrtab, sizeof(shstrtab));

    // --- .symtab at 0x90: null entry (24 bytes zeros, already zero) + main ---
    Elf64_Sym mainSym{};
    mainSym.st_name  = 1; // "main" in strtab
    mainSym.st_info  = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    mainSym.st_shndx = 1; // .text section index
    mainSym.st_value = 0x400040;
    mainSym.st_size  = 8;
    memcpy(buf + 0x90 + sizeof(Elf64_Sym), &mainSym, sizeof(mainSym));

    // --- Section header table at 0x100 ---
    // Section 0: null (all zeros, already zero)

    // Section 1: .text
    Elf64_Shdr textShdr{};
    textShdr.sh_name      = 1;
    textShdr.sh_type      = SHT_PROGBITS;
    textShdr.sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
    textShdr.sh_addr      = 0x400040;
    textShdr.sh_offset    = 0x40;
    textShdr.sh_size      = 8;
    textShdr.sh_addralign = 1;
    memcpy(buf + 0x100 + 1 * sizeof(Elf64_Shdr), &textShdr, sizeof(textShdr));

    // Section 2: .symtab
    Elf64_Shdr symtabShdr{};
    symtabShdr.sh_name      = 7;
    symtabShdr.sh_type      = SHT_SYMTAB;
    symtabShdr.sh_offset    = 0x90;
    symtabShdr.sh_size      = 2 * sizeof(Elf64_Sym);
    symtabShdr.sh_link      = 3; // .strtab
    symtabShdr.sh_info      = 1;
    symtabShdr.sh_entsize   = sizeof(Elf64_Sym);
    symtabShdr.sh_addralign = 8;
    memcpy(buf + 0x100 + 2 * sizeof(Elf64_Shdr), &symtabShdr, sizeof(symtabShdr));

    // Section 3: .strtab
    Elf64_Shdr strtabShdr{};
    strtabShdr.sh_name      = 15;
    strtabShdr.sh_type      = SHT_STRTAB;
    strtabShdr.sh_offset    = 0x50;
    strtabShdr.sh_size      = sizeof(strtab);
    strtabShdr.sh_addralign = 1;
    memcpy(buf + 0x100 + 3 * sizeof(Elf64_Shdr), &strtabShdr, sizeof(strtabShdr));

    // Section 4: .shstrtab
    Elf64_Shdr shstrtabShdr{};
    shstrtabShdr.sh_name      = 23;
    shstrtabShdr.sh_type      = SHT_STRTAB;
    shstrtabShdr.sh_offset    = 0x60;
    shstrtabShdr.sh_size      = sizeof(shstrtab);
    shstrtabShdr.sh_addralign = 1;
    memcpy(buf + 0x100 + 4 * sizeof(Elf64_Shdr), &shstrtabShdr, sizeof(shstrtabShdr));

    return data;
}

TEST(ElfDisassembler, DetectsElfMagic) {
    std::string elf = buildTestElf();
    EXPECT_TRUE(area::elf::isElf(elf));
}

TEST(ElfDisassembler, RejectsNonElf) {
    EXPECT_FALSE(area::elf::isElf(""));
    EXPECT_FALSE(area::elf::isElf("abc"));
    EXPECT_FALSE(area::elf::isElf(".class public Lcom/test/Foo;"));
}

TEST(ElfDisassembler, ParsesArchitecture) {
    auto info = area::elf::disassemble(buildTestElf(), "test.bin");
    EXPECT_EQ(info.arch, "x86_64");
}

TEST(ElfDisassembler, ParsesType) {
    auto info = area::elf::disassemble(buildTestElf(), "test.bin");
    EXPECT_EQ(info.type, "executable");
}

TEST(ElfDisassembler, FindsFunctions) {
    auto info = area::elf::disassemble(buildTestElf(), "test.bin");
    ASSERT_EQ(info.functions.size(), 1);
    EXPECT_EQ(info.functions[0].name, "main");
    EXPECT_EQ(info.functions[0].address, 0x400040);
    EXPECT_EQ(info.functions[0].size, 8);
    EXPECT_EQ(info.functions[0].section, ".text");
}

TEST(ElfDisassembler, DisassemblesFunction) {
    auto info = area::elf::disassemble(buildTestElf(), "test.bin");
    ASSERT_EQ(info.functions.size(), 1);

    auto& disasm = info.functions[0].disassembly;
    // Should contain x86-64 mnemonics for our code
    EXPECT_NE(disasm.find("push"), std::string::npos);
    EXPECT_NE(disasm.find("ret"), std::string::npos);
}

TEST(ElfDisassembler, SetsFilename) {
    auto info = area::elf::disassemble(buildTestElf(), "malware.so");
    EXPECT_EQ(info.filename, "malware.so");
}

TEST(ElfDisassembler, HandlesEmptyInput) {
    auto info = area::elf::disassemble("", "empty");
    EXPECT_EQ(info.raw_info, "not an ELF file");
    EXPECT_TRUE(info.functions.empty());
}

TEST(ElfDisassembler, HandlesTruncatedElf) {
    // Valid magic but truncated
    std::string truncated = "\x7f""ELF\x02\x01\x01";
    auto info = area::elf::disassemble(truncated, "trunc");
    EXPECT_TRUE(info.functions.empty());
}

TEST(ElfDisassembler, RawInfoContainsArch) {
    auto info = area::elf::disassemble(buildTestElf(), "test.bin");
    EXPECT_NE(info.raw_info.find("x86_64"), std::string::npos);
    EXPECT_NE(info.raw_info.find("executable"), std::string::npos);
}
