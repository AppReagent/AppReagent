#include <gtest/gtest.h>
#include "domains/graph/graphs/elf_analysis.h"

using namespace area::graph;

// ── File-level signal tests ─────────────────────────────────────────

TEST(ElfFileSignals, DetectsNetworkC2) {
    std::vector<std::string> imports = {"socket", "connect", "send", "recv"};
    auto signals = computeElfFileSignals(imports, {});

    int risk = signals["file_risk_score"];
    EXPECT_GE(risk, 30) << "socket+connect should trigger Network C2 pattern";

    bool foundC2 = false;
    for (auto& p : signals["matched_patterns"]) {
        if (p["category"] == "c2") foundC2 = true;
    }
    EXPECT_TRUE(foundC2);
}

TEST(ElfFileSignals, DetectsRemoteShell) {
    std::vector<std::string> imports = {"socket", "connect", "execve", "dup2"};
    auto signals = computeElfFileSignals(imports, {});

    int risk = signals["file_risk_score"];
    EXPECT_GE(risk, 50) << "socket+execve should trigger Remote shell pattern";

    bool foundC2 = false;
    for (auto& p : signals["matched_patterns"]) {
        if (p["name"] == "Remote shell") foundC2 = true;
    }
    EXPECT_TRUE(foundC2);
}

TEST(ElfFileSignals, DetectsServerBackdoor) {
    std::vector<std::string> imports = {"socket", "bind", "listen", "accept", "fork"};
    auto signals = computeElfFileSignals(imports, {});

    bool found = false;
    for (auto& p : signals["matched_patterns"]) {
        if (p["name"] == "Server backdoor") found = true;
    }
    EXPECT_TRUE(found);
}

TEST(ElfFileSignals, DetectsPrivilegeEscalation) {
    std::vector<std::string> imports = {"setuid", "execve"};
    auto signals = computeElfFileSignals(imports, {});

    bool found = false;
    for (auto& p : signals["matched_patterns"]) {
        if (p["category"] == "rootkit") found = true;
    }
    EXPECT_TRUE(found);
}

TEST(ElfFileSignals, DetectsAntiDebugging) {
    std::vector<std::string> imports = {"ptrace", "fork"};
    auto signals = computeElfFileSignals(imports, {});

    bool found = false;
    for (auto& p : signals["matched_patterns"]) {
        if (p["name"] == "Anti-debugging") found = true;
    }
    EXPECT_TRUE(found);
}

TEST(ElfFileSignals, DetectsFilelessPayload) {
    std::vector<std::string> imports = {"memfd_create", "dlopen", "dlsym"};
    auto signals = computeElfFileSignals(imports, {});

    bool found = false;
    for (auto& p : signals["matched_patterns"]) {
        if (p["name"] == "Fileless payload") found = true;
    }
    EXPECT_TRUE(found);
}

TEST(ElfFileSignals, BenignImportsLowRisk) {
    std::vector<std::string> imports = {"printf", "malloc", "free", "strlen", "strcmp"};
    auto signals = computeElfFileSignals(imports, {});

    int risk = signals["file_risk_score"];
    EXPECT_EQ(risk, 0) << "Standard libc imports should not trigger any patterns";
    EXPECT_TRUE(signals["matched_patterns"].empty());
}

TEST(ElfFileSignals, EmptyImportsNoRisk) {
    auto signals = computeElfFileSignals({}, {});
    EXPECT_EQ(signals["file_risk_score"], 0);
}

TEST(ElfFileSignals, VersionedImportsMatch) {
    // Stripped binaries only have versioned names like "socket@GLIBC_2.2.5"
    std::vector<std::string> imports = {"socket@GLIBC_2.2.5", "connect@GLIBC_2.2.5"};
    auto signals = computeElfFileSignals(imports, {});

    int risk = signals["file_risk_score"];
    EXPECT_GE(risk, 30) << "versioned imports should still trigger patterns";

    bool foundC2 = false;
    for (auto& p : signals["matched_patterns"]) {
        if (p["category"] == "c2") foundC2 = true;
    }
    EXPECT_TRUE(foundC2) << "Network C2 pattern should match versioned imports";
}

TEST(ElfFileSignals, CapsRiskAt100) {
    // Lots of suspicious imports should cap at 100
    std::vector<std::string> imports = {
        "socket", "connect", "bind", "listen", "accept",
        "execve", "system", "popen", "fork", "ptrace",
        "dlopen", "dlsym", "mmap", "mprotect", "memfd_create",
        "setuid", "setgid", "seteuid", "setreuid"
    };
    auto signals = computeElfFileSignals(imports, {});
    EXPECT_LE(signals["file_risk_score"].get<int>(), 100);
}

// ── Method-level analysis tests ─────────────────────────────────────

TEST(ElfMethodAnalysis, DetectsCallToSocket) {
    std::string disasm =
        "  0x1000:  push\trbp\n"
        "  0x1001:  mov\trbp, rsp\n"
        "  0x1004:  call\tsocket\n"
        "  0x1009:  call\tconnect\n"
        "  0x100e:  pop\trbp\n"
        "  0x100f:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    int risk = analysis["static_risk_score"];
    EXPECT_GE(risk, 15) << "call to socket should trigger c2 indicator";

    bool foundSocket = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri["api"] == "socket") foundSocket = true;
    }
    EXPECT_TRUE(foundSocket);
}

TEST(ElfMethodAnalysis, DetectsCallToExecve) {
    std::string disasm =
        "  0x1000:  call\texecve\n"
        "  0x1005:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    bool found = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri["api"] == "execve") found = true;
    }
    EXPECT_TRUE(found);
    EXPECT_GE(analysis["static_risk_score"].get<int>(), 20);
}

TEST(ElfMethodAnalysis, DetectsSyscallInstruction) {
    std::string disasm =
        "  0x1000:  mov\teax, 59\n"
        "  0x1005:  syscall\n"
        "  0x1007:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    bool found = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri.contains("pattern") && ri["pattern"] == "syscall") found = true;
    }
    EXPECT_TRUE(found);
}

TEST(ElfMethodAnalysis, DetectsXorLoop) {
    std::string disasm =
        "  0x1000:  xor\tcl, byte ptr [rdi]\n"
        "  0x1002:  inc\trdi\n"
        "  0x1005:  dec\trcx\n"
        "  0x1008:  jnz\t0x1000\n"
        "  0x100a:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    bool found = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri.contains("pattern") && ri["pattern"] == "xor_loop") found = true;
    }
    EXPECT_TRUE(found);
}

TEST(ElfMethodAnalysis, IgnoresSelfXor) {
    // xor eax, eax is just zeroing, not obfuscation
    std::string disasm =
        "  0x1000:  xor\teax, eax\n"
        "  0x1002:  jnz\t0x1000\n"
        "  0x1004:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    bool foundXorLoop = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri.contains("pattern") && ri["pattern"] == "xor_loop") foundXorLoop = true;
    }
    EXPECT_FALSE(foundXorLoop) << "self-xor (register zeroing) should not trigger xor_loop";
}

TEST(ElfMethodAnalysis, DetectsRdtscAntiDebug) {
    std::string disasm =
        "  0x1000:  rdtsc\n"
        "  0x1002:  mov\tesi, eax\n"
        "  0x1004:  rdtsc\n"
        "  0x1006:  sub\teax, esi\n"
        "  0x1008:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    bool found = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri.contains("pattern") && ri["pattern"] == "rdtsc") found = true;
    }
    EXPECT_TRUE(found);
}

TEST(ElfMethodAnalysis, BenignFunctionNoRisk) {
    std::string disasm =
        "  0x1000:  push\trbp\n"
        "  0x1001:  mov\trbp, rsp\n"
        "  0x1004:  mov\teax, edi\n"
        "  0x1006:  add\teax, esi\n"
        "  0x1008:  pop\trbp\n"
        "  0x1009:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    EXPECT_EQ(analysis["static_risk_score"], 0);
    EXPECT_TRUE(analysis["risk_indicators"].empty());
}

TEST(ElfMethodAnalysis, ExtractsCalledFunctions) {
    std::string disasm =
        "  0x1000:  call\tmalloc\n"
        "  0x1005:  call\tfree\n"
        "  0x100a:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    ASSERT_GE(analysis["api_calls"].size(), 2u);
    bool hasMalloc = false, hasFree = false;
    for (auto& call : analysis["api_calls"]) {
        if (call == "malloc") hasMalloc = true;
        if (call == "free") hasFree = true;
    }
    EXPECT_TRUE(hasMalloc);
    EXPECT_TRUE(hasFree);
}

TEST(ElfMethodAnalysis, DetectsArmBlInstruction) {
    std::string disasm =
        "  0x1000:  bl\tconnect\n"
        "  0x1004:  bl\tsend\n"
        "  0x1008:  bx\tlr\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    bool foundConnect = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri["api"] == "connect") foundConnect = true;
    }
    EXPECT_TRUE(foundConnect);
}

TEST(ElfMethodAnalysis, DetectsInt80Syscall) {
    std::string disasm =
        "  0x1000:  mov\teax, 11\n"
        "  0x1005:  int\t0x80\n"
        "  0x1007:  ret\n";
    auto analysis = computeElfMethodStaticAnalysis(disasm, "");

    bool found = false;
    for (auto& ri : analysis["risk_indicators"]) {
        if (ri.contains("pattern") && ri["pattern"] == "int\t0x80") found = true;
    }
    EXPECT_TRUE(found);
}

// ── Integration: ELF scan graph pipeline test ───────────────────────

#include "domains/graph/engine/graph_runner.h"
#include "domains/graph/graphs/scan_task_graph.h"
#include "infra/llm/LLMBackend.h"
#include "domains/elf/disassembler.h"
#include <cstring>
#include <elf.h>
#include <fstream>

// Reuse the minimal test ELF builder
static std::string buildTestElfBinary() {
    std::string data(0x0240, '\0');
    auto* buf = reinterpret_cast<uint8_t*>(data.data());

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

    uint8_t code[] = {0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3};
    memcpy(buf + 0x40, code, sizeof(code));

    const char strtab[] = "\0main";
    memcpy(buf + 0x50, strtab, sizeof(strtab));

    const char shstrtab[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
    memcpy(buf + 0x60, shstrtab, sizeof(shstrtab));

    Elf64_Sym mainSym{};
    mainSym.st_name  = 1;
    mainSym.st_info  = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
    mainSym.st_shndx = 1;
    mainSym.st_value = 0x400040;
    mainSym.st_size  = 8;
    memcpy(buf + 0x90 + sizeof(Elf64_Sym), &mainSym, sizeof(mainSym));

    Elf64_Shdr textShdr{};
    textShdr.sh_name      = 1;
    textShdr.sh_type      = SHT_PROGBITS;
    textShdr.sh_flags     = SHF_ALLOC | SHF_EXECINSTR;
    textShdr.sh_addr      = 0x400040;
    textShdr.sh_offset    = 0x40;
    textShdr.sh_size      = 8;
    textShdr.sh_addralign = 1;
    memcpy(buf + 0x100 + 1 * sizeof(Elf64_Shdr), &textShdr, sizeof(textShdr));

    Elf64_Shdr symtabShdr{};
    symtabShdr.sh_name      = 7;
    symtabShdr.sh_type      = SHT_SYMTAB;
    symtabShdr.sh_offset    = 0x90;
    symtabShdr.sh_size      = 2 * sizeof(Elf64_Sym);
    symtabShdr.sh_link      = 3;
    symtabShdr.sh_info      = 1;
    symtabShdr.sh_entsize   = sizeof(Elf64_Sym);
    symtabShdr.sh_addralign = 8;
    memcpy(buf + 0x100 + 2 * sizeof(Elf64_Shdr), &symtabShdr, sizeof(symtabShdr));

    Elf64_Shdr strtabShdr{};
    strtabShdr.sh_name      = 15;
    strtabShdr.sh_type      = SHT_STRTAB;
    strtabShdr.sh_offset    = 0x50;
    strtabShdr.sh_size      = sizeof(strtab);
    strtabShdr.sh_addralign = 1;
    memcpy(buf + 0x100 + 3 * sizeof(Elf64_Shdr), &strtabShdr, sizeof(strtabShdr));

    Elf64_Shdr shstrtabShdr{};
    shstrtabShdr.sh_name      = 23;
    shstrtabShdr.sh_type      = SHT_STRTAB;
    shstrtabShdr.sh_offset    = 0x60;
    shstrtabShdr.sh_size      = sizeof(shstrtab);
    shstrtabShdr.sh_addralign = 1;
    memcpy(buf + 0x100 + 4 * sizeof(Elf64_Shdr), &shstrtabShdr, sizeof(shstrtabShdr));

    return data;
}

TEST(ElfScanGraph, ElfRoutedThroughPipeline) {
    // Write a test ELF to a temp file
    std::string elfPath = "/tmp/area_test_elf.bin";
    {
        std::ofstream f(elfPath, std::ios::binary);
        f << buildTestElfBinary();
    }

    area::AiEndpoint ep{"test", "mock", "", "auto"};
    area::MockBackend tier0(ep), tier1(ep), tier2(ep);

    // tier1: triage worker (1x), then deep_analysis supervisor (1x)
    tier1.setResponses({
        R"({"relevant": true, "confidence": 0.8, "api_calls": [], "findings": ["test function"], "threat_category": "other", "reasoning": "test"})",
        "PASS"
    });
    // tier0: triage supervisor (1x), synthesis supervisor (1x)
    tier0.setResponse("PASS");
    // tier2: deep_analysis worker (1x), synthesis worker (1x)
    tier2.setResponses({
        R"json({"detailed_findings":["test"],"evidence":[],"data_flows":[],"threat_type":"unknown","mitre_techniques":[],"adversary_intent":"test","relevance_score":20,"reasoning":"test"})json",
        R"json({"answer":"benign test binary","relevant_methods":[],"evidence_summary":"test","overall_relevance":"not_relevant","threat_type":"none","mitre_techniques":[],"relevance_score":5,"recommendation":"none"})json"
    });

    area::graph::TierBackends backends;
    backends.backends[0] = &tier0;
    backends.backends[1] = &tier1;
    backends.backends[2] = &tier2;

    auto graph = area::graph::buildScanTaskGraph(backends, PROMPTS_DIR);

    area::graph::TaskContext initial;
    initial.set("file_path", elfPath);
    initial.set("scan_goal", "Analyze this binary for threats");

    area::graph::GraphRunner runner;
    runner.setMaxParallel(1);

    std::vector<std::string> nodeTrace;
    runner.onNodeStart([&](const std::string& name, const area::graph::TaskContext&) {
        nodeTrace.push_back(name);
    });

    // Track that file_format is set to "elf" on items
    bool elfFormatSet = false;
    runner.onNodeEnd([&](const std::string& name, const area::graph::TaskContext& ctx) {
        if (name == "static_enrich" && ctx.has("file_format")) {
            elfFormatSet = (ctx.get("file_format").get<std::string>() == "elf");
        }
    });

    auto result = runner.run(graph, std::move(initial));

    // Verify the graph took the ELF path
    EXPECT_EQ(nodeTrace[0], "read_file");
    EXPECT_EQ(nodeTrace[1], "detect_format");
    // ELF skips file_signals, goes straight to split_methods
    EXPECT_EQ(nodeTrace[2], "split_methods");

    // file_format should be propagated to items
    EXPECT_TRUE(elfFormatSet);

    // Should produce a result (not discarded)
    EXPECT_TRUE(result.has("risk_profile"));

    std::remove(elfPath.c_str());
}
