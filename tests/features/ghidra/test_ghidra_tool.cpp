#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <map>

#include "features/ghidra/GhidraTool.h"
#include "util/file_io.h"
#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "infra/agent/Harness.h"

namespace fs = std::filesystem;

struct GhidraToolMessages {
    std::vector<area::AgentMessage> messages;
    area::MessageCallback cb() {
        return [this](const area::AgentMessage& msg) {
            messages.push_back(msg);
        };
    }
    std::string allContent() const {
        std::string out;
        for (auto& m : messages) out += m.content + "\n";
        return out;
    }
};

class FakeGhidraTool : public area::GhidraTool {
public:
    std::map<std::string, std::string> outputs;
    std::string lastMode;
    std::string lastFilter;

protected:
    std::optional<std::string> checkEnvironment() const override {
        return std::nullopt;
    }

    std::string runGhidra(const std::string&,
                          const std::string& mode,
                          const std::string& filter,
                          const std::string& outputPath,
                          std::string& ghidraLog) override {
        lastMode = mode;
        lastFilter = filter;
        ghidraLog = "Import succeeded\nProcessing succeeded\n";

        auto it = outputs.find(mode);
        if (it == outputs.end()) return "missing fake output for mode " + mode;

        std::ofstream f(outputPath);
        f << it->second;
        return "";
    }
};

static std::string makeTempBinary() {
    std::string path = "/tmp/test_ghidra_" + std::to_string(getpid()) + ".bin";
    std::ofstream f(path);
    f << "dummy";
    return path;
}

// ── prefix matching ────────────────────────────────────────────────

TEST(GhidraTool, IgnoresNonMatchingAction) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    EXPECT_FALSE(tool.tryExecute("SCAN: /path", ctx).has_value());
    EXPECT_FALSE(tool.tryExecute("DISASM: /path", ctx).has_value());
    EXPECT_FALSE(tool.tryExecute("SQL: SELECT 1", ctx).has_value());
    EXPECT_FALSE(tool.tryExecute("STRINGS: /path", ctx).has_value());
}

TEST(GhidraTool, MatchesGhidraPrefix) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    // Should match but fail on empty args
    auto result = tool.tryExecute("GHIDRA:", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
}

TEST(GhidraTool, NameIsCorrect) {
    area::GhidraTool tool;
    EXPECT_EQ(tool.name(), "GHIDRA");
}

TEST(GhidraTool, DescriptionMentionsModes) {
    area::GhidraTool tool;
    auto desc = tool.description();
    EXPECT_NE(desc.find("overview"), std::string::npos);
    EXPECT_NE(desc.find("decompile"), std::string::npos);
    EXPECT_NE(desc.find("disasm"), std::string::npos);
    EXPECT_NE(desc.find("strings"), std::string::npos);
    EXPECT_NE(desc.find("xrefs"), std::string::npos);
    EXPECT_NE(desc.find("function_at"), std::string::npos);
    EXPECT_NE(desc.find("data_at"), std::string::npos);
    EXPECT_NE(desc.find("ELF"), std::string::npos);
}

// ── argument parsing ───────────────────────────────────────────────

TEST(GhidraTool, HandlesEmptyArgs) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GHIDRA:   ", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
    EXPECT_NE(result->observation.find("Usage"), std::string::npos);
}

TEST(GhidraTool, HandlesNonexistentFile) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GHIDRA: /nonexistent/binary.elf", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("not found"), std::string::npos);
}

TEST(GhidraTool, HandlesInvalidMode) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    // Create a temp file so path validation passes
    std::string path = "/tmp/test_ghidra_" + std::to_string(getpid()) + ".bin";
    std::ofstream f(path);
    f << "dummy";
    f.close();

    auto result = tool.tryExecute("GHIDRA: " + path + " | badmode", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("unknown mode"), std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
}

TEST(GhidraTool, FormatsFunctionAtLookup) {
    FakeGhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};
    std::string path = makeTempBinary();

    tool.outputs["function_at"] = R"json({
  "metadata": {"name": "sample.exe"},
  "function_at": {
    "requested_address": "010001656",
    "name": "sub_10001620",
    "address": "010001620",
    "signature": "void sub_10001620(void)",
    "calling_convention": "__stdcall",
    "size": 64,
    "offset_from_entry": 54,
    "caller_count": 3,
    "callee_count": 2,
    "is_thunk": false
  }
})json";

    auto result = tool.tryExecute("GHIDRA: " + path + " | function_at | 0x10001656", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(tool.lastMode, "function_at");
    EXPECT_EQ(tool.lastFilter, "0x10001656");
    EXPECT_NE(result->observation.find("Function Lookup"), std::string::npos);
    EXPECT_NE(result->observation.find("Requested address: 010001656"), std::string::npos);
    EXPECT_NE(result->observation.find("sub_10001620"), std::string::npos);
    EXPECT_NE(result->observation.find("Offset from entry: 54"), std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
}

TEST(GhidraTool, FormatsDataAtLookup) {
    FakeGhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};
    std::string path = makeTempBinary();

    tool.outputs["data_at"] = R"json({
  "metadata": {"name": "sample.exe"},
  "data_at": {
    "requested_address": "01001D988",
    "address": "01001D980",
    "max_address": "01001D99F",
    "data_type": "string",
    "length": 32,
    "value": "Sleep",
    "memory_block": ".rdata",
    "offset_from_start": 8,
    "xref_count": 2,
    "references": [
      {"from": "010001358", "function": "sub_10001320", "type": "DATA"},
      {"from": "010001400", "function": "sub_100013F0", "type": "READ"}
    ]
  }
})json";

    auto result = tool.tryExecute("GHIDRA: " + path + " | data_at | 0x1001D988", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(tool.lastMode, "data_at");
    EXPECT_EQ(tool.lastFilter, "0x1001D988");
    EXPECT_NE(result->observation.find("Data Lookup"), std::string::npos);
    EXPECT_NE(result->observation.find("Type: string (32 bytes)"), std::string::npos);
    EXPECT_NE(result->observation.find("Value: \"Sleep\""), std::string::npos);
    EXPECT_NE(result->observation.find("Referenced by: sub_10001320 @ 010001358 [DATA], sub_100013F0 @ 010001400 [READ]"), std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
}

TEST(GhidraTool, FormatsDataXrefs) {
    FakeGhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};
    std::string path = makeTempBinary();

    tool.outputs["xrefs"] = R"json({
  "metadata": {"name": "sample.exe"},
  "xrefs": {
    "requested_address": "01001D988",
    "kind": "data",
    "address": "01001D980",
    "max_address": "01001D99F",
    "data_type": "unicode",
    "length": 32,
    "value": "mutex_name",
    "memory_block": ".data",
    "offset_from_start": 8,
    "xref_count": 1,
    "references": [
      {"from": "010001656", "function": "sub_10001620", "type": "READ"}
    ],
    "callees": []
  }
})json";

    auto result = tool.tryExecute("GHIDRA: " + path + " | xrefs | 0x1001D988", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(tool.lastMode, "xrefs");
    EXPECT_EQ(tool.lastFilter, "0x1001D988");
    EXPECT_NE(result->observation.find("Requested address: 01001D988"), std::string::npos);
    EXPECT_NE(result->observation.find("Data: 01001D980 .. 01001D99F"), std::string::npos);
    EXPECT_NE(result->observation.find("References (1)"), std::string::npos);
    EXPECT_NE(result->observation.find("sub_10001620 @ 010001656 [READ]"), std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
}

TEST(GhidraTool, FormatsAddressDisassembly) {
    FakeGhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};
    std::string path = makeTempBinary();

    tool.outputs["disasm"] = R"json({
  "metadata": {"name": "sample.exe"},
  "disassembly": {
    "kind": "function",
    "function": "sub_10001620",
    "address": "010001620",
    "signature": "void sub_10001620(void)",
    "requested_address": "010001656",
    "offset_from_entry": 54,
    "instruction_count": 3,
    "function_instruction_count": 87,
    "instructions": [
      {"address": "010001650", "text": "MOV EAX,dword ptr [EBP + 0x8]", "flow_type": "FALL_THROUGH"},
      {"address": "010001656", "text": "CALL Sleep", "flow_type": "CALL", "is_target": true},
      {"address": "01000165b", "text": "TEST EAX,EAX", "flow_type": "FALL_THROUGH"}
    ]
  }
})json";

    auto result = tool.tryExecute("GHIDRA: " + path + " | disasm | 0x10001656", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(tool.lastMode, "disasm");
    EXPECT_EQ(tool.lastFilter, "0x10001656");
    EXPECT_NE(result->observation.find("Ghidra Disassembly"), std::string::npos);
    EXPECT_NE(result->observation.find("Requested address: 010001656"), std::string::npos);
    EXPECT_NE(result->observation.find("Function: sub_10001620 @ 010001620"), std::string::npos);
    EXPECT_NE(result->observation.find("Instructions shown: 3 / 87"), std::string::npos);
    EXPECT_NE(result->observation.find("=> 010001656: CALL Sleep [CALL]"), std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
}

TEST(GhidraTool, FormatsResolvedImportOrdinalsAndCallers) {
    FakeGhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};
    std::string path = makeTempBinary();

    tool.outputs["imports"] = R"json({
  "metadata": {"name": "sample.dll"},
  "imports": [
    {
      "name": "gethostbyname",
      "library": "WS2_32.DLL",
      "address": "EXTERNAL:00000034",
      "original_name": "Ordinal_52",
      "ordinal": 52,
      "caller_count": 3,
      "referenced_by": ["FUN_10001074", "FUN_1000208f", "FUN_10002cce"]
    }
  ],
  "exports": []
})json";

    auto result = tool.tryExecute("GHIDRA: " + path + " | imports", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(tool.lastMode, "imports");
    EXPECT_NE(result->observation.find("gethostbyname [WS2_32.DLL] (ordinal 52) @ EXTERNAL:00000034"), std::string::npos);
    EXPECT_NE(result->observation.find("original: Ordinal_52"), std::string::npos);
    EXPECT_NE(result->observation.find("callers: 3 — referenced by: FUN_10001074 FUN_1000208f FUN_10002cce"), std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
}

TEST(GhidraTool, FormatsOverviewWithEntryPointAndNamedFunctions) {
    FakeGhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};
    std::string path = makeTempBinary();

    tool.outputs["overview"] = R"json({
  "metadata": {
    "name": "sample.dll",
    "language": "x86:LE:32:default",
    "compiler": "windows",
    "image_base": "10000000",
    "executable_format": "Portable Executable (PE)",
    "function_count": 4,
    "memory_size": 4096,
    "is_dll": true,
    "entry_point": "1000D02E",
    "entry_point_rva": "0xD02E",
    "entry_function": "DllMain",
    "entry_signature": "BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)",
    "entry_callees": [
      {"name": "ServiceMain", "address": "1000CF30"},
      {"name": "PSLIST", "address": "10007025"}
    ],
    "likely_dllmain": {"name": "ServiceMain", "address": "1000CF30"},
    "section_names": [".text", ".rdata", ".data"]
  },
  "functions": [
    {
      "name": "FUN_10001000",
      "address": "10001000",
      "signature": "void FUN_10001000(void)",
      "size": 32,
      "caller_count": 0,
      "callee_count": 1
    },
    {
      "name": "PSLIST",
      "address": "10007025",
      "signature": "void PSLIST(char * arg)",
      "size": 64,
      "caller_count": 0,
      "callee_count": 4
    },
    {
      "name": "StartEXS",
      "address": "10007ECB",
      "signature": "void StartEXS(void)",
      "size": 128,
      "caller_count": 0,
      "callee_count": 37
    }
  ],
  "imports": [
    {
      "name": "gethostbyname",
      "library": "WS2_32.DLL",
      "address": "EXTERNAL:00000016",
      "caller_count": 8
    }
  ],
  "exports": []
})json";

    auto result = tool.tryExecute("GHIDRA: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(tool.lastMode, "overview");
    EXPECT_NE(result->observation.find("Entry point: 1000D02E (DLL entry) -> DllMain"), std::string::npos);
    EXPECT_NE(result->observation.find("Entry signature: BOOL DllMain"), std::string::npos);
    EXPECT_NE(result->observation.find("Entry direct callees: ServiceMain @ 1000CF30, PSLIST @ 10007025"), std::string::npos);
    EXPECT_NE(result->observation.find("Likely DllMain: ServiceMain @ 1000CF30 (direct callee of PE entry stub)"), std::string::npos);
    EXPECT_NE(result->observation.find("Sections: .text, .rdata, .data"), std::string::npos);
    EXPECT_NE(result->observation.find("--- Named Functions / Exports (2) ---"), std::string::npos);
    EXPECT_NE(result->observation.find("PSLIST @ 10007025"), std::string::npos);
    EXPECT_NE(result->observation.find("StartEXS @ 10007ECB"), std::string::npos);
    EXPECT_NE(result->observation.find("gethostbyname [WS2_32.DLL] @ EXTERNAL:00000016 [callers:8]"), std::string::npos);

    std::error_code ec;
    fs::remove(path, ec);
}

// ── integration tests (require Ghidra installed) ───────────────────

class GhidraIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Check if Ghidra is available
        std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/home/builder";
        bool found = false;
        if (auto env = std::getenv("GHIDRA_HOME")) {
            found = fs::exists(std::string(env) + "/support/analyzeHeadless");
        }
        if (!found && fs::is_directory(home + "/.local/opt")) {
            for (auto& entry : fs::directory_iterator(home + "/.local/opt")) {
                auto name = entry.path().filename().string();
                if (name.find("ghidra_") == 0) {
                    found = fs::exists(entry.path() / "support" / "analyzeHeadless");
                    break;
                }
            }
        }
        if (!found) GTEST_SKIP() << "Ghidra not installed, skipping integration tests";

        // Check for test ELF
        elfPath_ = "/workspace/tests/use-cases/scan-elf-benign/assets/hello";
        if (!fs::exists(elfPath_)) {
            GTEST_SKIP() << "Test ELF not found";
        }
    }

    std::string elfPath_;
};

TEST_F(GhidraIntegrationTest, OverviewAnalysis) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GHIDRA: " + elfPath_, ctx);
    ASSERT_TRUE(result.has_value());

    auto& obs = result->observation;
    EXPECT_NE(obs.find("Ghidra Analysis"), std::string::npos);
    EXPECT_NE(obs.find("x86"), std::string::npos);
    EXPECT_NE(obs.find("ELF"), std::string::npos);
    EXPECT_NE(obs.find("Functions"), std::string::npos);
    // Should have found main
    EXPECT_NE(obs.find("main"), std::string::npos);
}

TEST_F(GhidraIntegrationTest, DecompileSpecificFunction) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GHIDRA: " + elfPath_ + " | decompile | main", ctx);
    ASSERT_TRUE(result.has_value());

    auto& obs = result->observation;
    EXPECT_NE(obs.find("Decompilation"), std::string::npos);
    EXPECT_NE(obs.find("main"), std::string::npos);
    // Decompiled code should have C-like syntax
    EXPECT_NE(obs.find("("), std::string::npos); // function params
}

TEST_F(GhidraIntegrationTest, StringsExtraction) {
    area::GhidraTool tool;
    GhidraToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GHIDRA: " + elfPath_ + " | strings", ctx);
    ASSERT_TRUE(result.has_value());

    auto& obs = result->observation;
    EXPECT_NE(obs.find("Strings"), std::string::npos);
    // A hello world program should have at least some strings
    EXPECT_NE(obs.find("strings found"), std::string::npos);
}
