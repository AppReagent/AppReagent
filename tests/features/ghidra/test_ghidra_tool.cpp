#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

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
    EXPECT_NE(desc.find("strings"), std::string::npos);
    EXPECT_NE(desc.find("xrefs"), std::string::npos);
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
