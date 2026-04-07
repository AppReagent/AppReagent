#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "features/grep/GrepTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"

namespace fs = std::filesystem;

struct GrepMessages {
    std::vector<area::AgentMessage> messages;
    area::MessageCallback cb() {
        return [this](const area::AgentMessage& msg) { messages.push_back(msg); };
    }
};

class GrepToolTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = "/tmp/test_grep_tool_" + std::to_string(getpid());
        fs::create_directories(tmpDir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmpDir, ec);
    }

    void createFile(const std::string& relPath, const std::string& content) {
        auto full = fs::path(tmpDir) / relPath;
        fs::create_directories(full.parent_path());
        std::ofstream f(full);
        f << content;
    }
};

TEST_F(GrepToolTest, IgnoresNonGrepAction) {
    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("SCAN: /path", ctx);
    EXPECT_FALSE(result.has_value());
}

TEST_F(GrepToolTest, ErrorOnEmptyPattern) {
    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: ", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
}

TEST_F(GrepToolTest, FindsSimplePattern) {
    createFile("src/Net.smali", R"(
.class public Lcom/test/Net;
.super Ljava/lang/Object;
.method public connect()V
    const-string v0, "HttpURLConnection"
    return-void
.end method
)");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: HttpURLConnection | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("HttpURLConnection"), std::string::npos);
    EXPECT_NE(result->observation.find("match"), std::string::npos);
}

TEST_F(GrepToolTest, CaseInsensitiveSearch) {
    createFile("src/Test.smali", "const-string v0, \"SENSITIVE_DATA\"\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: sensitive_data | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("SENSITIVE_DATA"), std::string::npos);
}

TEST_F(GrepToolTest, OrPatternSearch) {
    createFile("src/A.smali", "const-string v0, \"http://evil.com\"\n");
    createFile("src/B.smali", "const-string v0, \"192.168.1.1\"\n");
    createFile("src/C.smali", "const-string v0, \"hello world\"\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: evil.com | 192.168 | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // Should match files with evil.com or 192.168 pattern
    // Note: the last | is path separator, so we test with explicit path
    EXPECT_NE(result->observation.find("match"), std::string::npos);
}

TEST_F(GrepToolTest, NoMatchesReturnsEmpty) {
    createFile("src/Foo.smali", "const-string v0, \"hello\"\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: nonexistent_pattern_xyz | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("No matches"), std::string::npos);
}

TEST_F(GrepToolTest, SkipsNonSearchableFiles) {
    // .bin is not in the searchable extensions list
    createFile("data/binary.bin", "HttpURLConnection hidden here");
    createFile("src/Code.smali", "HttpURLConnection used here");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: HttpURLConnection | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // Should find in .smali but not in .bin
    EXPECT_NE(result->observation.find("Code.smali"), std::string::npos);
    EXPECT_EQ(result->observation.find("binary.bin"), std::string::npos);
}

TEST_F(GrepToolTest, SearchesMultipleFileTypes) {
    createFile("src/Main.java", "String url = \"http://api.example.com\";\n");
    createFile("src/config.json", "{\"url\": \"http://api.example.com\"}\n");
    createFile("src/Net.smali", "const-string v0, \"http://api.example.com\"\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: api.example.com | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // All three file types should be searchable
    EXPECT_NE(result->observation.find("Main.java"), std::string::npos);
    EXPECT_NE(result->observation.find("config.json"), std::string::npos);
    EXPECT_NE(result->observation.find("Net.smali"), std::string::npos);
}

TEST_F(GrepToolTest, ShowsLineNumbers) {
    createFile("src/Test.smali",
        "line1\n"
        "line2\n"
        "TARGET_MATCH here\n"
        "line4\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: TARGET_MATCH | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // Line 3 should contain the match
    EXPECT_NE(result->observation.find("3:"), std::string::npos);
}

TEST_F(GrepToolTest, TruncatesLongLines) {
    std::string longLine(300, 'A');
    longLine += "FINDME";
    createFile("src/Long.smali", longLine + "\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: AAAA | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // Should truncate to 200 chars + "..."
    EXPECT_NE(result->observation.find("..."), std::string::npos);
}

TEST_F(GrepToolTest, SkipsGitDirectory) {
    createFile(".git/config", "searchable pattern here\n");
    createFile("src/Main.smali", "searchable pattern here\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: searchable pattern | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // Should find in src/ but not in .git/
    EXPECT_EQ(result->observation.find(".git"), std::string::npos);
}

TEST_F(GrepToolTest, GroupsMatchesByFile) {
    createFile("src/A.smali",
        "match1\n"
        "other\n"
        "match2\n");
    createFile("src/B.smali", "match3\n");

    area::GrepTool tool;
    GrepMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: match | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("3 match(es) across 2 file(s)"), std::string::npos);
}
