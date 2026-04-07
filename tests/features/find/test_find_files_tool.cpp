#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "features/find/FindFilesTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"

namespace fs = std::filesystem;

struct FindFilesMessages {
    std::vector<area::AgentMessage> messages;
    area::MessageCallback cb() {
        return [this](const area::AgentMessage& msg) { messages.push_back(msg); };
    }
};

class FindFilesToolTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = "/tmp/test_find_files_" + std::to_string(getpid());
        fs::create_directories(tmpDir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmpDir, ec);
    }

    void createFile(const std::string& relPath, const std::string& content = "") {
        auto full = fs::path(tmpDir) / relPath;
        fs::create_directories(full.parent_path());
        std::ofstream f(full);
        f << content;
    }
};

TEST_F(FindFilesToolTest, IgnoresNonFindFilesAction) {
    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("GREP: pattern", ctx);
    EXPECT_FALSE(result.has_value());
}

TEST_F(FindFilesToolTest, ErrorOnEmptyQuery) {
    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("FIND_FILES: ", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
}

TEST_F(FindFilesToolTest, FindsByExactName) {
    createFile("app/SmsExfil.smali", ".class public Lcom/test/SmsExfil;");
    createFile("app/Other.smali", ".class public Lcom/test/Other;");

    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("FIND_FILES: SmsExfil | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("SmsExfil"), std::string::npos);
    EXPECT_EQ(result->observation.find("Other.smali"), std::string::npos);
}

TEST_F(FindFilesToolTest, FindsBySubstring) {
    createFile("lib/NetworkHelper.java");
    createFile("lib/NetworkClient.java");
    createFile("lib/Database.java");

    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("FIND_FILES: Network | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("NetworkHelper"), std::string::npos);
    EXPECT_NE(result->observation.find("NetworkClient"), std::string::npos);
    EXPECT_EQ(result->observation.find("Database"), std::string::npos);
}

TEST_F(FindFilesToolTest, GlobPatternWithWildcard) {
    createFile("src/Foo.smali");
    createFile("src/Bar.smali");
    createFile("src/Baz.java");

    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("FIND_FILES: *.smali | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Foo.smali"), std::string::npos);
    EXPECT_NE(result->observation.find("Bar.smali"), std::string::npos);
    EXPECT_EQ(result->observation.find("Baz.java"), std::string::npos);
}

TEST_F(FindFilesToolTest, CountsScannableFiles) {
    createFile("app/A.smali");
    createFile("app/B.smali");
    createFile("app/config.xml");

    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("FIND_FILES: *.smali | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("scannable"), std::string::npos);
}

TEST_F(FindFilesToolTest, NoMatchesReturnsEmpty) {
    createFile("app/Foo.smali");

    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("FIND_FILES: nonexistent_xyz | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("No files matching"), std::string::npos);
}

TEST_F(FindFilesToolTest, CaseInsensitiveSearch) {
    createFile("app/MyActivity.smali");

    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("FIND_FILES: myactivity | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("MyActivity"), std::string::npos);
}

TEST_F(FindFilesToolTest, SkipsGitDirectory) {
    createFile(".git/objects/abc123", "blob data");
    createFile("src/Main.smali");

    area::FindFilesTool tool;
    FindFilesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    // Search for something that would match in .git
    auto result = tool.tryExecute("FIND_FILES: abc123 | " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // Should not find the .git file
    EXPECT_NE(result->observation.find("No files matching"), std::string::npos);
}
