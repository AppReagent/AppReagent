#include <gtest/gtest.h>
#include "tools/ReadCodeTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using namespace area;

class ReadCodeToolTest : public ::testing::Test {
protected:
    void SetUp() override {
        tmpDir_ = "/tmp/test_read_code_" + std::to_string(getpid());
        fs::create_directories(tmpDir_);
    }

    void TearDown() override {
        fs::remove_all(tmpDir_);
    }

    std::string tmpDir_;
    ReadCodeTool tool_;
    Harness harness_;

    ToolContext makeCtx() {
        return ToolContext{[](const AgentMessage&){}, nullptr, harness_};
    }

    void writeFile(const std::string& name, const std::string& content) {
        std::ofstream f(tmpDir_ + "/" + name);
        f << content;
    }
};

TEST_F(ReadCodeToolTest, DoesNotMatchNonReadActions) {
    auto ctx = makeCtx();
    EXPECT_FALSE(tool_.tryExecute("SQL: SELECT 1", ctx).has_value());
    EXPECT_FALSE(tool_.tryExecute("SCAN: /path", ctx).has_value());
    EXPECT_FALSE(tool_.tryExecute("ANSWER: hello", ctx).has_value());
    EXPECT_FALSE(tool_.tryExecute("FIND: behavior", ctx).has_value());
}

TEST_F(ReadCodeToolTest, MatchesReadPrefix) {
    auto ctx = makeCtx();
    auto result = tool_.tryExecute("READ: /nonexistent/file.smali", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("not found"), std::string::npos);
}

TEST_F(ReadCodeToolTest, ReadsSmaliFile) {
    std::string smali =
        ".class public Lcom/example/Test;\n"
        ".super Ljava/lang/Object;\n"
        "\n"
        ".method public test()V\n"
        "    .locals 0\n"
        "    return-void\n"
        ".end method\n";

    writeFile("Test.smali", smali);
    auto ctx = makeCtx();
    auto result = tool_.tryExecute("READ: " + tmpDir_ + "/Test.smali", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Lcom/example/Test"), std::string::npos);
    EXPECT_NE(result->observation.find("test"), std::string::npos);
}

TEST_F(ReadCodeToolTest, ReadsSmaliMethodByName) {
    std::string smali =
        ".class public Lcom/example/Multi;\n"
        ".super Ljava/lang/Object;\n"
        "\n"
        ".method public foo()V\n"
        "    .locals 0\n"
        "    return-void\n"
        ".end method\n"
        "\n"
        ".method public bar()V\n"
        "    .locals 0\n"
        "    return-void\n"
        ".end method\n";

    writeFile("Multi.smali", smali);
    auto ctx = makeCtx();
    auto result = tool_.tryExecute("READ: " + tmpDir_ + "/Multi.smali bar", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("bar"), std::string::npos);
}

TEST_F(ReadCodeToolTest, ReadsGenericFile) {
    writeFile("manifest.xml", "<manifest package=\"com.example\"/>");
    auto ctx = makeCtx();
    auto result = tool_.tryExecute("READ: " + tmpDir_ + "/manifest.xml", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("com.example"), std::string::npos);
}

TEST_F(ReadCodeToolTest, ReadsDirectory) {
    writeFile("A.smali", ".class public La;");
    writeFile("B.smali", ".class public Lb;");
    auto ctx = makeCtx();
    auto result = tool_.tryExecute("READ: " + tmpDir_, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("smali"), std::string::npos);
    EXPECT_NE(result->observation.find("A.smali"), std::string::npos);
}

TEST_F(ReadCodeToolTest, ErrorOnEmptyArgs) {
    auto ctx = makeCtx();
    auto result = tool_.tryExecute("READ:", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
}
