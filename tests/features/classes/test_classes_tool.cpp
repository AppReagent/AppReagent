#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "features/classes/ClassesTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"

namespace fs = std::filesystem;

struct ClassesMessages {
    std::vector<area::AgentMessage> messages;
    area::MessageCallback cb() {
        return [this](const area::AgentMessage& msg) { messages.push_back(msg); };
    }
};

class ClassesToolTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = "/tmp/test_classes_" + std::to_string(getpid());
        fs::create_directories(tmpDir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmpDir, ec);
    }

    void writeSmali(const std::string& relPath, const std::string& content) {
        auto full = fs::path(tmpDir) / relPath;
        fs::create_directories(full.parent_path());
        std::ofstream f(full);
        f << content;
    }
};

TEST_F(ClassesToolTest, IgnoresNonClassesAction) {
    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("SCAN: /path", ctx);
    EXPECT_FALSE(result.has_value());
}

TEST_F(ClassesToolTest, ErrorOnEmptyPath) {
    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: ", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
}

TEST_F(ClassesToolTest, ErrorOnNonexistentPath) {
    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: /nonexistent/xyz", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("not found"), std::string::npos);
}

TEST_F(ClassesToolTest, ParsesSingleClass) {
    writeSmali("com/example/Foo.smali", R"(
.class public Lcom/example/Foo;
.super Ljava/lang/Object;

.field private name:Ljava/lang/String;
.field private count:I

.method public constructor <init>()V
    .locals 0
    return-void
.end method

.method public doWork()V
    .locals 0
    return-void
.end method

.method public getName()Ljava/lang/String;
    .locals 1
    return-object v0
.end method
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("1 class(es)"), std::string::npos);
    EXPECT_NE(result->observation.find("Foo"), std::string::npos);
    EXPECT_NE(result->observation.find("com.example"), std::string::npos);
    EXPECT_NE(result->observation.find("3 methods"), std::string::npos);
    EXPECT_NE(result->observation.find("2 fields"), std::string::npos);
}

TEST_F(ClassesToolTest, ParsesInheritanceAndInterfaces) {
    writeSmali("com/example/MyService.smali", R"(
.class public Lcom/example/MyService;
.super Landroid/app/Service;
.implements Ljava/lang/Runnable;
.implements Ljava/io/Serializable;

.method public constructor <init>()V
    .locals 0
    return-void
.end method
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("extends Service"), std::string::npos);
    EXPECT_NE(result->observation.find("Runnable"), std::string::npos);
    EXPECT_NE(result->observation.find("Serializable"), std::string::npos);
}

TEST_F(ClassesToolTest, ParsesAbstractAndInterface) {
    writeSmali("com/example/Base.smali", R"(
.class public abstract Lcom/example/Base;
.super Ljava/lang/Object;

.method public abstract doSomething()V
.end method
)");
    writeSmali("com/example/ICallback.smali", R"(
.class public interface abstract Lcom/example/ICallback;
.super Ljava/lang/Object;

.method public abstract onResult(Ljava/lang/String;)V
.end method
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("[abstract]"), std::string::npos);
    EXPECT_NE(result->observation.find("[interface]"), std::string::npos);
}

TEST_F(ClassesToolTest, FilterByClassName) {
    writeSmali("com/example/Foo.smali", R"(
.class public Lcom/example/Foo;
.super Ljava/lang/Object;
)");
    writeSmali("com/example/Bar.smali", R"(
.class public Lcom/example/Bar;
.super Ljava/lang/Object;
)");
    writeSmali("com/other/Baz.smali", R"(
.class public Lcom/other/Baz;
.super Ljava/lang/Object;
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir + " | Foo", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("1 class(es)"), std::string::npos);
    EXPECT_NE(result->observation.find("Foo"), std::string::npos);
    // Bar and Baz should be filtered out
    EXPECT_EQ(result->observation.find("Bar"), std::string::npos);
    EXPECT_EQ(result->observation.find("Baz"), std::string::npos);
}

TEST_F(ClassesToolTest, FilterByPackage) {
    writeSmali("com/example/A.smali", R"(
.class public Lcom/example/A;
.super Ljava/lang/Object;
)");
    writeSmali("com/other/B.smali", R"(
.class public Lcom/other/B;
.super Ljava/lang/Object;
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir + " | com.other", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("1 class(es)"), std::string::npos);
    EXPECT_EQ(result->observation.find("com.example"), std::string::npos);
}

TEST_F(ClassesToolTest, MultiplePackagesGrouped) {
    writeSmali("com/app/net/Http.smali", R"(
.class public Lcom/app/net/Http;
.super Ljava/lang/Object;
)");
    writeSmali("com/app/ui/Main.smali", R"(
.class public Lcom/app/ui/Main;
.super Ljava/lang/Object;
)");
    writeSmali("com/app/ui/Settings.smali", R"(
.class public Lcom/app/ui/Settings;
.super Ljava/lang/Object;
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("3 class(es)"), std::string::npos);
    EXPECT_NE(result->observation.find("2 package(s)"), std::string::npos);
    EXPECT_NE(result->observation.find("com.app.net"), std::string::npos);
    EXPECT_NE(result->observation.find("com.app.ui"), std::string::npos);
}

TEST_F(ClassesToolTest, MethodNamesPreview) {
    writeSmali("com/example/Net.smali", R"(
.class public Lcom/example/Net;
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    return-void
.end method

.method public connect(Ljava/lang/String;)V
    .locals 0
    return-void
.end method

.method public disconnect()V
    .locals 0
    return-void
.end method
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    // Should show method names but skip <init>
    EXPECT_NE(result->observation.find("connect"), std::string::npos);
    EXPECT_NE(result->observation.find("disconnect"), std::string::npos);
}

TEST_F(ClassesToolTest, SingleFileMode) {
    writeSmali("Test.smali", R"(
.class public Lcom/test/Test;
.super Ljava/lang/Object;
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir + "/Test.smali", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("1 class(es)"), std::string::npos);
    EXPECT_NE(result->observation.find("Test"), std::string::npos);
}

TEST_F(ClassesToolTest, NonSmaliFileRejected) {
    std::ofstream(tmpDir + "/test.txt") << "not smali";

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir + "/test.txt", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Not a .smali"), std::string::npos);
}

TEST_F(ClassesToolTest, NoMatchesWithFilter) {
    writeSmali("com/example/Foo.smali", R"(
.class public Lcom/example/Foo;
.super Ljava/lang/Object;
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir + " | nonexistent", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("No classes found"), std::string::npos);
}

TEST_F(ClassesToolTest, EnumClass) {
    writeSmali("com/example/Color.smali", R"(
.class public final enum Lcom/example/Color;
.super Ljava/lang/Enum;

.field public static final enum RED:Lcom/example/Color;
.field public static final enum GREEN:Lcom/example/Color;
.field public static final enum BLUE:Lcom/example/Color;
)");

    area::ClassesTool tool;
    ClassesMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("CLASSES: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("[enum]"), std::string::npos);
    EXPECT_NE(result->observation.find("3 fields"), std::string::npos);
}
