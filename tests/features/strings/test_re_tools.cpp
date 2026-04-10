#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "features/strings/StringsTool.h"
#include "features/disasm/DisasmTool.h"
#include "features/manifest/PermissionsTool.h"
#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "infra/agent/Harness.h"

namespace fs = std::filesystem;

static std::string createTempFile(const std::string& suffix, const std::string& content) {
    std::string path = "/tmp/test_re_tools_" + std::to_string(getpid()) + suffix;
    std::ofstream f(path);
    f << content;
    f.close();
    return path;
}

static void removeTempFile(const std::string& path) {
    std::error_code ec;
    fs::remove(path, ec);
}

struct ToolMessages {
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

TEST(StringsTool, ExtractsUrlsFromSmali) {
    std::string smali = R"(
.class public Lcom/test/Net;
.super Ljava/lang/Object;
.method public connect()V
    .locals 1
    const-string v0, "http://evil.example.com/beacon"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("evil.example.com"), std::string::npos);
    EXPECT_NE(result->observation.find("URL"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsIpAddresses) {
    std::string smali = R"(
.class public Lcom/test/C2;
.super Ljava/lang/Object;
.method public beacon()V
    .locals 1
    const-string v0, "http://192.168.1.100:8080/api"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("192.168.1.100"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsPhoneNumbers) {
    std::string smali = R"(
.class public Lcom/test/Sms;
.super Ljava/lang/Object;
.method public send()V
    .locals 1
    const-string v0, "+15551234567"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("15551234567"), std::string::npos);
    EXPECT_NE(result->observation.find("Phone"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsReflectionTargets) {
    std::string smali = R"(
.class public Lcom/test/Evade;
.super Ljava/lang/Object;
.method public exec()V
    .locals 1
    const-string v0, "java.lang.Runtime"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("java.lang.Runtime"), std::string::npos);
    EXPECT_NE(result->observation.find("eflection"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsCryptoConstants) {
    std::string smali = R"(
.class public Lcom/test/Crypto;
.super Ljava/lang/Object;
.method public encrypt()V
    .locals 1
    const-string v0, "AES/CBC/PKCS5Padding"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("AES"), std::string::npos);
    EXPECT_NE(result->observation.find("rypto"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsFilePaths) {
    std::string smali = R"(
.class public Lcom/test/Stealer;
.super Ljava/lang/Object;
.method public steal()V
    .locals 1
    const-string v0, "/sdcard/Download/.hidden_data"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("sdcard"), std::string::npos);
    EXPECT_NE(result->observation.find("ile"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsApiKeys) {
    std::string smali = R"(
.class public Lcom/test/Config;
.super Ljava/lang/Object;
.method public init()V
    .locals 1
    const-string v0, "AIzaSyA1234567890abcdefghijklmnop"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("AIza"), std::string::npos);
    EXPECT_NE(result->observation.find("API Key"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsEmailAddresses) {
    std::string smali = R"(
.class public Lcom/test/Exfil;
.super Ljava/lang/Object;
.method public send()V
    .locals 1
    const-string v0, "attacker@evil-domain.com"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("attacker@evil-domain.com"), std::string::npos);
    EXPECT_NE(result->observation.find("Email"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsJwtTokens) {
    std::string smali = R"(
.class public Lcom/test/Auth;
.super Ljava/lang/Object;
.method public auth()V
    .locals 1
    const-string v0, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("eyJ"), std::string::npos);
    EXPECT_NE(result->observation.find("JWT"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, ExtractsMixedCharsetSecrets) {
    std::string smali = R"(
.class public Lcom/test/Secrets;
.super Ljava/lang/Object;
.method public getKey()V
    .locals 1
    const-string v0, "s3cr3t_k3y_12345"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("s3cr3t_k3y"), std::string::npos);

    removeTempFile(path);
}

TEST(StringsTool, IgnoresNonMatchingAction) {
    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("SCAN: /path", ctx);
    EXPECT_FALSE(result.has_value());
}

TEST(StringsTool, HandlesNonexistentPath) {
    area::StringsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("STRINGS: /nonexistent/file.smali", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("not found"), std::string::npos);
}

TEST(DisasmTool, ListsMethodsInSmali) {
    std::string smali = R"(
.class public Lcom/test/Foo;
.super Ljava/lang/Object;
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public doStuff()V
    .locals 0
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::DisasmTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("DISASM: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("<init>"), std::string::npos);
    EXPECT_NE(result->observation.find("doStuff"), std::string::npos);
    EXPECT_NE(result->observation.find("Method"), std::string::npos);

    removeTempFile(path);
}

TEST(DisasmTool, ShowsSpecificMethod) {
    std::string smali = R"(
.class public Lcom/test/Bar;
.super Ljava/lang/Object;
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
.method public sendSMS()V
    .locals 2
    invoke-static {}, Landroid/telephony/SmsManager;->getDefault()Landroid/telephony/SmsManager;
    move-result-object v0
    const-string v1, "+15551234567"
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::DisasmTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("DISASM: " + path + " | sendSMS", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("SmsManager"), std::string::npos);
    EXPECT_NE(result->observation.find("invoke-static"), std::string::npos);
    // Should show call targets
    EXPECT_NE(result->observation.find("Call target"), std::string::npos);

    removeTempFile(path);
}

TEST(DisasmTool, ShowsFieldInfo) {
    std::string smali = R"(
.class public Lcom/test/Fields;
.super Ljava/lang/Object;
.field private secret:Ljava/lang/String;
.field public flag:Z
.method public constructor <init>()V
    .locals 0
    return-void
.end method
)";
    auto path = createTempFile(".smali", smali);

    area::DisasmTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("DISASM: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("secret"), std::string::npos);
    EXPECT_NE(result->observation.find("flag"), std::string::npos);

    removeTempFile(path);
}

TEST(PermissionsTool, ParsesDangerousPermissions) {
    std::string manifest = R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app" android:versionName="1.0">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.SEND_SMS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application>
        <activity android:name=".Main" android:exported="true" />
    </application>
</manifest>)";
    auto path = createTempFile(".xml", manifest);

    area::PermissionsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("PERMISSIONS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("READ_SMS"), std::string::npos);
    EXPECT_NE(result->observation.find("SEND_SMS"), std::string::npos);
    EXPECT_NE(result->observation.find("CAMERA"), std::string::npos);
    EXPECT_NE(result->observation.find("[!]"), std::string::npos); // danger markers

    removeTempFile(path);
}

TEST(PermissionsTool, DetectsSuspiciousCombinations) {
    std::string manifest = R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.spy">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <application />
</manifest>)";
    auto path = createTempFile(".xml", manifest);

    area::PermissionsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("PERMISSIONS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    // Should flag SMS+internet and camera+internet combinations
    EXPECT_NE(result->observation.find("Suspicious"), std::string::npos);
    EXPECT_NE(result->observation.find("exfiltration"), std::string::npos);

    removeTempFile(path);
}

TEST(PermissionsTool, ParsesComponents) {
    std::string manifest = R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.comp">
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <service android:name=".BackgroundSync" android:exported="false" />
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>)";
    auto path = createTempFile(".xml", manifest);

    area::PermissionsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("PERMISSIONS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("MainActivity"), std::string::npos);
    EXPECT_NE(result->observation.find("BackgroundSync"), std::string::npos);
    EXPECT_NE(result->observation.find("BootReceiver"), std::string::npos);
    EXPECT_NE(result->observation.find("EXPORTED"), std::string::npos);
    EXPECT_NE(result->observation.find("BOOT_COMPLETED"), std::string::npos);

    removeTempFile(path);
}

TEST(PermissionsTool, ParsesPackageInfo) {
    std::string manifest = R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.info" android:versionName="2.1.0" android:versionCode="42">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
    <application />
</manifest>)";
    auto path = createTempFile(".xml", manifest);

    area::PermissionsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("PERMISSIONS: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("com.test.info"), std::string::npos);
    EXPECT_NE(result->observation.find("2.1.0"), std::string::npos);
    EXPECT_NE(result->observation.find("21"), std::string::npos); // minSdk

    removeTempFile(path);
}

TEST(PermissionsTool, HandlesManifestNotFound) {
    area::PermissionsTool tool;
    ToolMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("PERMISSIONS: /nonexistent/path", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("not found"), std::string::npos);
}

TEST(ToolPrefixes, AllNewToolsIgnoreUnrelatedActions) {
    area::Harness h;
    ToolMessages msgs;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    area::StringsTool strings;
    area::DisasmTool disasm;
    area::PermissionsTool perms;

    // Each tool should return nullopt for non-matching prefixes
    EXPECT_FALSE(strings.tryExecute("SCAN: /path", ctx).has_value());
    EXPECT_FALSE(strings.tryExecute("SQL: SELECT 1", ctx).has_value());
    EXPECT_FALSE(disasm.tryExecute("STRINGS: /path", ctx).has_value());
    EXPECT_FALSE(perms.tryExecute("DISASM: /path", ctx).has_value());
}

TEST(ToolPrefixes, NewToolNamesAreCorrect) {
    area::StringsTool strings;
    area::DisasmTool disasm;
    area::PermissionsTool perms;

    EXPECT_EQ(strings.name(), "STRINGS");
    EXPECT_EQ(disasm.name(), "DISASM");
    EXPECT_EQ(perms.name(), "PERMISSIONS");
}
