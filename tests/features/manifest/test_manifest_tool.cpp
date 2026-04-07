#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "features/manifest/ManifestTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"

namespace fs = std::filesystem;

struct ManifestMessages {
    std::vector<area::AgentMessage> messages;
    area::MessageCallback cb() {
        return [this](const area::AgentMessage& msg) { messages.push_back(msg); };
    }
};

class ManifestToolTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = "/tmp/test_manifest_" + std::to_string(getpid());
        fs::create_directories(tmpDir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmpDir, ec);
    }

    std::string writeManifest(const std::string& content) {
        std::string path = tmpDir + "/AndroidManifest.xml";
        std::ofstream f(path);
        f << content;
        return path;
    }
};

TEST_F(ManifestToolTest, IgnoresNonManifestAction) {
    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("SCAN: /some/file", ctx);
    EXPECT_FALSE(result.has_value());
}

TEST_F(ManifestToolTest, ErrorOnEmptyPath) {
    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: ", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
}

TEST_F(ManifestToolTest, ErrorOnNonexistentPath) {
    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: /nonexistent/path/xyz", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("not found"), std::string::npos);
}

TEST_F(ManifestToolTest, ParsesPackageAndSdk) {
    writeManifest(R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.malware">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
</manifest>
)");

    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("com.example.malware"), std::string::npos);
    EXPECT_NE(result->observation.find("Min SDK: 21"), std::string::npos);
    EXPECT_NE(result->observation.find("Target SDK: 33"), std::string::npos);
}

TEST_F(ManifestToolTest, ParsesPermissions) {
    writeManifest(R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_CONTACTS" />
    <uses-permission android:name="android.permission.VIBRATE" />
</manifest>
)");

    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Permissions (3)"), std::string::npos);
    EXPECT_NE(result->observation.find("INTERNET"), std::string::npos);
    EXPECT_NE(result->observation.find("READ_CONTACTS"), std::string::npos);
    EXPECT_NE(result->observation.find("VIBRATE"), std::string::npos);
    // Dangerous permissions should be marked with [!]
    EXPECT_NE(result->observation.find("[!]"), std::string::npos);
}

TEST_F(ManifestToolTest, ParsesComponents) {
    writeManifest(R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
            </intent-filter>
        </activity>
        <service android:name=".BackgroundService" android:exported="false" />
        <receiver android:name=".BootReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        <provider android:name=".DataProvider" android:authorities="com.test.app.provider" android:exported="false" />
    </application>
</manifest>
)");

    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());

    EXPECT_NE(result->observation.find("Activities (1)"), std::string::npos);
    EXPECT_NE(result->observation.find(".MainActivity"), std::string::npos);
    EXPECT_NE(result->observation.find("[exported]"), std::string::npos);

    EXPECT_NE(result->observation.find("Services (1)"), std::string::npos);
    EXPECT_NE(result->observation.find(".BackgroundService"), std::string::npos);

    EXPECT_NE(result->observation.find("Receivers (1)"), std::string::npos);
    EXPECT_NE(result->observation.find(".BootReceiver"), std::string::npos);

    EXPECT_NE(result->observation.find("Providers (1)"), std::string::npos);
    EXPECT_NE(result->observation.find(".DataProvider"), std::string::npos);
    EXPECT_NE(result->observation.find("com.test.app.provider"), std::string::npos);
}

TEST_F(ManifestToolTest, ParsesIntentFilters) {
    writeManifest(R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    <application>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <action android:name="android.intent.action.VIEW" />
            </intent-filter>
        </activity>
    </application>
</manifest>
)");

    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Intent Filters"), std::string::npos);
    EXPECT_NE(result->observation.find("android.intent.action.MAIN"), std::string::npos);
    EXPECT_NE(result->observation.find("android.intent.action.VIEW"), std::string::npos);
}

TEST_F(ManifestToolTest, ParsesMetaData) {
    writeManifest(R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app">
    <application>
        <meta-data android:name="com.google.android.gms.version" android:value="12451000" />
    </application>
</manifest>
)");

    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: " + tmpDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Meta-data"), std::string::npos);
    EXPECT_NE(result->observation.find("com.google.android.gms.version"), std::string::npos);
    EXPECT_NE(result->observation.find("12451000"), std::string::npos);
}

TEST_F(ManifestToolTest, DirectManifestPath) {
    auto path = writeManifest(R"(<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.direct.test">
</manifest>
)");

    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: " + path, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("com.direct.test"), std::string::npos);
}

TEST_F(ManifestToolTest, NoManifestInDir) {
    // Create a dir without AndroidManifest.xml
    std::string emptyDir = tmpDir + "/empty";
    fs::create_directories(emptyDir);

    area::ManifestTool tool;
    ManifestMessages msgs;
    area::Harness h;
    area::ToolContext ctx{msgs.cb(), nullptr, h};

    auto result = tool.tryExecute("MANIFEST: " + emptyDir, ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("not found"), std::string::npos);
}
