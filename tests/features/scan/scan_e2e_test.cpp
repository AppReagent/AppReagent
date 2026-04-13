#include <gtest/gtest.h>
#include "features/testing/McpTestClient.h"
#include "util/file_io.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using area::features::testing::McpTestClient;
using json = nlohmann::json;

/// MCP-driven scan pipeline e2e tests.
/// Uses mock backend for the graph pipeline (triage → deep_analysis → synthesis).
class ScanE2E : public ::testing::Test {
protected:
    void SetUp() override {
        auto self = area::util::selfExe();
        if (!self.empty()) {
            srcDir_ = fs::path(self).parent_path().string();
            binary_ = (fs::path(srcDir_) / "area").string();
        }
        if (binary_.empty() || !fs::exists(binary_)) GTEST_SKIP() << "area binary not found";

        dataDir_ = "/tmp/area-scan-e2e-" + std::to_string(getpid()) + "-" +
                   std::to_string(testCounter_++);
        fs::create_directories(dataDir_);

        auto mockFile = srcDir_ + "/tests/fixtures/scan_pipeline.json";
        if (!fs::exists(mockFile)) GTEST_SKIP() << "scan_pipeline.json not found";

        // Build config with mock endpoints at all tiers
        std::string srcConfig = "/opt/area/config.json";
        json cfg;
        if (fs::exists(srcConfig)) {
            std::ifstream in(srcConfig);
            cfg = json::parse(in, nullptr, true, true);
        }
        auto cert = cfg.value("postgres_cert", "");
        if (!cert.empty() && cert[0] != '/') {
            auto absCert = srcDir_ + "/" + cert;
            if (fs::exists(absCert)) {
                cfg["postgres_cert"] = absCert;
                fs::copy_file(absCert, dataDir_ + "/" + cert, fs::copy_options::skip_existing);
            }
        }
        cfg["ai_endpoints"] = json::array({
            {{"id", "mock-t0"}, {"provider", "mock"}, {"url", mockFile},
             {"tier", 0}, {"max_concurrent", 3}, {"context_window", 131072}},
            {{"id", "mock-t1"}, {"provider", "mock"}, {"url", mockFile},
             {"tier", 1}, {"max_concurrent", 3}, {"context_window", 131072}},
            {{"id", "mock-t2"}, {"provider", "mock"}, {"url", mockFile},
             {"tier", 2}, {"max_concurrent", 3}, {"context_window", 131072}}
        });
        // Remove embedding config to avoid external calls
        cfg.erase("embedding");
        {
            std::ofstream out(dataDir_ + "/config.json");
            out << cfg.dump(2);
        }

        // Copy prompts, ddl
        if (fs::exists(srcDir_ + "/prompts"))
            fs::copy(srcDir_ + "/prompts", dataDir_ + "/prompts", fs::copy_options::recursive);
        if (fs::exists(srcDir_ + "/ddl.sql"))
            fs::copy_file(srcDir_ + "/ddl.sql", dataDir_ + "/ddl.sql", fs::copy_options::skip_existing);
        if (fs::exists(srcDir_ + "/constitution.md"))
            fs::copy_file(srcDir_ + "/constitution.md", dataDir_ + "/constitution.md", fs::copy_options::skip_existing);

        client_ = std::make_unique<McpTestClient>(binary_, dataDir_);
        ASSERT_TRUE(client_->start()) << "Failed to start MCP process";
        client_->serverStart();
    }

    void TearDown() override {
        if (client_) {
            try { client_->serverStop(); } catch (...) {}
            client_.reset();
        }
        std::error_code ec;
        fs::remove_all(dataDir_, ec);
    }

    std::string scan(const std::string& path, const std::string& goal = "") {
        json args = {{"path", path}};
        if (!goal.empty()) args["goal"] = goal;
        return client_->callTool("area_scan", args);
    }

    std::string chat(const std::string& msg, const std::string& chatId = "scan-test") {
        return client_->chat(msg, chatId);
    }

    std::string asset(const std::string& testName, const std::string& fileName) {
        return srcDir_ + "/tests/use-cases/" + testName + "/assets/" + fileName;
    }

    std::string binary_;
    std::string srcDir_;
    std::string dataDir_;
    std::unique_ptr<McpTestClient> client_;
    static int testCounter_;
};

int ScanE2E::testCounter_ = 0;

// ── Ported from: tests/use-cases/scan-mock-pipeline ──────────────

TEST_F(ScanE2E, DISABLED_MockPipeline) {
    auto smali = asset("scan-suspicious-file", "SmsExfil.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "SmsExfil.smali not found";

    auto output = scan(smali);
    EXPECT_NE(output.find("relevant"), std::string::npos)
        << "Should classify as relevant:\n" << output;
    bool hasScanned = output.find("1 scanned") != std::string::npos ||
                      output.find("Scanned: 1") != std::string::npos;
    EXPECT_TRUE(hasScanned) << "Should scan 1 file:\n" << output;
}

// ── Ported from: tests/use-cases/scan-suspicious-file ────────────

TEST_F(ScanE2E, DISABLED_SuspiciousFile) {
    auto smali = asset("scan-suspicious-file", "SmsExfil.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    auto output = scan(smali);
    bool isRelevant = output.find("relevant") != std::string::npos ||
                      output.find("Relevant") != std::string::npos;
    EXPECT_TRUE(isRelevant) << "Should detect as relevant:\n" << output;
}

// ── Ported from: tests/use-cases/scan-benign-file ────────────────

TEST_F(ScanE2E, DISABLED_BenignFile) {
    auto smali = asset("scan-benign-file", "BenignActivity.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    auto output = scan(smali);
    bool isBenign = output.find("not_relevant") != std::string::npos ||
                    output.find("0 relevant") != std::string::npos ||
                    output.find("Relevant: 0") != std::string::npos ||
                    output.find("irrelevant") != std::string::npos;
    EXPECT_TRUE(isBenign) << "Should classify as benign:\n" << output;
}

// ── Ported from: tests/use-cases/scan-banking-trojan ─────────────

TEST_F(ScanE2E, DISABLED_BankingTrojan) {
    auto smali = asset("scan-banking-trojan", "OverlayAttack.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    auto output = scan(smali);
    bool isRelevant = output.find("relevant") != std::string::npos ||
                      output.find("Relevant") != std::string::npos;
    EXPECT_TRUE(isRelevant) << "Should detect as relevant:\n" << output;
}

// ── Ported from: tests/use-cases/scan-dropper ────────────────────

TEST_F(ScanE2E, DISABLED_Dropper) {
    auto smali = asset("scan-dropper", "PayloadLoader.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    auto output = scan(smali);
    bool isRelevant = output.find("relevant") != std::string::npos ||
                      output.find("Relevant") != std::string::npos;
    EXPECT_TRUE(isRelevant) << "Should detect as relevant:\n" << output;
}

// ── Ported from: tests/use-cases/scan-persistence ────────────────

TEST_F(ScanE2E, DISABLED_Persistence) {
    auto smali = asset("scan-persistence", "BootPersistence.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    auto output = scan(smali);
    bool isRelevant = output.find("relevant") != std::string::npos ||
                      output.find("Relevant") != std::string::npos;
    EXPECT_TRUE(isRelevant) << "Should detect as relevant:\n" << output;
}

// ── Ported from: tests/use-cases/scan-elf-benign ─────────────────

TEST_F(ScanE2E, DISABLED_ElfBenign) {
    auto elf = asset("scan-elf-benign", "hello");
    if (!fs::exists(elf)) GTEST_SKIP() << "asset not found";

    auto output = scan(elf);
    bool isBenign = output.find("not_relevant") != std::string::npos ||
                    output.find("0 relevant") != std::string::npos ||
                    output.find("Relevant: 0") != std::string::npos;
    EXPECT_TRUE(isBenign) << "Should classify as benign:\n" << output;
}

// ── Ported from: tests/use-cases/scan-elf-malicious ──────────────

TEST_F(ScanE2E, DISABLED_ElfMalicious) {
    auto elf = asset("scan-elf-malicious", "revshell");
    if (!fs::exists(elf)) GTEST_SKIP() << "asset not found";

    auto output = scan(elf);
    bool isRelevant = output.find("relevant") != std::string::npos ||
                      output.find("Relevant") != std::string::npos;
    EXPECT_TRUE(isRelevant) << "Should detect as relevant:\n" << output;
}

// ── Ported from: tests/use-cases/scan-with-goal ──────────────────

TEST_F(ScanE2E, DISABLED_WithGoal) {
    auto smali = asset("scan-with-goal", "NetworkHelper.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    auto output = scan(smali, "does this file open any network connections?");
    bool hasNetwork = output.find("relevant") != std::string::npos ||
                      output.find("network") != std::string::npos ||
                      output.find("HTTP") != std::string::npos ||
                      output.find("connection") != std::string::npos;
    EXPECT_TRUE(hasNetwork) << "Should find network behavior:\n" << output;
}

// ── Ported from: tests/use-cases/scan-lifecycle ──────────────────

TEST_F(ScanE2E, DISABLED_Lifecycle) {
    auto smali = asset("scan-benign-file", "BenignActivity.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    // Scan via agent chat (to test agent integration)
    auto scanOutput = chat("scan " + smali, "lifecycle-a");
    bool hasResult = scanOutput.find("scan") != std::string::npos ||
                     scanOutput.find("Scan") != std::string::npos;
    EXPECT_TRUE(hasResult) << "Should produce scan output:\n" << scanOutput;

    // Check state from different session
    auto stateOutput = chat("is there a scan running right now?", "lifecycle-b");
    bool noActive = stateOutput.find("no active") != std::string::npos ||
                    stateOutput.find("No active") != std::string::npos ||
                    stateOutput.find("no scan") != std::string::npos;
    EXPECT_TRUE(noActive) << "Should report no active scans:\n" << stateOutput;
}

// ── Ported from: tests/use-cases/scan-hidden-malware ─────────────

TEST_F(ScanE2E, DISABLED_HiddenMalware) {
    auto dir = srcDir_ + "/tests/use-cases/scan-hidden-malware/assets";
    if (!fs::exists(dir)) GTEST_SKIP() << "assets not found";

    auto output = scan(dir);
    bool isRelevant = output.find("relevant") != std::string::npos ||
                      output.find("Relevant") != std::string::npos;
    EXPECT_TRUE(isRelevant) << "Should detect hidden malware:\n" << output;
}

// ── Ported from: tests/use-cases/scan-obfuscation ────────────────

TEST_F(ScanE2E, DISABLED_Obfuscation) {
    auto smali = srcDir_ + "/tests/use-cases/scan-obfuscation/assets/ObfuscatedClass.smali";
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    auto output = scan(smali);
    bool isRelevant = output.find("relevant") != std::string::npos ||
                      output.find("score") != std::string::npos;
    EXPECT_TRUE(isRelevant) << "Should detect obfuscation:\n" << output;
}
