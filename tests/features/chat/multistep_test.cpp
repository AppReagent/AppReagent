#include <gtest/gtest.h>
#include "features/testing/McpTestClient.h"
#include "util/file_io.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using area::features::testing::McpTestClient;
using json = nlohmann::json;

/// Multi-step agent tests that require scan + query chains.
class MultiStepE2E : public ::testing::Test {
protected:
    void SetUp() override {
        auto self = area::util::selfExe();
        if (!self.empty()) {
            srcDir_ = fs::path(self).parent_path().string();
            binary_ = (fs::path(srcDir_) / "area").string();
        }
        if (binary_.empty() || !fs::exists(binary_)) GTEST_SKIP() << "area binary not found";

        dataDir_ = "/tmp/area-multi-e2e-" + std::to_string(getpid()) + "-" +
                   std::to_string(testCounter_++);
        fs::create_directories(dataDir_);

        // Use scan_pipeline mock (handles both agent and pipeline calls)
        auto mockFile = srcDir_ + "/tests/fixtures/scan_pipeline.json";
        if (!fs::exists(mockFile)) GTEST_SKIP() << "scan_pipeline.json not found";

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
        cfg.erase("embedding");
        {
            std::ofstream out(dataDir_ + "/config.json");
            out << cfg.dump(2);
        }

        if (fs::exists(srcDir_ + "/prompts"))
            fs::copy(srcDir_ + "/prompts", dataDir_ + "/prompts", fs::copy_options::recursive);
        if (fs::exists(srcDir_ + "/ddl.sql"))
            fs::copy_file(srcDir_ + "/ddl.sql", dataDir_ + "/ddl.sql", fs::copy_options::skip_existing);
        if (fs::exists(srcDir_ + "/constitution.md"))
            fs::copy_file(srcDir_ + "/constitution.md", dataDir_ + "/constitution.md", fs::copy_options::skip_existing);

        // Point IMPROVE tool at minimal test corpus (2 files instead of 20)
        auto fixtureCorpus = srcDir_ + "/tests/fixtures/corpus";
        if (fs::exists(fixtureCorpus)) {
            setenv("AREA_CORPUS_DIR", fixtureCorpus.c_str(), 1);
        }

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

    std::string scan(const std::string& path) {
        return client_->callTool("area_scan", {{"path", path}});
    }

    std::string chat(const std::string& msg, const std::string& chatId = "multi") {
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

int MultiStepE2E::testCounter_ = 0;

// ── Ported from: tests/use-cases/find-behavior ───────────────────

TEST_F(MultiStepE2E, FindBehavior) {
    auto smali = asset("find-behavior", "FileReader.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    // Scan first to populate data
    scan(smali);

    // Query behaviors
    auto output = chat("find methods that read from the filesystem");
    bool hasFs = output.find("readExternalFile") != std::string::npos ||
                 output.find("FileInputStream") != std::string::npos ||
                 output.find("file") != std::string::npos ||
                 output.find("filesystem") != std::string::npos;
    EXPECT_TRUE(hasFs) << "Should find filesystem behavior:\n" << output;
}

// ── Ported from: tests/use-cases/xrefs-search ───────────────────

TEST_F(MultiStepE2E, XrefsSearch) {
    auto smali = asset("xrefs-search", "SmsExfil.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    scan(smali);

    auto output = chat("find all cross-references to SmsManager");
    bool hasSms = output.find("SmsManager") != std::string::npos ||
                  output.find("sendTextMessage") != std::string::npos ||
                  output.find("SMS") != std::string::npos;
    EXPECT_TRUE(hasSms) << "Should find SMS references:\n" << output;
}

// ── Ported from: tests/use-cases/similar-methods ─────────────────

TEST_F(MultiStepE2E, SimilarMethods) {
    auto smali = asset("similar-methods", "SmsExfil.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    scan(smali);

    auto output = chat("find methods similar to SMS sending", "similar-test");
    bool hasResult = output.find("sms") != std::string::npos ||
                     output.find("SMS") != std::string::npos ||
                     output.find("similar") != std::string::npos ||
                     output.find("method") != std::string::npos;
    EXPECT_TRUE(hasResult) << "Should find SMS-related results:\n" << output;
}

// ── Ported from: tests/use-cases/call-graph ──────────────────────

TEST_F(MultiStepE2E, CallGraph) {
    auto smali = asset("call-graph", "SmsExfil.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    scan(smali);

    auto output = chat("what methods does exfiltrateViaSms call? use the method_calls table",
                       "callgraph-test");
    bool hasResult = output.find("method") != std::string::npos ||
                     output.find("call") != std::string::npos ||
                     output.find("SmsManager") != std::string::npos;
    EXPECT_TRUE(hasResult) << "Should find call graph data:\n" << output;
}

// ── Ported from: tests/use-cases/analyze-scan ────────────────────

TEST_F(MultiStepE2E, DISABLED_AnalyzeScan) {
    // Disabled in ctest: requires sequential execution (DB contention with parallel tests)
    auto smali = asset("scan-suspicious-file", "SmsExfil.smali");
    if (!fs::exists(smali)) GTEST_SKIP() << "asset not found";

    // Scan to populate results
    auto scanOutput = chat("scan " + smali, "analyze-test");

    // Analyze
    auto output = chat("analyze the latest scan results", "analyze-test");
    // With mock, the agent processes the request and returns something meaningful
    EXPECT_FALSE(output.empty()) << "Should produce some output";
    EXPECT_EQ(output.find("[error]"), std::string::npos)
        << "Should have no errors:\n" << output;
}

// ── Ported from: tests/use-cases/investigate-app ─────────────────

TEST_F(MultiStepE2E, InvestigateApp) {
    auto dir = srcDir_ + "/tests/use-cases/investigate-app/assets";
    if (!fs::exists(dir)) GTEST_SKIP() << "assets not found";

    auto output = chat("what network calls does the app in " + dir + " make?");
    bool hasNetwork = output.find("HTTP") != std::string::npos ||
                      output.find("URL") != std::string::npos ||
                      output.find("network") != std::string::npos ||
                      output.find("connection") != std::string::npos;
    EXPECT_TRUE(hasNetwork) << "Should find network references:\n" << output;
}

// ── Ported from: tests/use-cases/improve-eval ────────────────────

TEST_F(MultiStepE2E, DISABLED_ImproveEval) {
    // Disabled in ctest: runs corpus scan, slow + DB contention
    auto output = chat("evaluate the corpus score", "improve-eval");
    bool hasScore = output.find("score") != std::string::npos ||
                    output.find("evaluation") != std::string::npos ||
                    output.find("corpus") != std::string::npos ||
                    output.find("improve") != std::string::npos;
    EXPECT_TRUE(hasScore) << "Should return evaluation info:\n" << output;
}

// ── Ported from: tests/use-cases/improve-shell-escape ────────────

TEST_F(MultiStepE2E, DISABLED_ImproveShellEscape) {
    // Disabled in ctest: runs corpus scan, slow + DB contention
    auto output = chat("evaluate the corpus with goal: test'; echo INJECTED; echo '",
                       "improve-escape");
    EXPECT_EQ(output.find("INJECTED"), std::string::npos)
        << "Shell injection should not execute:\n" << output;
    EXPECT_EQ(output.find("syntax error"), std::string::npos)
        << "No shell syntax errors:\n" << output;
}
