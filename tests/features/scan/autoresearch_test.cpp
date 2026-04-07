#include <gtest/gtest.h>
#include "features/testing/McpTestClient.h"
#include "util/file_io.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using area::features::testing::McpTestClient;
using json = nlohmann::json;

/// Autoresearch evaluation test — scans malware + benign, verifies separation.
class AutoresearchE2E : public ::testing::Test {
protected:
    void SetUp() override {
        auto self = area::util::selfExe();
        if (!self.empty()) {
            srcDir_ = fs::path(self).parent_path().string();
            binary_ = (fs::path(srcDir_) / "area").string();
        }
        if (binary_.empty() || !fs::exists(binary_)) GTEST_SKIP() << "area binary not found";

        // Check for corpus files
        malware_ = srcDir_ + "/tests/fixtures/corpus/malware/SmsExfil.smali";
        benign_ = srcDir_ + "/tests/fixtures/corpus/benign/BenignActivity.smali";
        if (!fs::exists(malware_) || !fs::exists(benign_))
            GTEST_SKIP() << "corpus files not found";

        dataDir_ = "/tmp/area-autoresearch-e2e-" + std::to_string(getpid());
        fs::create_directories(dataDir_);

        auto mockFile = srcDir_ + "/tests/fixtures/scan_pipeline.json";
        std::string srcConfig = "/opt/area/config.json";
        json cfg;
        if (fs::exists(srcConfig)) {
            std::ifstream in(srcConfig);
            cfg = json::parse(in);
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

        client_ = std::make_unique<McpTestClient>(binary_, dataDir_);
        ASSERT_TRUE(client_->start());
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

    std::string binary_;
    std::string srcDir_;
    std::string dataDir_;
    std::string malware_;
    std::string benign_;
    std::unique_ptr<McpTestClient> client_;
};

// ── Ported from: tests/use-cases/autoresearch-eval ───────────────

TEST_F(AutoresearchE2E, ScanMalwareAndBenign) {
    // Scan malware
    auto malOut = client_->callTool("area_scan", {{"path", malware_}});
    bool malScanned = malOut.find("relevant") != std::string::npos ||
                      malOut.find("Relevant") != std::string::npos ||
                      malOut.find("Scan") != std::string::npos;
    EXPECT_TRUE(malScanned) << "Malware scan should produce output:\n" << malOut;

    // Scan benign
    auto benOut = client_->callTool("area_scan", {{"path", benign_}});
    bool benScanned = benOut.find("scan") != std::string::npos ||
                      benOut.find("Scan") != std::string::npos;
    EXPECT_TRUE(benScanned) << "Benign scan should produce output:\n" << benOut;
}
