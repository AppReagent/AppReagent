#include <gtest/gtest.h>
#include "features/testing/McpTestClient.h"
#include "util/file_io.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using area::features::testing::McpTestClient;
using json = nlohmann::json;

/// Ghidra e2e tests using the headless TUI MCP to invoke the GHIDRA tool.
/// Requires either local Ghidra install or area-ghidra Docker image.
class GhidraE2E : public ::testing::Test {
protected:
    void SetUp() override {
        auto self = area::util::selfExe();
        if (!self.empty()) {
            srcDir_ = fs::path(self).parent_path().string();
            binary_ = (fs::path(srcDir_) / "area").string();
        }
        if (binary_.empty() || !fs::exists(binary_)) GTEST_SKIP() << "area binary not found";

        // Check if Ghidra is available (local or Docker)
        bool hasLocal = false;
        if (auto gh = std::getenv("GHIDRA_HOME")) {
            hasLocal = fs::exists(std::string(gh) + "/support/analyzeHeadless");
        }
        if (!hasLocal) {
            int rc = system("sudo docker image inspect area-ghidra >/dev/null 2>&1");
            if (rc != 0) GTEST_SKIP() << "Ghidra not available (no local install or Docker image)";
        }

        // Check for test binaries
        revshell_ = srcDir_ + "/tests/use-cases/scan-elf-malicious/assets/revshell";
        hello_ = srcDir_ + "/tests/use-cases/scan-elf-benign/assets/hello";
        if (!fs::exists(revshell_) || !fs::exists(hello_))
            GTEST_SKIP() << "ELF test binaries not found";

        dataDir_ = "/tmp/area-ghidra-e2e-" + std::to_string(getpid());
        fs::create_directories(dataDir_);

        // Config with mock agent backend
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

    std::string chat(const std::string& msg) {
        return client_->chat(msg, "ghidra-test");
    }

    std::string binary_;
    std::string srcDir_;
    std::string dataDir_;
    std::string revshell_;
    std::string hello_;
    std::unique_ptr<McpTestClient> client_;
};

// ── Ported from: tests/use-cases/ghidra-analyze ──────────────────

TEST_F(GhidraE2E, DecompileRevshell) {
    auto output = chat("use ghidra to decompile the main function in " + revshell_);
    bool hasDecompiled = output.find("main") != std::string::npos ||
                         output.find("decompil") != std::string::npos;
    EXPECT_TRUE(hasDecompiled) << "Should show decompiled main:\n" << output;

    bool hasMalicious = output.find("socket") != std::string::npos ||
                        output.find("connect") != std::string::npos ||
                        output.find("exec") != std::string::npos ||
                        output.find("shell") != std::string::npos;
    EXPECT_TRUE(hasMalicious) << "Should identify malicious patterns:\n" << output;
}

TEST_F(GhidraE2E, OverviewBenign) {
    auto output = chat("use ghidra to get an overview of " + hello_);
    bool hasOverview = output.find("main") != std::string::npos ||
                       output.find("function") != std::string::npos ||
                       output.find("ELF") != std::string::npos;
    EXPECT_TRUE(hasOverview) << "Should show binary overview:\n" << output;
}
