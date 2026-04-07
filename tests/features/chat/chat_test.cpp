#include <gtest/gtest.h>
#include "features/testing/McpTestClient.h"
#include "util/file_io.h"

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using area::features::testing::McpTestClient;
using json = nlohmann::json;

/// MCP-driven agent e2e test fixture.
/// Starts server with mock LLM backend, tests agent behavior through MCP.
class McpE2E : public ::testing::Test {
protected:
    void SetUp() override {
        // Find binary
        auto self = area::util::selfExe();
        if (!self.empty()) {
            srcDir_ = fs::path(self).parent_path().string();
            binary_ = (fs::path(srcDir_) / "area").string();
        }
        if (binary_.empty() || !fs::exists(binary_)) GTEST_SKIP() << "area binary not found";

        dataDir_ = "/tmp/area-mcp-e2e-" + std::to_string(getpid());
        fs::create_directories(dataDir_);

        // Find the fixtures directory
        fixturesDir_ = srcDir_ + "/tests/fixtures";
        if (!fs::exists(fixturesDir_)) GTEST_SKIP() << "fixtures dir not found";

        // Write config with mock backend at all tiers
        auto mockFile = fixturesDir_ + "/agent_tools.json";
        if (!fs::exists(mockFile)) GTEST_SKIP() << "agent_tools.json not found";

        // Read real config for postgres connection, rewrite endpoints to mock
        std::string srcConfig = "/opt/area/config.json";
        json cfg;
        if (fs::exists(srcConfig)) {
            std::ifstream in(srcConfig);
            cfg = json::parse(in);
        }
        // Resolve cert path
        auto cert = cfg.value("postgres_cert", "");
        if (!cert.empty() && cert[0] != '/') {
            auto absCert = srcDir_ + "/" + cert;
            if (fs::exists(absCert)) {
                cfg["postgres_cert"] = absCert;
                fs::copy_file(absCert, dataDir_ + "/" + cert, fs::copy_options::skip_existing);
            }
        }
        // Replace endpoints with mock
        cfg["ai_endpoints"] = json::array({
            {{"id", "mock-t0"}, {"provider", "mock"}, {"url", mockFile},
             {"tier", 0}, {"max_concurrent", 3}, {"context_window", 131072}},
            {{"id", "mock-t1"}, {"provider", "mock"}, {"url", mockFile},
             {"tier", 1}, {"max_concurrent", 3}, {"context_window", 131072}},
            {{"id", "mock-t2"}, {"provider", "mock"}, {"url", mockFile},
             {"tier", 2}, {"max_concurrent", 3}, {"context_window", 131072}}
        });
        {
            std::ofstream out(dataDir_ + "/config.json");
            out << cfg.dump(2);
        }

        // Copy prompts, ddl, constitution
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

    std::string chat(const std::string& msg, const std::string& chatId = "test") {
        return client_->chat(msg, chatId);
    }

    std::string binary_;
    std::string srcDir_;
    std::string dataDir_;
    std::string fixturesDir_;
    std::unique_ptr<McpTestClient> client_;
};

// ── Ported from: tests/use-cases/generate-run-id ─────────────────

TEST_F(McpE2E, GenerateRunId) {
    auto output = chat("please generate a new run id for a scan");
    EXPECT_NE(output.find("run"), std::string::npos)
        << "Should mention run in response:\n" << output;
    EXPECT_EQ(output.find("[error]"), std::string::npos)
        << "Should have no errors:\n" << output;
}

// ── Ported from: tests/use-cases/check-scan-state ────────────────

TEST_F(McpE2E, CheckScanState) {
    auto output = chat("is there a scan running right now?");
    bool found = output.find("no active") != std::string::npos ||
                 output.find("No active") != std::string::npos ||
                 output.find("no scan") != std::string::npos ||
                 output.find("not running") != std::string::npos;
    EXPECT_TRUE(found) << "Should report no active scans:\n" << output;
    EXPECT_EQ(output.find("[error]"), std::string::npos)
        << "Should have no errors:\n" << output;
}

// ── Ported from: tests/use-cases/query-tables ────────────────────

TEST_F(McpE2E, QueryTables) {
    auto output = chat("what tables are in the database?");
    EXPECT_NE(output.find("scan_results"), std::string::npos)
        << "Should mention scan_results:\n" << output;
    EXPECT_NE(output.find("llm_calls"), std::string::npos)
        << "Should mention llm_calls:\n" << output;
    EXPECT_EQ(output.find("[error]"), std::string::npos)
        << "Should have no errors:\n" << output;
}

// ── Ported from: tests/use-cases/clear-context ───────────────────

TEST_F(McpE2E, ClearContext) {
    // Establish context
    chat("remember that the secret word is pineapple", "clear-test");

    // Clear
    client_->callTool("area_clear_chat", {{"chat_id", "clear-test"}});

    // Verify forgotten
    auto output = chat("what was the secret word I told you earlier?", "clear-test");
    EXPECT_EQ(output.find("pineapple"), std::string::npos)
        << "Should not remember pineapple after clear:\n" << output;
}
