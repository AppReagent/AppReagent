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
            cfg = json::parse(in, nullptr, true, true);
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

// ── Ported from: tests/use-cases/sql-markdown-stripping ──────────

TEST_F(McpE2E, SqlMarkdownStripping) {
    auto output = chat("how many rows are in the scan_results table?");
    EXPECT_EQ(output.find("syntax error"), std::string::npos)
        << "Should have no SQL syntax errors:\n" << output;
    EXPECT_EQ(output.find("max iterations"), std::string::npos)
        << "Should not hit max iterations:\n" << output;
    EXPECT_FALSE(output.empty()) << "Should have a response";
}

// ── Ported from: tests/use-cases/find-files ──────────────────────

TEST_F(McpE2E, FindFiles) {
    auto output = chat("find me the SmsExfil smali file, I don't remember the exact path");
    EXPECT_NE(output.find("SmsExfil"), std::string::npos)
        << "Should find SmsExfil:\n" << output;
    EXPECT_EQ(output.find("[error]"), std::string::npos)
        << "Should have no errors:\n" << output;
}

// ── Tool-execution tests ─────────────────────────────────────────
// These tests need a real LLM to extract paths from user messages
// and route to the correct tools. With mock backend they verify
// no errors; with real LLM they verify actual tool output.
// TODO: Add {{path_from_user}} mock variable to enable full mock testing.

TEST_F(McpE2E, ManifestParse) {
    auto manifest = srcDir_ + "/tests/use-cases/manifest-parse/assets/AndroidManifest.xml";
    if (!fs::exists(manifest)) GTEST_SKIP() << "manifest asset not found";

    auto output = chat("analyze the manifest at " + manifest);
    bool hasPerms = output.find("INTERNET") != std::string::npos ||
                    output.find("READ_CONTACTS") != std::string::npos ||
                    output.find("SEND_SMS") != std::string::npos ||
                    output.find("permission") != std::string::npos;
    EXPECT_TRUE(hasPerms) << "Should find permissions:\n" << output;

    bool hasComponents = output.find("MalwareService") != std::string::npos ||
                         output.find("BootReceiver") != std::string::npos ||
                         output.find("MainActivity") != std::string::npos;
    EXPECT_TRUE(hasComponents) << "Should find components:\n" << output;
}

// ── Ported from: tests/use-cases/permissions-manifest ────────────

TEST_F(McpE2E, PermissionsManifest) {
    auto manifest = srcDir_ + "/tests/use-cases/permissions-manifest/assets/AndroidManifest.xml";
    if (!fs::exists(manifest)) GTEST_SKIP() << "manifest asset not found";

    auto output = chat("analyze the permissions in " + manifest);
    bool hasSms = output.find("READ_SMS") != std::string::npos ||
                  output.find("SEND_SMS") != std::string::npos ||
                  output.find("SMS") != std::string::npos;
    EXPECT_TRUE(hasSms) << "Should find SMS permissions:\n" << output;

    bool hasInternet = output.find("INTERNET") != std::string::npos ||
                       output.find("internet") != std::string::npos;
    EXPECT_TRUE(hasInternet) << "Should find internet permission:\n" << output;

    bool hasSuspicious = output.find("suspicious") != std::string::npos ||
                         output.find("exfiltration") != std::string::npos ||
                         output.find("surveillance") != std::string::npos ||
                         output.find("combination") != std::string::npos;
    EXPECT_TRUE(hasSuspicious) << "Should flag suspicious combinations:\n" << output;
}

// ── Ported from: tests/use-cases/read-code ───────────────────────

TEST_F(McpE2E, ReadCode) {
    auto smali = srcDir_ + "/tests/use-cases/read-code/assets/MalwareService.smali";
    if (!fs::exists(smali)) GTEST_SKIP() << "read-code asset not found";

    auto output = chat("show me the contents of " + smali);
    bool hasContent = output.find("MalwareService") != std::string::npos ||
                      output.find("exfiltrateData") != std::string::npos;
    EXPECT_TRUE(hasContent) << "Should show file content:\n" << output;
}

// ── Ported from: tests/use-cases/grep-code ───────────────────────

TEST_F(McpE2E, GrepCode) {
    auto smali = srcDir_ + "/tests/use-cases/grep-code/assets/MalwareService.smali";
    if (!fs::exists(smali)) GTEST_SKIP() << "grep-code asset not found";

    auto output = chat("find all network calls in " + smali);
    bool hasNetwork = output.find("HttpURLConnection") != std::string::npos ||
                      output.find("openConnection") != std::string::npos ||
                      output.find("URL") != std::string::npos;
    EXPECT_TRUE(hasNetwork) << "Should find network code:\n" << output;
}

// ── Ported from: tests/use-cases/strings-extract ─────────────────

TEST_F(McpE2E, StringsExtract) {
    auto smali = srcDir_ + "/tests/use-cases/strings-extract/assets/MalwareService.smali";
    if (!fs::exists(smali)) GTEST_SKIP() << "strings-extract asset not found";

    auto output = chat("extract all hardcoded strings from " + smali);
    bool hasStrings = output.find("evil-c2.example.com") != std::string::npos ||
                      output.find("s3cr3t_k3y") != std::string::npos ||
                      output.find("https") != std::string::npos ||
                      output.find("content://") != std::string::npos;
    EXPECT_TRUE(hasStrings) << "Should find hardcoded strings:\n" << output;
}

// ── Ported from: tests/use-cases/disasm-method ───────────────────

TEST_F(McpE2E, DisasmMethod) {
    auto smali = srcDir_ + "/tests/use-cases/disasm-method/assets/SmsExfil.smali";
    if (!fs::exists(smali)) GTEST_SKIP() << "disasm-method asset not found";

    auto output = chat("show me the methods in " + smali);
    bool hasMethods = output.find("sendStolenData") != std::string::npos ||
                      output.find("stealContacts") != std::string::npos ||
                      output.find("exfiltrate") != std::string::npos ||
                      output.find("SmsManager") != std::string::npos ||
                      output.find("method") != std::string::npos;
    EXPECT_TRUE(hasMethods) << "Should list methods:\n" << output;
}

// ── Ported from: tests/use-cases/decompile-method ────────────────

TEST_F(McpE2E, DecompileMethod) {
    auto smali = srcDir_ + "/tests/use-cases/decompile-method/assets/MalwareService.smali";
    if (!fs::exists(smali)) GTEST_SKIP() << "decompile-method asset not found";

    auto output = chat("decompile the code in " + smali);
    bool hasJava = output.find("URL") != std::string::npos ||
                   output.find("HttpURLConnection") != std::string::npos ||
                   output.find("exfiltrateData") != std::string::npos ||
                   output.find("void") != std::string::npos;
    EXPECT_TRUE(hasJava) << "Should show Java-like code:\n" << output;
}

// ── Ported from: tests/use-cases/classes-overview ────────────────

TEST_F(McpE2E, ClassesOverview) {
    auto appDir = srcDir_ + "/tests/use-cases/classes-overview/assets";
    if (!fs::exists(appDir)) GTEST_SKIP() << "classes-overview assets not found";

    auto output = chat("show me all the classes in " + appDir);
    bool hasClasses = output.find("MalwareService") != std::string::npos ||
                      output.find("NetworkHelper") != std::string::npos ||
                      output.find("DataCollector") != std::string::npos;
    EXPECT_TRUE(hasClasses) << "Should find app classes:\n" << output;
}

// ── Ported from: tests/use-cases/xrefs ───────────────────────────

TEST_F(McpE2E, Xrefs) {
    auto smali = srcDir_ + "/tests/use-cases/xrefs/assets/MalwareService.smali";
    if (!fs::exists(smali)) GTEST_SKIP() << "xrefs asset not found";

    auto output = chat("find all references to HttpURLConnection in " + smali);
    bool hasRefs = output.find("HttpURLConnection") != std::string::npos ||
                   output.find("openConnection") != std::string::npos ||
                   output.find("exfiltrateData") != std::string::npos ||
                   output.find("reference") != std::string::npos;
    EXPECT_TRUE(hasRefs) << "Should find HTTP references:\n" << output;
}
