#include <gtest/gtest.h>
#include "features/testing/McpTestClient.h"
#include "util/file_io.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using area::features::testing::McpTestClient;

/// Test fixture that starts area server + MCP for TUI screenshot tests.
/// Requires a config.json with valid endpoints (uses mock if available).
class TuiScreenshotTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Find the area binary (same directory as test binary, or cwd)
        auto self = area::util::selfExe();
        if (!self.empty()) {
            auto dir = fs::path(self).parent_path();
            binary_ = (dir / "area").string();
        }
        if (binary_.empty() || !fs::exists(binary_)) {
            binary_ = fs::current_path().string() + "/area";
        }
        if (!fs::exists(binary_)) GTEST_SKIP() << "area binary not found";

        // Create temp data dir
        dataDir_ = "/tmp/area-tui-test-" + std::to_string(getpid());
        fs::create_directories(dataDir_);

        // Source dir is where the binary lives
        srcDir_ = fs::path(binary_).parent_path().string();

        // Copy config, rewriting relative cert path to absolute
        std::string srcConfig = "/opt/area/config.json";
        if (!fs::exists(srcConfig)) GTEST_SKIP() << "no config.json";
        {
            std::ifstream in(srcConfig);
            auto cfg = nlohmann::json::parse(in, nullptr, true, true);
            auto cert = cfg.value("postgres_cert", "");
            if (!cert.empty() && cert[0] != '/') {
                // Resolve relative to data dir
                cfg["postgres_cert"] = dataDir_ + "/" + cert;
            }
            std::ofstream out(dataDir_ + "/config.json");
            out << cfg.dump(2);
        }

        // Copy prompts from source dir
        auto prompts = srcDir_ + "/prompts";
        if (fs::exists(prompts)) {
            fs::copy(prompts, dataDir_ + "/prompts",
                     fs::copy_options::recursive);
        }

        // Copy ddl.sql and certs
        for (auto& name : {"ddl.sql", "ca-certificate.crt"}) {
            auto src = srcDir_ + "/" + name;
            if (fs::exists(src))
                fs::copy_file(src, dataDir_ + "/" + name,
                              fs::copy_options::skip_existing);
        }

        // Copy constitution if present
        auto constitution = srcDir_ + "/constitution.md";
        if (fs::exists(constitution)) {
            fs::copy_file(constitution, dataDir_ + "/constitution.md");
        }

        // Start MCP client
        client_ = std::make_unique<McpTestClient>(binary_, dataDir_);
        ASSERT_TRUE(client_->start()) << "Failed to start MCP process";

        // Start server
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
    std::unique_ptr<McpTestClient> client_;
};

TEST_F(TuiScreenshotTest, ScreenShowsWaveBar) {
    auto screen = client_->tuiScreen(1000);
    // Wave bar uses box-drawing chars at the bottom
    EXPECT_NE(screen.find("━"), std::string::npos)
        << "Wave bar not found on screen:\n" << screen;
}

TEST_F(TuiScreenshotTest, RightClickOpensContextMenu) {
    // Right-click somewhere in the middle
    auto screen = client_->tuiClick(12, 40, "right");
    EXPECT_NE(screen.find("View"), std::string::npos)
        << "Context menu not found:\n" << screen;
    EXPECT_NE(screen.find("Header"), std::string::npos)
        << "Header menu item not found:\n" << screen;
}

TEST_F(TuiScreenshotTest, HeaderToggleShowsTokens) {
    // Right-click to open menu
    client_->tuiClick(12, 40, "right");
    // Click on Header to toggle it on
    auto screen = client_->tuiClick(13, 45, "left");
    EXPECT_NE(screen.find("App Reagent"), std::string::npos)
        << "Header title not found:\n" << screen;
    // Should show token count format "X / Y" or "Xk / Yk"
    EXPECT_NE(screen.find(" / "), std::string::npos)
        << "Token count not found in header:\n" << screen;
}

TEST_F(TuiScreenshotTest, TypeTextAppearsInInput) {
    auto screen = client_->tuiType("hello world");
    EXPECT_NE(screen.find("hello world"), std::string::npos)
        << "Typed text not found:\n" << screen;
}

TEST_F(TuiScreenshotTest, EscapeClosesContextMenu) {
    // Open context menu
    client_->tuiClick(12, 40, "right");
    // Press escape to close
    auto screen = client_->tuiKey("escape");
    EXPECT_EQ(screen.find("View"), std::string::npos)
        << "Context menu should be closed:\n" << screen;
}

TEST_F(TuiScreenshotTest, SeparatorShowsSessionName) {
    auto screen = client_->tuiScreen(1000);
    // Separator line should show the default chat session name
    EXPECT_NE(screen.find("default"), std::string::npos)
        << "Session name not found in separator:\n" << screen;
}

TEST_F(TuiScreenshotTest, WaveBarSpansFullWidth) {
    auto screen = client_->tuiScreen(1000);
    // Find the last line containing wave bar chars (┗ or ━)
    auto lastLine = screen.rfind('\n', screen.size() - 2);
    std::string waveLine;
    if (lastLine != std::string::npos) {
        waveLine = screen.substr(lastLine + 1);
    } else {
        waveLine = screen;
    }
    // Wave bar should have multiple ━ chars spanning most of the width
    int barCount = 0;
    size_t pos = 0;
    while ((pos = waveLine.find("━", pos)) != std::string::npos) {
        barCount++;
        pos += 3; // UTF-8 ━ is 3 bytes
    }
    EXPECT_GT(barCount, 30)
        << "Wave bar should span more than 30 chars, got " << barCount
        << " in: " << waveLine;
}
