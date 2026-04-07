#include "features/test/TestFeature.h"
#include "mcp/McpUtil.h"
#include "util/file_io.h"

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace area::features::test {

static std::string findBin(const std::string& workDir) {
    auto exe = util::selfExe();
    if (!exe.empty() && fs::exists(exe)) return exe;
    auto wb = workDir + "/area";
    if (fs::exists(wb)) return wb;
    return {};
}

void registerTools(mcp::McpServer& server, const std::string& workDir) {
    server.registerTool({
        "area_test_unit",
        "Run C++ unit tests (Google Test, ~125 tests). Rebuilds if needed.",
        {{"type", "object"}, {"properties", json::object()}},
        [workDir](const json&) -> mcp::ToolResult {
            std::cerr << "[area-mcp] running unit tests" << std::endl;
            auto [out, rc] = mcp::exec(workDir, {"make", "test"});
            out = mcp::trimOutput(out);
            if (out.empty()) out = rc == 0 ? "All tests passed." : "Tests failed.";
            return {out, rc != 0};
        }
    });

    server.registerTool({
        "area_test_e2e",
        "Run end-to-end use-case tests against a real server with real LLM "
        "endpoints. Can take several minutes.",
        {{"type", "object"}, {"properties", {
             {"test_name", {{"type", "string"},
                            {"description",
                             "Specific test or 'all' (default: all). "
                             "E.g. 'scan-benign-file'."}}}
        }}},
        [workDir](const json& args) -> mcp::ToolResult {
            auto testName = args.value("test_name", "all");
            if (!mcp::isValidName(testName)) return {"Invalid test name.", true};
            std::cerr << "[area-mcp] running e2e: " << testName << std::endl;
            auto [out, rc] = mcp::exec(workDir, {"./scripts/test-use-case.sh", testName});
            out = mcp::trimOutput(out);
            if (out.empty()) out = rc == 0 ? "E2E tests passed." : "E2E tests failed.";
            return {out, rc != 0};
        }
    });

    server.registerTool({
        "area_evaluate",
        "Run the scan evaluation pipeline to score current prompt quality, "
        "classification accuracy, and risk calibration.",
        {{"type", "object"}, {"properties", json::object()}},
        [workDir](const json&) -> mcp::ToolResult {
            auto bin = findBin(workDir);
            if (bin.empty()) return {"Binary not found — run area_build first.", true};
            std::cerr << "[area-mcp] running evaluation" << std::endl;
            auto [out, rc] = mcp::exec(workDir, {bin, "evaluate"});
            out = mcp::trimOutput(out);
            if (out.empty()) out = rc == 0 ? "Evaluation complete." : "Evaluation failed.";
            return {out, rc != 0};
        }
    });
}

} // namespace area::features::test
