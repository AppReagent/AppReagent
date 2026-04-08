#include "features/frontend/mcp/ScanFeature.h"

#include <iostream>
#include <map>
#include <vector>

#include "features/frontend/mcp/McpTool.h"
#include "features/frontend/mcp/McpUtil.h"
#include "nlohmann/detail/json_ref.hpp"
#include "nlohmann/json.hpp"
using json = nlohmann::json;

namespace area::features::scan {

void registerTools(mcp::McpServer& server,
                   const std::string& binary,
                   const std::string& dataDir) {
    server.registerTool({
        "area_scan",
        "Run a scan on a file or directory. Executes the full scan pipeline "
        "(triage → deep analysis → synthesis) and returns results. "
        "The server must be running for database storage.",
        {{"type", "object"},
         {"properties", {
             {"path", {{"type", "string"},
                       {"description", "Path to file or directory to scan."}}},
             {"goal", {{"type", "string"},
                       {"description", "Optional analysis goal/question."}}},
             {"run_id", {{"type", "string"},
                         {"description", "Optional run ID for tracking."}}}
         }},
         {"required", json::array({"path"})}},
        [binary, dataDir](const json& args) -> mcp::ToolResult {
            auto path = args.value("path", "");
            if (path.empty()) return {"'path' is required.", true};

            std::vector<std::string> argv = {binary, "scan", path};
            auto goal = args.value("goal", "");
            if (!goal.empty()) {
                argv.push_back("--goal"); argv.push_back(goal);
            }
            auto runId = args.value("run_id", "");
            if (!runId.empty()) {
                argv.push_back("--run-id"); argv.push_back(runId);
            }

            std::cerr << "[area-mcp] scan: " << path << std::endl;
            auto [out, rc] = mcp::exec("", argv);

            out = mcp::trimOutput(out);
            if (rc != 0)
                return {"Scan failed (exit " + std::to_string(rc) + "):\n" + out, true};
            return {out, false};
        }
    });
}

}  // namespace area::features::scan
