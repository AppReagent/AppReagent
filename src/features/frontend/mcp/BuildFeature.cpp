#include "features/frontend/mcp/BuildFeature.h"

#include <stddef.h>

#include <iostream>
#include <map>
#include <vector>

#include "features/frontend/mcp/McpTool.h"
#include "features/frontend/mcp/McpUtil.h"
#include "nlohmann/detail/json_ref.hpp"
#include "nlohmann/json.hpp"
using json = nlohmann::json;

namespace area::features::build {

static constexpr size_t kBuildOutputTrimLen  = 3000;
static constexpr size_t kBuildSuccessTrimLen = 1000;

void registerTools(mcp::McpServer& server, const std::string& workDir) {
    server.registerTool({
        "area_build",
        "Build (or rebuild) the AppReagent project. Run after editing C++ "
        "source, prompts, or CMakeLists.",
        {{"type", "object"}, {"properties", {
             {"target", {{"type", "string"},
                         {"description",
                          "Make target (default: all). Use 'test' for unit tests."}}}
        }}},
        [workDir](const json& args) -> mcp::ToolResult {
            auto target = args.value("target", "all");
            if (!mcp::isValidName(target)) return {"Invalid make target.", true};
            std::cerr << "[area-mcp] build target=" << target << std::endl;
            auto [out, rc] = mcp::exec(workDir, {"make", target});
            out = mcp::trimOutput(out, kBuildOutputTrimLen);
            if (rc != 0)
                return {"Build failed (exit " + std::to_string(rc) + "):\n" + out, true};
            return {"Build succeeded.\n" + mcp::trimOutput(out, kBuildSuccessTrimLen), false};
        }
    });
}

}  // namespace area::features::build
