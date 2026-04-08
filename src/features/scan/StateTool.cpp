#include "features/scan/StateTool.h"

#include <functional>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "features/scan/ScanState.h"

namespace area {

std::optional<ToolResult> StateTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("STATE:") && !action.starts_with("STATE"))
        return std::nullopt;

    std::string state;
    if (state_) {
        state = state_->summary();
    } else {
        state = "No active scans.";
    }
    ctx.cb({AgentMessage::RESULT, state});
    return ToolResult{"OBSERVATION: " + state};
}

}  // namespace area
