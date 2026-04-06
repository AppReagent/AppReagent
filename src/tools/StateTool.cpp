#include "tools/StateTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"
#include "ScanState.h"

namespace area {

std::optional<ToolResult> StateTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("STATE:") != 0 && action.find("STATE") != 0)
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

} // namespace area
