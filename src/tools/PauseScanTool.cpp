#include "tools/PauseScanTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"
#include "ScanState.h"

namespace area {

std::optional<ToolResult> PauseScanTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("PAUSE_SCAN:") != 0)
        return std::nullopt;

    std::string runId = action.substr(11);
    while (!runId.empty() && runId[0] == ' ') runId.erase(0, 1);
    while (!runId.empty() && runId.back() == ' ') runId.pop_back();

    std::string result;
    if (!state_) {
        result = "Error: scan state not available.";
    } else {
        std::string jsonlPath = "scan-outputs/" + runId + ".jsonl";
        if (state_->pause(runId, jsonlPath)) {
            result = "Scan " + runId + " is being paused. It will stop after the current file completes.";
        } else {
            result = "No active scan found with run_id '" + runId + "'.";
        }
    }
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{"OBSERVATION: " + result};
}

} // namespace area
