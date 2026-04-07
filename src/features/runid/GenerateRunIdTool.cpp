#include "features/runid/GenerateRunIdTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "ScanLog.h"

namespace area {

std::optional<ToolResult> GenerateRunIdTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("GENERATE_RUN_ID:") != 0 && action.find("GENERATE_RUN_ID") != 0)
        return std::nullopt;

    if (ctx.confirm) {
        auto r = ctx.confirm("Generate a new run ID");
        if (r.action == ConfirmResult::DENY)
            return ToolResult{"User denied this action."};
        if (r.action == ConfirmResult::CUSTOM)
            return ToolResult{r.customText};
    }

    std::string runId = ScanLog::generateRunId();
    ctx.cb({AgentMessage::RESULT, "Generated run ID: " + runId});
    return ToolResult{"OBSERVATION: Generated run ID: " + runId};
}

} // namespace area
