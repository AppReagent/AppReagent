#include "features/scan/DeleteScanTool.h"

#include <cstdio>
#include <functional>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "infra/llm/Embedding.h"
#include "features/scan/ScanLog.h"
#include "features/scan/ScanState.h"

namespace area {

std::optional<ToolResult> DeleteScanTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("DELETE_SCAN:"))
        return std::nullopt;

    std::string runId = action.substr(12);
    while (!runId.empty() && runId[0] == ' ') runId.erase(0, 1);
    while (!runId.empty() && runId.back() == ' ') runId.pop_back();

    if (ctx.confirm) {
        auto r = ctx.confirm("Delete all data for scan " + runId);
        if (r.action == ConfirmResult::DENY)
            return ToolResult{"User denied this action."};
    }

    ScanLog log(db_);
    log.deleteRun(runId);

    EmbeddingStore embStore(db_);
    embStore.deleteRun(runId);

    if (state_) state_->removePaused(runId);

    std::string jsonlPath = "scan-outputs/" + runId + ".jsonl";
    std::remove(jsonlPath.c_str());

    std::string result = "Deleted scan " + runId + " (database records and output file removed).";
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{"OBSERVATION: " + result};
}

}  // namespace area
