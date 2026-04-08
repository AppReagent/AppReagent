#include "features/scan/ResumeScanTool.h"

#include <bits/chrono.h>
#include <sstream>
#include <functional>
#include <memory>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "features/scan/ScanCommand.h"
#include "features/scan/ScanOutputFile.h"
#include "features/scan/ScanState.h"

namespace area {

std::optional<ToolResult> ResumeScanTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("RESUME_SCAN:"))
        return std::nullopt;

    std::string runId = action.substr(12);
    while (!runId.empty() && runId[0] == ' ') runId.erase(0, 1);
    while (!runId.empty() && runId.back() == ' ') runId.pop_back();

    if (!state_ || !config_) {
        ctx.cb({AgentMessage::ERROR, "Scan resume not available."});
        return ToolResult{"OBSERVATION: Error — scan state or config not available."};
    }

    PausedScan paused;
    if (!state_->getPaused(runId, paused)) {
        std::string jsonlPath = "scan-outputs/" + runId + ".jsonl";
        try {
            auto loaded = ScanOutputFile::load(jsonlPath);
            paused = {loaded.run_id, loaded.target_path, loaded.goal, 0, 0, jsonlPath};
        } catch (...) {
            ctx.cb({AgentMessage::ERROR, "No paused scan found with run_id '" + runId + "'."});
            return ToolResult{"OBSERVATION: No paused scan found with run_id '" + runId + "'."};
        }
    }

    state_->removePaused(runId);

    ScanCommand scan(*config_, db_);
    scan.setLogCallback([&ctx](const std::string& msg) {
        ctx.cb({AgentMessage::THINKING, msg});
    });

    auto interruptFlag = state_->start(
        {runId, chatId_, paused.path, paused.goal, 0, 0, std::chrono::steady_clock::now()});
    scan.setInterruptFlag(interruptFlag);
    scan.setProgressCallback([this, runId](int scanned, int total) {
        state_->update(runId, scanned, total);
    });

    ctx.cb({AgentMessage::THINKING, "Resuming scan " + runId + " on " + paused.path});
    auto summary = scan.run(paused.path, runId, paused.goal);
    state_->finish(runId);

    std::ostringstream resultStr;
    if (summary.paused) {
        resultStr << "Scan " << runId << " paused again.\n";
    } else {
        resultStr << "Scan " << runId << " resumed and completed.\n";
    }
    resultStr << "  Scanned: " << summary.files_scanned << "\n"
              << "  Skipped (already done): " << summary.files_skipped << "\n"
              << "  Relevant: " << summary.files_relevant << "\n"
              << "  Errors: " << summary.files_error;

    std::string observation = resultStr.str();
    ctx.cb({AgentMessage::RESULT, observation});
    return ToolResult{"OBSERVATION: " + observation +
        "\nYou can query the database for run_id '" + runId + "'."};
}

}  // namespace area
