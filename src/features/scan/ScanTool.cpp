#include "features/scan/ScanTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"
#include "ScanCommand.h"
#include "ScanLog.h"
#include "ScanState.h"

#include <sstream>

namespace area {

std::optional<ToolResult> ScanTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("SCAN:") != 0)
        return std::nullopt;

    std::string args = action.substr(5);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);

    if (ctx.confirm) {
        auto r = ctx.confirm("SCAN: " + args);
        if (r.action == ConfirmResult::DENY)
            return ToolResult{"User denied this action."};
        if (r.action == ConfirmResult::CUSTOM)
            args = r.customText;
    }

    if (!config_) {
        ctx.cb({AgentMessage::ERROR, "Scan not available (no config)"});
        return ToolResult{"OBSERVATION: Error — scan not available, no config provided."};
    }

    // Parse: path | goal
    std::string path, goal;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        path = args.substr(0, pipePos);
        goal = args.substr(pipePos + 1);
        while (!path.empty() && path.back() == ' ') path.pop_back();
        while (!goal.empty() && goal[0] == ' ') goal.erase(0, 1);
    } else {
        path = args;
    }

    // Check for existing scan results before spending LLM tokens
    bool forceRescan = (goal.find("rescan") != std::string::npos);
    if (!forceRescan && !path.ends_with(".jsonl")) {
        ScanLog log(db_);
        auto existing = log.findRecentScan(path);
        if (existing) {
            std::ostringstream obs;
            obs << "OBSERVATION: Found existing scan for this path.\n"
                << "  run_id: " << existing->run_id << "\n"
                << "  files: " << existing->file_count << "\n"
                << "  flagged: " << existing->flagged_count << "\n"
                << "  max risk score: " << existing->max_risk << "\n"
                << "  scanned at: " << existing->latest << "\n\n"
                << "Use SQL to query these results (run_id = '" << existing->run_id << "') "
                << "instead of re-scanning. If you need a fresh scan, use "
                << "SCAN: " << path << " | rescan";
            ctx.cb({AgentMessage::RESULT, obs.str()});
            return ToolResult{obs.str()};
        }
    }

    ScanCommand scan(*config_, db_);
    scan.setLogCallback([&ctx](const std::string& msg) {
        ctx.cb({AgentMessage::THINKING, msg});
    });
    if (events_) scan.setEventBus(events_);

    ScanSummary summary;
    std::string runId;

    if (path.ends_with(".jsonl")) {
        summary = scan.runFromFile(path);
    } else {
        // Allow "rescan" goal to bypass the existing-scan check
        runId = ScanLog::generateRunId();

        if (state_) {
            auto interruptFlag = state_->start({runId, chatId_, path, goal, 0, 0, std::chrono::steady_clock::now()});
            scan.setInterruptFlag(interruptFlag);
            scan.setProgressCallback([this, runId](int scanned, int total) {
                state_->update(runId, scanned, total);
            });
        }

        summary = scan.run(path, runId, goal);

        if (state_) state_->finish(runId);
    }

    std::ostringstream result;
    if (summary.paused) {
        result << "Scan " << summary.run_id << " PAUSED:\n";
    } else {
        result << "Scan " << summary.run_id << " complete:\n";
    }
    result << "  Total files: " << summary.files_total << "\n"
           << "  Scanned: " << summary.files_scanned << "\n"
           << "  Skipped (resumed): " << summary.files_skipped << "\n"
           << "  Relevant: " << summary.files_relevant << "\n"
           << "  Partially relevant: " << summary.files_partial << "\n"
           << "  Not relevant: " << summary.files_irrelevant << "\n"
           << "  Errors: " << summary.files_error;

    if (!summary.answer.empty()) {
        result << "\n\n--- Analysis ---\n" << summary.answer;
    }

    std::string observation = result.str();
    ctx.cb({AgentMessage::RESULT, observation});

    std::string sensorFeedback = ctx.harness.runSensors("scan", args, observation);

    std::string feedback = "OBSERVATION: " + observation;
    feedback += "\n\nrun_id: " + summary.run_id;
    if (summary.files_relevant > 0 || summary.files_partial > 0) {
        feedback += "\n\nIMPORTANT — Do NOT answer yet. Follow up autonomously:\n"
                    "1. SQL: SELECT class_name, method_name, risk_label, threat_category, confidence "
                    "FROM method_findings WHERE run_id = '" + summary.run_id +
                    "' AND risk_label != 'not_relevant' ORDER BY confidence DESC LIMIT 20\n"
                    "2. DECOMPILE the most suspicious methods to see actual code\n"
                    "3. Use XREFS or CALLGRAPH to trace connections\n"
                    "4. Then give a thorough ANSWER with concrete evidence";
    } else if (summary.answer.empty()) {
        feedback += "\nNo suspicious findings. You may query the database for run_id '" + summary.run_id + "' to confirm.";
    } else {
        feedback += "\nFor per-file details, query the database for run_id '" + summary.run_id + "'.";
    }
    if (!sensorFeedback.empty()) {
        feedback += "\n\nSENSOR FEEDBACK:\n" + sensorFeedback;
    }
    return ToolResult{feedback};
}

} // namespace area
