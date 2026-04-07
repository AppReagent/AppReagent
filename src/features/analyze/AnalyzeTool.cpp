#include "features/analyze/AnalyzeTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "AnalyzeCommand.h"

#include <sstream>

namespace area {

std::optional<ToolResult> AnalyzeTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("ANALYZE:") != 0)
        return std::nullopt;

    std::string args = action.substr(8);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) args = "latest";

    // Support "reanalyze <run_id>" to force re-analysis
    bool forceReanalyze = false;
    if (args.find("reanalyze") == 0) {
        forceReanalyze = true;
        args = args.substr(9);
        while (!args.empty() && args[0] == ' ') args.erase(0, 1);
        if (args.empty()) args = "latest";
    }

    if (!config_) {
        ctx.cb({AgentMessage::ERROR, "Analyze not available (no config)"});
        return ToolResult{"OBSERVATION: Error — analyze not available, no config provided."};
    }

    ctx.cb({AgentMessage::THINKING, "Starting RAG-augmented analysis for run: " + args});

    AnalyzeCommand analyze(*config_, db_);
    analyze.setForceReanalyze(forceReanalyze);
    analyze.setLogCallback([&ctx](const std::string& msg) {
        ctx.cb({AgentMessage::THINKING, msg});
    });
    if (events_) analyze.setEventBus(events_);

    auto result = analyze.run(args);

    std::ostringstream out;
    if (result.summary.empty() && result.full_json.empty()) {
        out << "Analysis produced no results for run " << args << ".";
    } else {
        out << "Analysis of run " << result.run_id << ":\n";
        out << "  Threat level: " << result.threat_level << "\n";
        out << "  Confidence: " << result.confidence << "%\n";
        out << "  Risk score: " << result.risk_score << "/100\n";
        if (!result.summary.empty()) {
            out << "\n--- Summary ---\n" << result.summary;
        }
        if (!result.full_json.empty()) {
            out << "\n\n--- Full Analysis ---\n" << result.full_json;
        }
    }

    std::string observation = out.str();
    ctx.cb({AgentMessage::RESULT, observation});

    return ToolResult{"OBSERVATION: " + observation};
}

} // namespace area
