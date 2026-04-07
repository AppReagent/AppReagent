#include "features/analyze/AnalyzeCommand.h"

#include <filesystem>
#include <iostream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "infra/events/EventBus.h"
#include "domains/graph/engine/graph_runner.h"
#include "domains/graph/graphs/analyze_task_graph.h"
#include "domains/graph/graphs/tier_pool.h"
#include "domains/graph/util/json_extract.h"
#include "features/scan/ScanLog.h"

namespace fs = std::filesystem;

namespace area {

AnalyzeCommand::AnalyzeCommand(const Config& config, Database& db)
    : config_(config), db_(db) {
    if (config.embedding.has_value()) {
        try {
            embeddingBackend_ = EmbeddingBackend::create(*config.embedding);
            embeddingStore_ = std::make_unique<EmbeddingStore>(db, embeddingBackend_.get());
        } catch (const std::exception& e) {
            std::cerr << "[analyze] embedding init failed: " << e.what() << std::endl;
        }
    }
}

void AnalyzeCommand::emitLog(const std::string& msg) {
    if (logCb_) logCb_(msg);
    else std::cerr << msg << std::endl;
}

std::string AnalyzeCommand::resolveRunId(const std::string& run_id) {
    if (run_id != "latest") return run_id;

    auto result = db_.execute(
        "SELECT DISTINCT run_id FROM scan_results ORDER BY created_at DESC LIMIT 1");
    if (result.ok() && !result.rows.empty() && !result.rows[0].empty()) {
        return result.rows[0][0];
    }
    return "";
}

std::string AnalyzeCommand::loadScanGoal(const std::string& run_id) {
    // Try to extract goal from llm_calls metadata (the triage prompts contain the goal)
    auto result = db_.executeParams(
        "SELECT prompt FROM llm_calls WHERE run_id = $1 "
        "AND node_name = 'scan_synthesis' LIMIT 1",
        {run_id});
    if (result.ok() && !result.rows.empty() && !result.rows[0].empty()) {
        // Extract goal from the synthesis prompt — it starts with "Scan goal: ..."
        auto& prompt = result.rows[0][0];
        auto goalPos = prompt.find("Scan goal:");
        if (goalPos != std::string::npos) {
            auto lineEnd = prompt.find('\n', goalPos);
            if (lineEnd != std::string::npos) {
                return prompt.substr(goalPos + 11, lineEnd - goalPos - 11);
            }
        }
    }
    return "Analyze this application for security threats and malicious behavior.";
}

AnalysisResult AnalyzeCommand::run(const std::string& run_id) {
    AnalysisResult result;

    std::string resolvedId = resolveRunId(run_id);
    if (resolvedId.empty()) {
        emitLog("No scan results found" + (run_id == "latest" ? "" : " for run " + run_id));
        return result;
    }
    result.run_id = resolvedId;

    // Check that scan results exist
    auto check = db_.executeParams(
        "SELECT COUNT(*) FROM scan_results WHERE run_id = $1 AND risk_score > 0",
        {resolvedId});
    if (!check.ok() || check.rows.empty() || check.rows[0].empty() || check.rows[0][0] == "0") {
        emitLog("No relevant findings in run " + resolvedId + " (nothing to analyze)");
        return result;
    }

    // Check for previous analyses — return cached result unless force re-analyze
    auto prev = db_.executeParams(
        "SELECT threat_level, confidence, risk_score, summary, full_json, findings_count, created_at "
        "FROM analyze_results WHERE run_id = $1 ORDER BY created_at DESC LIMIT 1",
        {resolvedId});
    if (prev.ok() && !prev.rows.empty() && prev.rows[0].size() >= 7 && !forceReanalyze_) {
        result.threat_level = prev.rows[0][0];
        try { result.confidence = std::stoi(prev.rows[0][1]); } catch (...) {}
        try { result.risk_score = std::stoi(prev.rows[0][2]); } catch (...) {}
        result.summary = prev.rows[0][3];
        result.full_json = prev.rows[0][4];
        emitLog("Returning cached analysis for run " + resolvedId +
                " (" + result.threat_level + ", confidence=" +
                std::to_string(result.confidence) + "%, " + prev.rows[0][6] +
                "). Use ANALYZE:reanalyze " + resolvedId + " to force re-analysis.");
        return result;
    }
    if (prev.ok() && !prev.rows.empty() && prev.rows[0].size() >= 2 && forceReanalyze_) {
        emitLog("Re-analyzing run " + resolvedId + " (previous: " +
                prev.rows[0][0] + ", confidence=" + prev.rows[0][1] + "%)");
    }

    std::string scanGoal = loadScanGoal(resolvedId);
    emitLog("Analyzing run " + resolvedId + " (goal: " + scanGoal.substr(0, 80) + "...)");

    // Build tier pool and graph
    graph::TierPool pool(config_.ai_endpoints);
    auto backends = pool.backends();

    std::string promptsDir = "prompts";
    if (auto envDir = std::getenv("AREA_PROMPTS_DIR")) {
        promptsDir = envDir;
    }

    graph::TaskGraph graph = graph::buildAnalyzeTaskGraph(
        backends, db_, embeddingStore_.get(), promptsDir);
    graph::GraphRunner runner;
    runner.setMaxParallel(pool.totalConcurrency());

    runner.onNodeStart([this](const std::string& nodeName, const graph::TaskContext& ctx) {
        if (nodeName == "rag_retrieve" || nodeName == "analyze_finding" || nodeName == "analyze_synthesis") {
            std::string label = nodeName;
            if (ctx.has("method_name")) {
                auto mn = ctx.get("method_name").get<std::string>();
                if (!mn.empty()) label += ": " + mn;
            }
            // Show progress (e.g., "analyze_finding: sendSms [3/12]")
            if (ctx.has("finding_index") && ctx.has("total_findings")) {
                label += " [" + std::to_string(ctx.get("finding_index").get<int>()) +
                         "/" + std::to_string(ctx.get("total_findings").get<int>()) + "]";
            }
            emitLog(label);
        }
    });

    runner.onNodeEnd([this, resolvedId](const std::string& nodeName, const graph::TaskContext& ctx) {
        if (ctx.has("llm_response") && ctx.has("llm_prompt")) {
            auto prompt = ctx.get("llm_prompt").get<std::string>();
            auto response = ctx.get("llm_response").get<std::string>();
            auto promptHash = ScanLog::sha256(prompt);
            std::string filePath = ctx.has("file_path") ? ctx.get("file_path").get<std::string>() : "";
            std::string fileHash = ctx.has("file_hash") ? ctx.get("file_hash").get<std::string>() : "";
            // Log analyze LLM calls to the same llm_calls table
            db_.executeParams(
                "INSERT INTO llm_calls (run_id, file_path, file_hash, node_name, "
                "tier, prompt, prompt_hash, response, latency_ms) "
                "VALUES ($1, $2, $3, $4, 0, $5, $6, $7, 0)",
                {resolvedId, filePath, fileHash, "analyze:" + nodeName, prompt, promptHash, response});
        }
    });

    graph::TaskContext initial;
    initial.set("run_id", resolvedId);
    initial.set("scan_goal", scanGoal);

    graph::TaskContext graphResult;
    try {
        graphResult = runner.run(graph, std::move(initial));
    } catch (const std::exception& e) {
        emitLog("Analysis failed: " + std::string(e.what()));
        return result;
    }

    if (graphResult.discarded) {
        emitLog("Analysis skipped: " + graphResult.discard_reason);
        return result;
    }

    // Extract results
    int findingsCount = graphResult.has("files_analyzed")
        ? graphResult.get("files_analyzed").get<int>() : 0;

    if (graphResult.has("analysis_result")) {
        auto j = graphResult.get("analysis_result");
        result.summary = j.value("summary", "");
        result.threat_level = j.value("threat_level", "unknown");
        result.confidence = j.value("confidence", 0);
        result.risk_score = j.value("risk_score", 0);
        result.full_json = j.dump(2);
        emitLog("Analysis complete: " + result.threat_level +
                " (confidence=" + std::to_string(result.confidence) +
                ", risk=" + std::to_string(result.risk_score) + "/100)");

        // Persist to analyze_results table
        db_.executeParams(
            "INSERT INTO analyze_results (run_id, threat_level, confidence, risk_score, "
            "summary, full_json, findings_count) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7)",
            {resolvedId, result.threat_level,
             std::to_string(result.confidence),
             std::to_string(result.risk_score),
             result.summary, result.full_json,
             std::to_string(findingsCount)});
    } else if (graphResult.has("llm_response")) {
        result.full_json = graphResult.get("llm_response").get<std::string>();
        result.summary = result.full_json;
    }

    return result;
}

} // namespace area
