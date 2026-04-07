#include "features/report/ReportTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace area {

static std::string resolveRunId(Database& db, const std::string& input) {
    if (input.empty() || input == "latest") {
        auto qr = db.execute(
            "SELECT DISTINCT run_id FROM scan_results ORDER BY run_id DESC LIMIT 1");
        if (qr.ok() && !qr.rows.empty() && !qr.rows[0].empty()) return qr.rows[0][0];
        return "";
    }
    return input;
}

static std::string timestamp() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
    return buf;
}

std::optional<ToolResult> ReportTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("REPORT:") != 0)
        return std::nullopt;

    std::string args = action.substr(7);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) args = "latest";

    // Parse: run_id | output_path
    std::string runIdRaw, outputPath;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        runIdRaw = args.substr(0, pipePos);
        outputPath = args.substr(pipePos + 1);
        while (!runIdRaw.empty() && runIdRaw.back() == ' ') runIdRaw.pop_back();
        while (!outputPath.empty() && outputPath[0] == ' ') outputPath.erase(0, 1);
        while (!outputPath.empty() && outputPath.back() == ' ') outputPath.pop_back();
    } else {
        runIdRaw = args;
    }

    std::string runId = resolveRunId(db_, runIdRaw);
    if (runId.empty()) {
        return ToolResult{"OBSERVATION: No scan data found. Run a SCAN first."};
    }

    ctx.cb({AgentMessage::THINKING, "Generating report for run " + runId + "..."});

    std::ostringstream report;

    // Header
    report << "# Malware Analysis Report\n\n"
           << "| Field | Value |\n"
           << "|-------|-------|\n"
           << "| Run ID | `" << runId << "` |\n"
           << "| Generated | " << timestamp() << " |\n"
           << "| Tool | AppReagent |\n\n";

    // Executive Summary — scan_results
    {
        auto qr = db_.executeParams(
            "SELECT file_path, risk_score, "
            "risk_profile->>'overall_relevance' AS relevance, "
            "risk_profile->>'answer' AS answer, "
            "risk_profile->>'recommendation' AS recommendation "
            "FROM scan_results WHERE run_id = $1 "
            "ORDER BY risk_score DESC",
            {runId});

        if (qr.ok() && !qr.rows.empty()) {
            // Compute aggregate stats
            int maxScore = 0, totalFiles = (int)qr.rows.size();
            int relevant = 0, partial = 0, irrelevant = 0;
            for (auto& row : qr.rows) {
                if (row.size() < 5) continue;
                int score = 0;
                try { score = std::stoi(row[1]); } catch (...) {}
                if (score > maxScore) maxScore = score;
                if (row[2] == "relevant") relevant++;
                else if (row[2] == "partially_relevant") partial++;
                else irrelevant++;
            }

            std::string severity = "LOW";
            if (maxScore >= 70) severity = "HIGH";
            else if (maxScore >= 40) severity = "MEDIUM";

            report << "## Executive Summary\n\n"
                   << "**Overall Severity: " << severity << "** (max risk score: " << maxScore << "/100)\n\n"
                   << "| Metric | Count |\n"
                   << "|--------|-------|\n"
                   << "| Files analyzed | " << totalFiles << " |\n"
                   << "| Relevant (malicious) | " << relevant << " |\n"
                   << "| Partially relevant | " << partial << " |\n"
                   << "| Not relevant (benign) | " << irrelevant << " |\n\n";

            // Per-file details
            report << "## File Analysis\n\n";
            for (auto& row : qr.rows) {
                if (row.size() < 5) continue;
                std::string emoji;
                if (row[2] == "relevant") emoji = "[MALICIOUS]";
                else if (row[2] == "partially_relevant") emoji = "[SUSPICIOUS]";
                else emoji = "[BENIGN]";

                report << "### " << emoji << " " << fs::path(row[0]).filename().string() << "\n\n"
                       << "- **Path:** `" << row[0] << "`\n"
                       << "- **Risk Score:** " << row[1] << "/100\n"
                       << "- **Classification:** " << row[2] << "\n";

                if (!row[3].empty()) {
                    report << "- **Analysis:** " << row[3] << "\n";
                }
                if (!row[4].empty()) {
                    report << "- **Recommendation:** " << row[4] << "\n";
                }
                report << "\n";
            }
        } else {
            report << "## Summary\n\nNo scan results found for this run.\n\n";
        }
    }

    // Method-level findings
    {
        auto qr = db_.executeParams(
            "SELECT class_name, method_name, file_path, api_calls, findings, reasoning, "
            "relevant, confidence "
            "FROM method_findings WHERE run_id = $1 "
            "AND relevant = true "
            "ORDER BY confidence DESC LIMIT 50",
            {runId});

        if (qr.ok() && !qr.rows.empty()) {
            report << "## Relevant Methods (" << qr.rows.size() << ")\n\n"
                   << "| Class | Method | APIs | Confidence |\n"
                   << "|-------|--------|------|------------|\n";

            for (auto& row : qr.rows) {
                if (row.size() < 8) continue;
                std::string apis = row[3].size() > 60 ? row[3].substr(0, 60) + "..." : row[3];
                report << "| " << row[0] << " | " << row[1]
                       << " | " << apis << " | " << row[7] << " |\n";
            }
            report << "\n";

            // Detailed findings for top methods
            report << "### Detailed Findings\n\n";
            int shown = 0;
            for (auto& row : qr.rows) {
                if (shown++ >= 10) break;
                if (row.size() < 6) continue;
                report << "**" << row[0] << "::" << row[1] << "**\n"
                       << "- File: `" << row[2] << "`\n";
                if (!row[3].empty()) report << "- APIs: " << row[3] << "\n";
                if (!row[4].empty()) report << "- Findings: " << row[4] << "\n";
                if (!row[5].empty()) report << "- Reasoning: " << row[5] << "\n";
                report << "\n";
            }
        }
    }

    // Call graph edges for relevant methods
    {
        auto qr = db_.executeParams(
            "SELECT DISTINCT mc.caller_class, mc.caller_method, "
            "mc.callee_class, mc.callee_method, mc.invoke_type "
            "FROM method_calls mc "
            "INNER JOIN method_findings mf ON mc.run_id = mf.run_id "
            "  AND (mc.caller_class = mf.class_name OR mc.callee_class = mf.class_name) "
            "WHERE mc.run_id = $1 "
            "AND mf.relevant = true "
            "ORDER BY mc.caller_class LIMIT 50",
            {runId});

        if (qr.ok() && !qr.rows.empty()) {
            report << "## Call Graph (relevant methods)\n\n"
                   << "```\n";
            for (auto& row : qr.rows) {
                if (row.size() < 5) continue;
                report << row[0] << "::" << row[1]
                       << " --[" << row[4] << "]--> "
                       << row[2] << "::" << row[3] << "\n";
            }
            report << "```\n\n";
        }
    }

    // LLM call stats
    {
        auto qr = db_.executeParams(
            "SELECT node_name, tier, COUNT(*), "
            "ROUND(AVG(latency_ms)::numeric, 0), "
            "ROUND(SUM(latency_ms)::numeric / 1000, 1) "
            "FROM llm_calls WHERE run_id = $1 "
            "GROUP BY node_name, tier ORDER BY tier, node_name",
            {runId});

        if (qr.ok() && !qr.rows.empty()) {
            report << "## Analysis Statistics\n\n"
                   << "| Node | Tier | Calls | Avg Latency (ms) | Total (s) |\n"
                   << "|------|------|-------|-------------------|----------|\n";
            for (auto& row : qr.rows) {
                if (row.size() < 5) continue;
                report << "| " << row[0] << " | " << row[1]
                       << " | " << row[2] << " | " << row[3]
                       << " | " << row[4] << " |\n";
            }
            report << "\n";
        }
    }

    report << "---\n*Generated by AppReagent*\n";

    std::string reportStr = report.str();

    // Write to file if path given
    if (!outputPath.empty()) {
        fs::create_directories(fs::path(outputPath).parent_path());
        std::ofstream f(outputPath);
        if (f.is_open()) {
            f << reportStr;
            f.close();
            std::string msg = "Report written to " + outputPath + " (" +
                std::to_string(reportStr.size()) + " bytes)";
            ctx.cb({AgentMessage::RESULT, msg});
            return ToolResult{"OBSERVATION: " + msg};
        }
        return ToolResult{"OBSERVATION: Error — could not write to " + outputPath};
    }

    // Return inline (truncated if very long)
    if (reportStr.size() > 6000) {
        std::string truncated = reportStr.substr(0, 6000) +
            "\n\n... (truncated — use REPORT: " + runId +
            " | /path/to/report.md to save full report)";
        ctx.cb({AgentMessage::RESULT, truncated});
        return ToolResult{"OBSERVATION: " + truncated};
    }

    ctx.cb({AgentMessage::RESULT, reportStr});
    return ToolResult{"OBSERVATION: " + reportStr};
}

} // namespace area
