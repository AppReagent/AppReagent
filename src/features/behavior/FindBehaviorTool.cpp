#include "features/behavior/FindBehaviorTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"

#include <algorithm>
#include <sstream>
#include <unordered_set>

namespace area {

static const std::unordered_set<std::string> STOP_WORDS = {
    "the", "a", "an", "and", "or", "of", "in", "to", "from", "my", "code",
    "where", "it", "that", "this", "is", "are", "was", "were", "do", "does",
    "did", "find", "areas", "show", "list", "me", "all", "any", "for", "with",
    "has", "have", "which", "what", "how", "can", "could", "would", "should",
    "be", "been", "being", "there", "their", "its", "on", "at", "by", "up",
    "about", "into", "through", "during", "before", "after", "above", "below",
    "between", "out", "off", "over", "under", "again", "further", "then",
    "once", "here", "when", "why", "both", "each", "few", "more", "most",
    "other", "some", "such", "no", "not", "only", "own", "same", "so",
    "than", "too", "very", "just", "also"
};

std::vector<std::string> FindBehaviorTool::extractKeywords(const std::string& query) {
    std::vector<std::string> keywords;
    std::istringstream ss(query);
    std::string word;
    while (ss >> word) {
        // Lowercase
        std::string lower;
        for (char c : word) {
            if (std::isalnum(c) || c == '_' || c == '.' || c == '/') {
                lower += std::tolower(c);
            }
        }
        if (lower.empty() || lower.size() < 2) continue;
        if (STOP_WORDS.count(lower)) continue;
        keywords.push_back(lower);
    }
    return keywords;
}

std::optional<ToolResult> FindBehaviorTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("FIND:") != 0)
        return std::nullopt;

    std::string args = action.substr(5);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a behavior description after FIND:"};
    }

    // Parse optional run_id after pipe
    std::string query, runId;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        query = args.substr(0, pipePos);
        runId = args.substr(pipePos + 1);
        while (!query.empty() && query.back() == ' ') query.pop_back();
        while (!runId.empty() && runId[0] == ' ') runId.erase(0, 1);
        while (!runId.empty() && runId.back() == ' ') runId.pop_back();
    } else {
        query = args;
    }

    // If no run_id, find the most recent one
    if (runId.empty() || runId == "latest") {
        auto qr = db_.execute(
            "SELECT DISTINCT run_id FROM method_findings "
            "ORDER BY run_id DESC LIMIT 1");
        if (!qr.ok() || qr.rows.empty()) {
            // Fall back to scan_results
            qr = db_.execute(
                "SELECT DISTINCT run_id FROM scan_results "
                "ORDER BY run_id DESC LIMIT 1");
        }
        if (qr.ok() && !qr.rows.empty() && !qr.rows[0].empty()) {
            runId = qr.rows[0][0];
        } else {
            return ToolResult{
                "OBSERVATION: No scan data found. Run a SCAN first to analyze code, "
                "then use FIND to search for behaviors."};
        }
    }

    ctx.cb({AgentMessage::THINKING, "Searching for: " + query + " (run " + runId + ")"});

    auto keywords = extractKeywords(query);
    if (keywords.empty()) {
        // Fall back to using the whole query as a single search term
        keywords.push_back(query);
    }

    // Build WHERE clause with parameterized LIKE patterns
    std::vector<std::string> params;
    params.push_back(runId);  // $1

    std::ostringstream whereClauses;
    std::ostringstream rankExpr;
    rankExpr << "0";

    for (size_t i = 0; i < keywords.size(); i++) {
        if (i > 0) whereClauses << " OR ";
        // Escape LIKE metacharacters in keyword
        std::string likeKw;
        for (char c : keywords[i]) {
            if (c == '%') likeKw += "%%";
            else if (c == '_') likeKw += "\\_";
            else likeKw += c;
        }
        params.push_back("%" + likeKw + "%");
        std::string p = "$" + std::to_string(params.size());

        whereClauses << "lower(api_calls) LIKE " << p
                     << " OR lower(findings) LIKE " << p
                     << " OR lower(reasoning) LIKE " << p
                     << " OR lower(threat_category) LIKE " << p;

        rankExpr << " + CASE WHEN lower(api_calls || ' ' || findings || ' ' || reasoning) "
                 << "LIKE " << p << " THEN 1 ELSE 0 END";
    }

    std::string sql =
        "SELECT file_path, class_name, method_name, api_calls, findings, "
        "reasoning, relevant, confidence, threat_category, (" + rankExpr.str() + ") AS match_rank "
        "FROM method_findings "
        "WHERE run_id = $1 "
        "AND (" + whereClauses.str() + ") "
        "ORDER BY (" + rankExpr.str() + ") DESC, relevant DESC, confidence DESC "
        "LIMIT 25";

    auto qr = db_.executeParams(sql, params);

    if (!qr.ok()) {
        // Table might not exist yet if no scans have been run since the update
        if (qr.error.find("method_findings") != std::string::npos) {
            return ToolResult{
                "OBSERVATION: The method_findings table doesn't exist yet. "
                "Run a new SCAN to populate per-method behavioral data, "
                "then use FIND to search it."};
        }
        return ToolResult{"OBSERVATION: Search failed: " + qr.error};
    }

    if (qr.rows.empty()) {
        // Try a broader search on scan_results risk_profile
        std::vector<std::string> profileParams;
        profileParams.push_back(runId);  // $1

        std::ostringstream profileWhere;
        for (size_t i = 0; i < keywords.size(); i++) {
            if (i > 0) profileWhere << " OR ";
            std::string likeKw;
            for (char c : keywords[i]) {
                if (c == '%') likeKw += "%%";
                else if (c == '_') likeKw += "\\_";
                else likeKw += c;
            }
            profileParams.push_back("%" + likeKw + "%");
            profileWhere << "lower(risk_profile::text) LIKE $" << profileParams.size();
        }

        auto profileQr = db_.executeParams(
            "SELECT file_path, risk_profile->>'answer' AS answer, "
            "risk_profile->>'overall_relevance' AS relevance, risk_score "
            "FROM scan_results WHERE run_id = $1 "
            "AND (" + profileWhere.str() + ") "
            "ORDER BY risk_score DESC LIMIT 10",
            profileParams);

        if (profileQr.ok() && !profileQr.rows.empty()) {
            std::ostringstream out;
            out << "No per-method findings for this query (run may predate FIND support), "
                << "but found " << profileQr.rows.size()
                << " matching files in scan_results:\n\n";
            for (size_t i = 0; i < profileQr.rows.size(); i++) {
                if (profileQr.rows[i].size() < 4) continue;
                out << (i + 1) << ". " << profileQr.rows[i][0] << "\n"
                    << "   relevance: " << profileQr.rows[i][2]
                    << " (score=" << profileQr.rows[i][3] << ")\n"
                    << "   " << profileQr.rows[i][1].substr(0, 200) << "\n\n";
            }
            out << "For per-method detail, re-scan with the latest version to populate method_findings.";

            std::string formatted = out.str();
            ctx.cb({AgentMessage::RESULT, formatted});
            return ToolResult{"OBSERVATION: " + formatted};
        }

        ctx.cb({AgentMessage::RESULT, "No methods found matching: " + query});
        return ToolResult{
            "OBSERVATION: No methods found matching '" + query + "' in run " + runId + ". "
            "Try different search terms, or use SIMILAR: for semantic search, "
            "or SQL: to query scan_results directly."};
    }

    // Format results
    std::ostringstream out;
    out << qr.rows.size() << " methods found matching '" << query << "' (run " << runId << "):\n\n";

    for (size_t i = 0; i < qr.rows.size(); i++) {
        auto& row = qr.rows[i];
        if (row.size() < 8) continue;
        std::string filePath = row[0];
        std::string className = row[1];
        std::string methodName = row[2];
        std::string apiCalls = row[3];
        std::string findings = row[4];
        std::string reasoning = row[5];
        std::string relevant = row[6] == "t" ? "yes" : "no";
        std::string confidence = row[7];
        std::string threatCategory = row.size() > 8 ? row[8] : "none";
        std::string matchRank = row.size() > 9 ? row[9] : "0";

        out << (i + 1) << ". " << className << "::" << methodName << "\n"
            << "   file: " << filePath << "\n"
            << "   relevant: " << relevant << " (confidence=" << confidence << ")\n";

        if (threatCategory != "none" && !threatCategory.empty()) {
            out << "   threat_category: " << threatCategory << "\n";
        }
        if (!apiCalls.empty()) {
            out << "   api_calls: " << apiCalls.substr(0, 200) << "\n";
        }
        if (!findings.empty()) {
            out << "   findings: " << findings.substr(0, 300) << "\n";
        }
        out << "\n";
    }

    std::string formatted = out.str();
    ctx.cb({AgentMessage::RESULT, formatted});

    return ToolResult{
        "OBSERVATION: " + formatted +
        "Use CALLGRAPH: to trace call chains for these methods, "
        "or SQL: to query scan_results for file-level details."};
}

} // namespace area
