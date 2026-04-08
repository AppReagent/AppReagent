#include "features/callgraph/CallGraphTool.h"

#include <sstream>
#include <functional>
#include <vector>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"

namespace area {
static std::string resolveRunId(Database& db, const std::string& input) {
    if (input == "latest") {
        auto qr = db.execute(
            "SELECT DISTINCT run_id FROM method_calls ORDER BY run_id DESC LIMIT 1");
        if (qr.ok() && !qr.rows.empty() && !qr.rows[0].empty()) return qr.rows[0][0];
        return "";
    }
    return input;
}

std::optional<ToolResult> CallGraphTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("CALLGRAPH:"))
        return std::nullopt;

    std::string args = action.substr(10);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);

    std::istringstream ss(args);
    std::string runIdRaw, target, direction;
    ss >> runIdRaw >> target >> direction;

    if (runIdRaw.empty() || target.empty()) {
        return ToolResult{"OBSERVATION: Error — usage: CALLGRAPH: <run_id|latest> <class>::<method> [callers|callees]"};
    }

    std::string runId = resolveRunId(db_, runIdRaw);
    if (runId.empty()) {
        return ToolResult{"OBSERVATION: No call graph data found. Run a scan first."};
    }

    if (direction.empty()) direction = "callees";

    auto sepPos = target.find("::");
    std::string targetClass, targetMethod;
    if (sepPos != std::string::npos) {
        targetClass = target.substr(0, sepPos);
        targetMethod = target.substr(sepPos + 2);
    } else {
        targetMethod = target;
    }

    ctx.cb({AgentMessage::THINKING, "Querying call graph (" + direction + ") for " + target});

    std::string sql;
    std::vector<std::string> params;
    params.push_back(runId);

    if (direction == "callers") {
        sql = "SELECT caller_class, caller_method, invoke_type, file_path "
              "FROM method_calls WHERE run_id = $1";
        if (!targetClass.empty()) {
            params.push_back(targetClass);
            sql += " AND callee_class = $" + std::to_string(params.size());
        }
        params.push_back(targetMethod);
        sql += " AND callee_method = $" + std::to_string(params.size());
        sql += " ORDER BY caller_class, caller_method";
    } else {
        sql = "SELECT callee_class, callee_method, invoke_type, file_path "
              "FROM method_calls WHERE run_id = $1";
        if (!targetClass.empty()) {
            params.push_back(targetClass);
            sql += " AND caller_class = $" + std::to_string(params.size());
        }
        params.push_back(targetMethod);
        sql += " AND caller_method = $" + std::to_string(params.size());
        sql += " ORDER BY callee_class, callee_method";
    }

    auto qr = db_.executeParams(sql, params);
    if (!qr.ok()) {
        return ToolResult{"OBSERVATION: Query failed: " + qr.error};
    }

    if (qr.rows.empty()) {
        return ToolResult{"OBSERVATION: No " + direction + " found for " + target +
                          " in run " + runId + "."};
    }

    std::ostringstream out;
    out << direction << " of " << target << " (run " << runId << "):\n\n";

    for (auto& row : qr.rows) {
        if (row.size() < 4) continue;
        out << "  " << row[0] << "::" << row[1]
            << " [" << row[2] << "]"
            << " (file: " << row[3] << ")\n";
    }
    out << "\nTotal: " << qr.rows.size() << " edges\n";

    std::string formatted = out.str();
    ctx.cb({AgentMessage::RESULT, formatted});

    return ToolResult{"OBSERVATION: " + formatted};
}
}  // namespace area
