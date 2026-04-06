#include "tools/CallGraphTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"

#include <sstream>

namespace area {

static std::string escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    return out;
}

static std::string resolveRunId(Database& db, const std::string& input) {
    if (input == "latest") {
        auto qr = db.execute(
            "SELECT DISTINCT run_id FROM method_calls ORDER BY run_id DESC LIMIT 1");
        if (qr.ok() && !qr.rows.empty()) return qr.rows[0][0];
        return "";
    }
    return input;
}

std::optional<ToolResult> CallGraphTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("CALLGRAPH:") != 0)
        return std::nullopt;

    std::string args = action.substr(10);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);

    // Parse: <run_id> <class>::<method> [callers|callees]
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

    // Split target on "::" to get class and method
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
    if (direction == "callers") {
        // Who calls this method?
        sql = "SELECT caller_class, caller_method, invoke_type, file_path "
              "FROM method_calls WHERE run_id = '" + escape(runId) + "'";
        if (!targetClass.empty())
            sql += " AND callee_class = '" + escape(targetClass) + "'";
        sql += " AND callee_method = '" + escape(targetMethod) + "'"
               " ORDER BY caller_class, caller_method";
    } else {
        // What does this method call?
        sql = "SELECT callee_class, callee_method, invoke_type, file_path "
              "FROM method_calls WHERE run_id = '" + escape(runId) + "'";
        if (!targetClass.empty())
            sql += " AND caller_class = '" + escape(targetClass) + "'";
        sql += " AND caller_method = '" + escape(targetMethod) + "'"
               " ORDER BY callee_class, callee_method";
    }

    auto qr = db_.execute(sql);
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
        out << "  " << row[0] << "::" << row[1]
            << " [" << row[2] << "]"
            << " (file: " << row[3] << ")\n";
    }
    out << "\nTotal: " << qr.rows.size() << " edges\n";

    std::string formatted = out.str();
    ctx.cb({AgentMessage::RESULT, formatted});

    return ToolResult{"OBSERVATION: " + formatted};
}

} // namespace area
