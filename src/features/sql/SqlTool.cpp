#include "features/sql/SqlTool.h"

#include <stddef.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <functional>
#include <vector>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "infra/agent/Harness.h"

namespace area {

std::string SqlTool::stripMarkdownSql(std::string sql) {
    while (!sql.empty() && (sql[0] == ' ' || sql[0] == '\n')) sql.erase(0, 1);
    if (sql.starts_with("```sql")) {
        sql = sql.substr(6);
        if (!sql.empty() && sql[0] == '\n') sql.erase(0, 1);
        auto end = sql.find("```");
        if (end != std::string::npos) sql.resize(end);
    } else if (sql.starts_with("```")) {
        sql = sql.substr(3);
        if (!sql.empty() && sql[0] == '\n') sql.erase(0, 1);
        auto end = sql.find("```");
        if (end != std::string::npos) sql.resize(end);
    }
    return sql;
}

std::string SqlTool::extractSql(const std::string& response) {
    auto sqlPos = response.find("SQL:");
    if (sqlPos != std::string::npos) {
        return stripMarkdownSql(response.substr(sqlPos + 4));
    }

    auto sqlStart = response.find("```sql");
    if (sqlStart != std::string::npos) {
        auto nl = response.find('\n', sqlStart);
        if (nl != std::string::npos) {
            sqlStart = nl + 1;
            auto sqlEnd = response.find("```", sqlStart);
            if (sqlEnd != std::string::npos) {
                return response.substr(sqlStart, sqlEnd - sqlStart);
            }
        }
    }

    auto start = response.find("```");
    if (start != std::string::npos) {
        auto nl = response.find('\n', start);
        if (nl != std::string::npos) {
            start = nl + 1;
            auto end = response.find("```", start);
            if (end != std::string::npos) {
                return response.substr(start, end - start);
            }
        }
    }

    std::string trimmed = response;
    while (!trimmed.empty() && (trimmed[0] == ' ' || trimmed[0] == '\n')) trimmed.erase(0, 1);
    std::string upper;
    for (size_t i = 0; i < std::min(trimmed.size(), static_cast<size_t>(10)); i++) {
        upper += std::toupper(trimmed[i]);
    }
    if (upper.starts_with("SELECT") || upper.starts_with("INSERT") ||
        upper.starts_with("UPDATE") || upper.starts_with("DELETE") ||
        upper.starts_with("WITH") || upper.starts_with("EXPLAIN")) {
        return trimmed;
    }

    return "";
}

std::string SqlTool::formatResults(const QueryResult& qr) {
    if (!qr.ok()) return "ERROR: " + qr.error;

    std::ostringstream out;

    std::vector<size_t> widths;
    for (auto& col : qr.columns) widths.push_back(col.size());
    for (auto& row : qr.rows) {
        for (size_t i = 0; i < row.size() && i < widths.size(); i++) {
            widths[i] = std::max(widths[i], row[i].size());
        }
    }

    constexpr size_t MAX_COL_WIDTH = 200;
    for (auto& w : widths) w = std::min(w, MAX_COL_WIDTH);

    for (size_t i = 0; i < qr.columns.size(); i++) {
        if (i > 0) out << " | ";
        std::string col = qr.columns[i].substr(0, MAX_COL_WIDTH);
        out << col;
        if (col.size() < widths[i])
            out << std::string(widths[i] - col.size(), ' ');
    }
    out << "\n";

    for (size_t i = 0; i < widths.size(); i++) {
        if (i > 0) out << "-+-";
        out << std::string(widths[i], '-');
    }
    out << "\n";

    size_t maxRows = std::min(qr.rows.size(), static_cast<size_t>(50));
    for (size_t r = 0; r < maxRows; r++) {
        for (size_t i = 0; i < qr.rows[r].size() && i < widths.size(); i++) {
            if (i > 0) out << " | ";
            std::string val = qr.rows[r][i];
            if (val.size() > MAX_COL_WIDTH) {
                val.resize(MAX_COL_WIDTH - 3);
                val += "...";
            }
            out << val;
            if (val.size() < widths[i])
                out << std::string(widths[i] - val.size(), ' ');
        }
        out << "\n";
    }
    if (qr.rows.size() > maxRows) {
        out << "... (" << qr.rows.size() - maxRows << " more rows)\n";
    }

    return out.str();
}

std::optional<ToolResult> SqlTool::tryExecute(const std::string& action, ToolContext& ctx) {
    std::string sql = extractSql(action);
    if (sql.empty()) return std::nullopt;

    while (!sql.empty() && (sql[0] == ' ' || sql[0] == '\n')) sql.erase(0, 1);
    while (!sql.empty() && (sql.back() == ' ' || sql.back() == '\n')) sql.pop_back();

    std::string preSqlFeedback = ctx.harness.runSensors("sql", sql, "");
    if (!preSqlFeedback.empty() && preSqlFeedback.find("BLOCKED") != std::string::npos) {
        ctx.cb({AgentMessage::ERROR, preSqlFeedback});
        return ToolResult{"SENSOR FEEDBACK: " + preSqlFeedback};
    }

    ctx.cb({AgentMessage::SQL, sql});

    if (ctx.confirm) {
        auto r = ctx.confirm("SQL: " + sql);
        if (r.action == ConfirmResult::DENY)
            return ToolResult{"User denied this SQL query."};
        if (r.action == ConfirmResult::CUSTOM)
            return ToolResult{r.customText};
    }

    QueryResult qr = db_.execute(sql);

    if (!qr.ok()) {
        ctx.cb({AgentMessage::ERROR, qr.error});

        std::string sensorFeedback = ctx.harness.runSensors("sql", sql, "ERROR: " + qr.error);

        std::ostringstream feedback;
        feedback << "OBSERVATION: Query failed with error:\n" << qr.error;
        if (!sensorFeedback.empty()) {
            feedback << "\n\nSENSOR FEEDBACK:\n" << sensorFeedback;
        }
        feedback << "\n\nFix the query and try again.";
        return ToolResult{feedback.str()};
    }

    std::string formatted = formatResults(qr);
    std::ostringstream resultMsg;
    resultMsg << qr.rows.size() << " rows in " << std::fixed
              << std::setprecision(1) << qr.duration_ms << "ms";
    ctx.cb({AgentMessage::RESULT, resultMsg.str() + "\n" + formatted});

    std::ostringstream feedback;
    feedback << "OBSERVATION: Query returned " << qr.rows.size() << " rows ("
             << std::fixed << std::setprecision(1) << qr.duration_ms << "ms):\n"
             << formatted
             << "\nBased on this observation, continue reasoning. "
             << "Use ANSWER: when you have enough information, or another tool if you need more data.";
    return ToolResult{feedback.str()};
}

}  // namespace area
