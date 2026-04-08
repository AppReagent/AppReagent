#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"
#include "infra/db/Database.h"

namespace area {

class SqlTool : public Tool {
 public:
    explicit SqlTool(Database& db) : db_(db) {}

    std::string name() const override { return "SQL"; }
    std::string description() const override {
        return "<query> — query the PostgreSQL database. Key tables:\n"
               "  scan_results (run_id, file_path, risk_score, recommendation, risk_profile JSONB)\n"
               "  method_findings (run_id, file_path, class_name, method_name, "
               "api_calls, findings, reasoning, relevant, confidence)\n"
               "  method_calls (run_id, caller_class, caller_method, "
               "callee_class, callee_method, invoke_type)\n"
               "  llm_calls (run_id, file_path, node_name, prompt, response, latency_ms)\n"
               "  Example: SQL: SELECT file_path, risk_score, recommendation "
               "FROM scan_results ORDER BY run_id DESC LIMIT 5";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

 private:
    static std::string extractSql(const std::string& response);
    static std::string stripMarkdownSql(std::string sql);
    static std::string formatResults(const QueryResult& qr);

    Database& db_;
};

}  // namespace area
