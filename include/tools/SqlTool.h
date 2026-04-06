#pragma once

#include "tools/Tool.h"
#include "Database.h"

namespace area {

class SqlTool : public Tool {
public:
    explicit SqlTool(Database& db) : db_(db) {}

    std::string name() const override { return "SQL"; }
    std::string description() const override { return "<query> — query the PostgreSQL database"; }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    static std::string extractSql(const std::string& response);
    static std::string stripMarkdownSql(std::string sql);
    static std::string formatResults(const QueryResult& qr);

    Database& db_;
};

} // namespace area
