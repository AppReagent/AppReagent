#pragma once

#include "infra/tools/Tool.h"
#include "infra/db/Database.h"

namespace area {

class ReportTool : public Tool {
public:
    explicit ReportTool(Database& db) : db_(db) {}

    std::string name() const override { return "REPORT"; }
    std::string description() const override {
        return "<run_id|latest> [| <output-path>] — generate a structured markdown report "
               "for a scan run. Includes risk scores, findings, method analysis, call graph edges, "
               "and recommendations. Writes to file or returns inline.\n"
               "  Example: REPORT: latest\n"
               "  Example: REPORT: abc123 | /tmp/report.md";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    Database& db_;
};

} // namespace area
