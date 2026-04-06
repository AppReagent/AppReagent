#pragma once

#include "tools/Tool.h"
#include "Database.h"

namespace area {

class FindBehaviorTool : public Tool {
public:
    explicit FindBehaviorTool(Database& db) : db_(db) {}

    std::string name() const override { return "FIND"; }
    std::string description() const override {
        return "<behavior description> [| run_id] — search scanned code for specific "
               "behaviors, API usage, or patterns. Searches per-method findings from "
               "previous scans.\n"
               "  Example: FIND: reads from the filesystem\n"
               "  Example: FIND: sends SMS messages\n"
               "  Example: FIND: network connections | abc123XYZ_w\n"
               "  Example: FIND: uses reflection or dynamic class loading";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    static std::vector<std::string> extractKeywords(const std::string& query);
    Database& db_;
};

} // namespace area
