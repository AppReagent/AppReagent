#pragma once

#include "infra/tools/Tool.h"

namespace area {

class Database;
class ScanState;

class DeleteScanTool : public Tool {
public:
    DeleteScanTool(Database& db, ScanState* state) : db_(db), state_(state) {}

    std::string name() const override { return "DELETE_SCAN"; }
    std::string description() const override { return "<run_id> — delete all data for a scan (database records + output file)."; }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    Database& db_;
    ScanState* state_;
};

} // namespace area
