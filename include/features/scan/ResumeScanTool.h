#pragma once

#include <string>
#include "infra/tools/Tool.h"

namespace area {

class Config;
class Database;
class ScanState;

class ResumeScanTool : public Tool {
public:
    ResumeScanTool(const Config* config, Database& db, ScanState* state,
                   const std::string& chatId)
        : config_(config), db_(db), state_(state), chatId_(chatId) {}

    std::string name() const override { return "RESUME_SCAN"; }
    std::string description() const override { return "<run_id> — resume a paused scan from where it left off."; }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    const Config* config_;
    Database& db_;
    ScanState* state_;
    std::string chatId_;
};

} // namespace area
