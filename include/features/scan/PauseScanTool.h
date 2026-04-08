#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class ScanState;

class PauseScanTool : public Tool {
 public:
    explicit PauseScanTool(ScanState* state) : state_(state) {}

    std::string name() const override { return "PAUSE_SCAN"; }
    std::string description() const override {
        return "<run_id> — pause a running scan. It stops after the current file.";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

 private:
    ScanState* state_;
};

}  // namespace area
