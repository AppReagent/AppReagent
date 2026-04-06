#pragma once

#include "tools/Tool.h"

namespace area {

class ScanState;

class StateTool : public Tool {
public:
    explicit StateTool(ScanState* state) : state_(state) {}

    std::string name() const override { return "STATE"; }
    std::string description() const override { return "— check active and paused scans across all sessions"; }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    ScanState* state_;
};

} // namespace area
