#pragma once

#include "tools/Tool.h"

namespace area {

class TuiTool : public Tool {
public:
    std::string name() const override { return "TUI"; }
    std::string description() const override {
        return "— control TUI panel visibility. "
               "Use 'TUI: show task' to display the task pane during multi-step work, "
               "'TUI: hide task' to dismiss it. Panels: task";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

} // namespace area
