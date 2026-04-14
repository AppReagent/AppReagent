#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class ShellTool : public Tool {
 public:
    std::string name() const override { return "SHELL"; }
    std::string description() const override {
        return "<command> — run a command directly on the host shell. "
               "Use with care: this is not containerized or sandboxed.";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

}  // namespace area
