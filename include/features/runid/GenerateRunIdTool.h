#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class GenerateRunIdTool : public Tool {
 public:
    std::string name() const override { return "GENERATE_RUN_ID"; }
    std::string description() const override { return "<query> — generate a unique run ID"; }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

}
