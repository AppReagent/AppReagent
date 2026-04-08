#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "infra/tools/Tool.h"

namespace area {

class ToolRegistry {
 public:
    void add(std::unique_ptr<Tool> tool);

    std::optional<ToolResult> dispatch(const std::string& action, ToolContext& ctx);

    std::string describeAll() const;

    std::vector<std::string> prefixes() const;

 private:
    std::vector<std::unique_ptr<Tool>> tools_;
};

}  // namespace area
