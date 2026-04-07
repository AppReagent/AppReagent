#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "infra/tools/Tool.h"

namespace area {

class ToolContext;

class ToolRegistry {
public:
    void add(std::unique_ptr<Tool> tool);

    // Try all tools in registration order. Returns nullopt if none match.
    std::optional<ToolResult> dispatch(const std::string& action, ToolContext& ctx);

    // Generate "Tools:\n- NAME: description\n..." for the system prompt
    std::string describeAll() const;

    // Return all tool prefixes (e.g. "SQL:", "SCAN:") for thought extraction
    std::vector<std::string> prefixes() const;

private:
    std::vector<std::unique_ptr<Tool>> tools_;
};

} // namespace area
