#pragma once

#include <functional>
#include <string>
#include <utility>
#include <nlohmann/json.hpp>

namespace area::mcp {

using ToolResult = std::pair<std::string, bool>;

using ToolHandler = std::function<ToolResult(const nlohmann::json& args)>;

struct McpTool {
    std::string name;
    std::string description;
    nlohmann::json inputSchema;
    ToolHandler handler;
};

}  // namespace area::mcp
