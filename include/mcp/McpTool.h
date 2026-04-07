#pragma once

#include <functional>
#include <string>
#include <utility>
#include <nlohmann/json.hpp>

namespace area::mcp {

/// Result from a tool handler: {text, isError}
using ToolResult = std::pair<std::string, bool>;

/// A tool handler receives JSON args and returns a result.
using ToolHandler = std::function<ToolResult(const nlohmann::json& args)>;

/// Registration info for an MCP tool.
struct McpTool {
    std::string name;
    std::string description;
    nlohmann::json inputSchema;
    ToolHandler handler;
};

} // namespace area::mcp
