#pragma once

#include "mcp/McpTool.h"

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace area::mcp {

/// MCP server: JSON-RPC 2.0 over stdio with a tool registry.
/// Features register their tools, then run() handles the protocol loop.
class McpServer {
public:
    McpServer();

    /// Register a tool. Call before run().
    void registerTool(McpTool tool);

    /// Run the JSON-RPC protocol loop (blocking, reads stdin).
    int run();

private:
    void log(const std::string& msg);
    void send(const nlohmann::json& msg);

    nlohmann::json toolList() const;
    ToolResult dispatch(const std::string& name, const nlohmann::json& args);

    std::vector<McpTool> tools_;
};

} // namespace area::mcp
