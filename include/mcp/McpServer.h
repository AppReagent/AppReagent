#pragma once

#include <string>
#include <vector>

#include "mcp/McpTool.h"
#include <nlohmann/json.hpp>

namespace area::mcp {

class McpServer {
 public:
    McpServer();

    void registerTool(McpTool tool);

    int run();

 private:
    void log(const std::string& msg);
    void send(const nlohmann::json& msg);

    nlohmann::json toolList() const;
    ToolResult dispatch(const std::string& name, const nlohmann::json& args);

    std::vector<McpTool> tools_;
};

}  // namespace area::mcp
