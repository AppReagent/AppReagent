#pragma once

#include <mutex>
#include <string>
#include <vector>

#include "features/frontend/mcp/McpTool.h"
#include <nlohmann/json.hpp>

namespace area::mcp {

class McpService {
 public:
    void registerTool(McpTool tool);

    nlohmann::json handleRequest(const std::string& method,
                                 const nlohmann::json& params);

    nlohmann::json toolList() const;

    ToolResult dispatch(const std::string& name,
                        const nlohmann::json& args);

 private:
    mutable std::mutex mu_;
    std::vector<McpTool> tools_;
};

}  // namespace area::mcp
