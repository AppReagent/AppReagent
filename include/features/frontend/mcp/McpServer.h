#pragma once

#include <string>

#include "features/frontend/mcp/McpService.h"
#include "features/frontend/mcp/McpTool.h"
#include <nlohmann/json.hpp>

namespace area::mcp {

class McpServer {
 public:
    McpServer();

    void registerTool(McpTool tool);

    McpService& service() { return service_; }

    int run();

 private:
    void log(const std::string& msg);
    void send(const nlohmann::json& msg);

    McpService service_;
};

}  // namespace area::mcp
