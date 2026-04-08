#include "features/frontend/mcp/McpService.h"

#include <utility>

using json = nlohmann::json;

namespace area::mcp {

void McpService::registerTool(McpTool tool) {
    std::lock_guard lk(mu_);
    tools_.push_back(std::move(tool));
}

json McpService::toolList() const {
    std::lock_guard lk(mu_);
    json list = json::array();
    for (auto& t : tools_) {
        list.push_back({
            {"name", t.name},
            {"description", t.description},
            {"inputSchema", t.inputSchema}
        });
    }
    return list;
}

ToolResult McpService::dispatch(const std::string& name,
                                const nlohmann::json& args) {
    std::lock_guard lk(mu_);
    for (auto& t : tools_) {
        if (t.name == name) return t.handler(args);
    }
    return {"Unknown tool: " + name, true};
}

json McpService::handleRequest(const std::string& method,
                               const json& params) {
    if (method == "initialize") {
        return {
            {"protocolVersion", "2024-11-05"},
            {"capabilities", {{"tools", json::object()}}},
            {"serverInfo", {{"name", "area"}, {"version", "1.0.0"}}}
        };
    }

    if (method == "tools/list") {
        return {{"tools", toolList()}};
    }

    if (method == "tools/call") {
        auto name = params.value("name", "");
        auto args = params.value("arguments", json::object());
        auto [text, isErr] = dispatch(name, args);
        return {
            {"content", json::array({{{"type", "text"}, {"text", text}}})},
            {"isError", isErr}
        };
    }

    return json();
}

}  // namespace area::mcp
