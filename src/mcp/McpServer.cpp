#include "mcp/McpServer.h"

#include <iostream>

using json = nlohmann::json;

namespace area::mcp {

McpServer::McpServer() {}

void McpServer::registerTool(McpTool tool) {
    tools_.push_back(std::move(tool));
}

void McpServer::log(const std::string& msg) {
    std::cerr << "[area-mcp] " << msg << std::endl;
}

void McpServer::send(const json& msg) {
    std::cout << msg.dump() << "\n" << std::flush;
}

json McpServer::toolList() const {
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

ToolResult McpServer::dispatch(const std::string& name, const json& args) {
    for (auto& t : tools_) {
        if (t.name == name) return t.handler(args);
    }
    return {"Unknown tool: " + name, true};
}

int McpServer::run() {
    log("ready (" + std::to_string(tools_.size()) + " tools registered)");

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        json req;
        try { req = json::parse(line); }
        catch (...) { continue; }

        auto id     = req.contains("id") ? req["id"] : json();
        auto method = req.value("method", "");
        auto params = req.value("params", json::object());

        if (id.is_null()) continue;

        try {
            if (method == "initialize") {
                send({{"jsonrpc", "2.0"}, {"id", id}, {"result", {
                    {"protocolVersion", "2024-11-05"},
                    {"capabilities", {{"tools", json::object()}}},
                    {"serverInfo", {{"name", "area"}, {"version", "1.0.0"}}}
                }}});

            } else if (method == "tools/list") {
                send({{"jsonrpc", "2.0"}, {"id", id},
                      {"result", {{"tools", toolList()}}}});

            } else if (method == "tools/call") {
                auto name = params.value("name", "");
                auto args = params.value("arguments", json::object());
                auto [text, isErr] = dispatch(name, args);
                send({{"jsonrpc", "2.0"}, {"id", id}, {"result", {
                    {"content", json::array({{{"type", "text"}, {"text", text}}})},
                    {"isError", isErr}
                }}});

            } else {
                send({{"jsonrpc", "2.0"}, {"id", id}, {"error",
                    {{"code", -32601}, {"message", "Unknown method: " + method}}}});
            }
        } catch (const std::exception& e) {
            log("error: " + std::string(e.what()));
            send({{"jsonrpc", "2.0"}, {"id", id}, {"error",
                {{"code", -32603}, {"message", e.what()}}}});
        }
    }

    return 0;
}

} // namespace area::mcp
