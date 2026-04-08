#include "features/frontend/mcp/McpServer.h"

#include <iostream>
#include <exception>
#include <string>

using json = nlohmann::json;

namespace area::mcp {

McpServer::McpServer() {}

void McpServer::registerTool(McpTool tool) {
    service_.registerTool(std::move(tool));
}

void McpServer::log(const std::string& msg) {
    std::cerr << "[area-mcp] " << msg << std::endl;
}

void McpServer::send(const json& msg) {
    std::cout << msg.dump() << "\n" << std::flush;
}

int McpServer::run() {
    log("ready");

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        json req;
        try {
            req = json::parse(line);
        }
        catch (...) { continue; }

        auto id     = req.contains("id") ? req["id"] : json();
        auto method = req.value("method", "");
        auto params = req.value("params", json::object());

        if (id.is_null()) continue;

        try {
            auto result = service_.handleRequest(method, params);
            if (result.is_null()) {
                send({{"jsonrpc", "2.0"}, {"id", id}, {"error",
                    {{"code", -32601}, {"message", "Unknown method: " + method}}}});
            } else {
                send({{"jsonrpc", "2.0"}, {"id", id}, {"result", result}});
            }
        } catch (const std::exception& e) {
            log("error: " + std::string(e.what()));
            send({{"jsonrpc", "2.0"}, {"id", id}, {"error",
                {{"code", -32603}, {"message", e.what()}}}});
        }
    }

    return 0;
}

}  // namespace area::mcp
