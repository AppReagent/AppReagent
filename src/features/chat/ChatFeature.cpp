#include "features/chat/ChatFeature.h"

#include <iostream>

using json = nlohmann::json;

namespace area::features::chat {

void registerTools(mcp::McpServer& server, const std::string& sockPath) {
    auto service = std::make_shared<ChatService>(sockPath);

    server.registerTool({
        "area_chat",
        "Send a message to the AppReagent agent. The agent can run scans "
        "(SCAN), execute SQL queries, analyze files, generate reports, and "
        "more. The server must be running (area_server_start).",
        {{"type", "object"},
         {"properties", {
             {"message", {{"type", "string"},
                          {"description",
                           "Message for the agent. Examples: 'scan "
                           "/path/to/file.smali', 'show last 5 scan results', "
                           "'SELECT * FROM scan_results LIMIT 5'"}}},
             {"chat_id", {{"type", "string"},
                          {"description",
                           "Chat session ID (default: claude-code). "
                           "Different IDs = separate conversations."}}}
         }},
         {"required", json::array({"message"})}},
        [service, sockPath](const json& args) -> mcp::ToolResult {
            auto message = args.value("message", "");
            auto chatId  = args.value("chat_id", "claude-code");
            std::cerr << "[area-mcp] chat[" << chatId << "]: "
                      << message.substr(0, 80) << std::endl;
            auto resp = service->send(message, chatId);
            return {resp.text, resp.error};
        }
    });

    server.registerTool({
        "area_clear_chat",
        "Clear conversation history for a chat session. Useful for starting "
        "a fresh analysis.",
        {{"type", "object"}, {"properties", {
             {"chat_id", {{"type", "string"},
                          {"description",
                           "Chat session ID (default: claude-code)."}}}
        }}},
        [service](const json& args) -> mcp::ToolResult {
            auto chatId = args.value("chat_id", "claude-code");
            auto resp = service->clear(chatId);
            return {resp.text, resp.error};
        }
    });
}

} // namespace area::features::chat
