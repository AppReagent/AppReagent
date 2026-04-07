#pragma once

#include "features/chat/ChatService.h"
#include "mcp/McpServer.h"

#include <string>

namespace area::features::chat {

/// Register chat MCP tools (area_chat, area_clear_chat) with the server.
void registerTools(mcp::McpServer& server, const std::string& sockPath);

} // namespace area::features::chat
