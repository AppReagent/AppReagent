#pragma once

#include "mcp/McpServer.h"

#include <string>

namespace area::features::tui {

/// Register TUI MCP tools (area_tui_screen, _click, _type, _key, _resize).
void registerTools(mcp::McpServer& server,
                   const std::string& binary,
                   const std::string& sockPath);

} // namespace area::features::tui
