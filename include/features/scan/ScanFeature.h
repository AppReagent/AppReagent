#pragma once

#include "mcp/McpServer.h"

#include <string>

namespace area::features::scan {

/// Register scan MCP tools (area_scan).
void registerTools(mcp::McpServer& server,
                   const std::string& binary,
                   const std::string& dataDir);

} // namespace area::features::scan
