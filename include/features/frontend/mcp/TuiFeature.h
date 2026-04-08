#pragma once

#include <string>

#include "features/frontend/mcp/McpServer.h"
namespace area::features::tui {

void registerTools(mcp::McpServer& server,
                   const std::string& binary,
                   const std::string& sockPath);

}
