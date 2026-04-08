#pragma once

#include <string>

#include "features/frontend/mcp/McpServer.h"
namespace area::features::scan {

void registerTools(mcp::McpServer& server,
                   const std::string& binary,
                   const std::string& dataDir);

}
