#pragma once

#include <string>

#include "features/frontend/mcp/McpServer.h"
namespace area::features::server {

void registerTools(mcp::McpServer& server,
                   const std::string& dataDir,
                   const std::string& workDir);

}
