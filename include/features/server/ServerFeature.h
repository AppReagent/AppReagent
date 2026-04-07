#pragma once

#include "mcp/McpServer.h"

#include <string>

namespace area::features::server {

void registerTools(mcp::McpServer& server,
                   const std::string& dataDir,
                   const std::string& workDir);

} // namespace area::features::server
