#pragma once

#include <string>

#include "mcp/McpServer.h"
namespace area::features::scan {

void registerTools(mcp::McpServer& server,
                   const std::string& binary,
                   const std::string& dataDir);

}
