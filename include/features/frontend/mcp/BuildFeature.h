#pragma once

#include <string>

#include "features/frontend/mcp/McpServer.h"
namespace area::features::build {

void registerTools(mcp::McpServer& server, const std::string& workDir);

}
