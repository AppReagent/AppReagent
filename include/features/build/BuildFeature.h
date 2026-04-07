#pragma once

#include "mcp/McpServer.h"

#include <string>

namespace area::features::build {

void registerTools(mcp::McpServer& server, const std::string& workDir);

} // namespace area::features::build
