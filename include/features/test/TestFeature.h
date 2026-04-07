#pragma once

#include "mcp/McpServer.h"

#include <string>

namespace area::features::test {

void registerTools(mcp::McpServer& server, const std::string& workDir);

} // namespace area::features::test
