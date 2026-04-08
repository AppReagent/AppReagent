#pragma once

#include <string>

#include "mcp/McpServer.h"
namespace area::features::test {

void registerTools(mcp::McpServer& server, const std::string& workDir);

}
