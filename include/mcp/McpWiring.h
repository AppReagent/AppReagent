#pragma once

#include <string>

namespace area {

/// Set up and run the MCP server. Registers all features and tools,
/// then runs the JSON-RPC protocol loop.
int runMcpServer(const std::string& dataDir, const std::string& workDir);

} // namespace area
