#pragma once

#include <string>
#include <utility>
#include <nlohmann/json.hpp>

namespace area {

/// MCP (Model Context Protocol) server that exposes AppReagent lifecycle and
/// agent interaction as structured tools for Claude Code.
///
/// Speaks JSON-RPC 2.0 over stdio (newline-delimited).  Does NOT require a
/// database connection — it manages the area server via IPC and runs
/// build/test commands via fork+exec.
///
/// Usage:  area mcp          (launched automatically by Claude Code via .mcp.json)
class McpServer {
public:
    McpServer(std::string dataDir, std::string workDir);
    int run();

private:
    void log(const std::string& msg);
    void send(const nlohmann::json& msg);
    std::string findBin();

    nlohmann::json toolList();
    std::pair<std::string, bool> dispatch(const std::string& name,
                                          const nlohmann::json& args);

    // Tools
    std::pair<std::string, bool> toolBuild(const nlohmann::json& args);
    std::pair<std::string, bool> toolServerStart();
    std::pair<std::string, bool> toolServerStop();
    std::pair<std::string, bool> toolServerRestart();
    std::pair<std::string, bool> toolServerStatus();
    std::pair<std::string, bool> toolChat(const nlohmann::json& args);
    std::pair<std::string, bool> toolClearChat(const nlohmann::json& args);
    std::pair<std::string, bool> toolTestUnit();
    std::pair<std::string, bool> toolTestE2e(const nlohmann::json& args);
    std::pair<std::string, bool> toolEvaluate();

    bool isServerRunning(int* outPid = nullptr);

    std::string dataDir_;
    std::string workDir_;
    std::string sockPath_;
    std::string pidPath_;
};

} // namespace area
