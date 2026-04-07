#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <sys/types.h>

namespace area::features::testing {

/// Spawns `area mcp` as a child process and talks JSON-RPC over pipes.
/// Provides convenience wrappers for common MCP tool calls.
class McpTestClient {
public:
    McpTestClient(std::string binary, std::string dataDir);
    ~McpTestClient();

    McpTestClient(const McpTestClient&) = delete;
    McpTestClient& operator=(const McpTestClient&) = delete;

    /// Start the MCP server process and send initialize.
    bool start();

    /// Stop the MCP server process.
    void stop();

    /// Call a tool and return the text result. Throws on error.
    std::string callTool(const std::string& name,
                         const nlohmann::json& args = nlohmann::json::object());

    /// Call a tool and return the raw JSON response.
    nlohmann::json callToolRaw(const std::string& name,
                               const nlohmann::json& args = nlohmann::json::object());

    // ── Convenience wrappers ──

    void serverStart();
    void serverStop();

    std::string chat(const std::string& message,
                     const std::string& chatId = "test");

    std::string tuiScreen(int waitMs = 500);
    std::string tuiClick(int row, int col, const std::string& button = "left");
    std::string tuiKey(const std::string& key);
    std::string tuiType(const std::string& text);

private:
    nlohmann::json sendRequest(const std::string& method,
                               const nlohmann::json& params);
    std::string readLine();
    void writeLine(const std::string& line);

    std::string binary_;
    std::string dataDir_;
    pid_t child_ = -1;
    int writeFd_ = -1;
    int readFd_ = -1;
    int nextId_ = 1;
};

} // namespace area::features::testing
