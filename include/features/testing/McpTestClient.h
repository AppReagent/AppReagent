#pragma once

#include <sys/types.h>

#include <map>
#include <string>

#include <nlohmann/json.hpp>
namespace area::features::testing {

class McpTestClient {
 public:
    McpTestClient(std::string binary, std::string dataDir);
    ~McpTestClient();

    McpTestClient(const McpTestClient&) = delete;
    McpTestClient& operator=(const McpTestClient&) = delete;

    bool start();

    void stop();

    std::string callTool(const std::string& name,
                         const nlohmann::json& args = nlohmann::json::object());

    nlohmann::json callToolRaw(const std::string& name,
                               const nlohmann::json& args = nlohmann::json::object());

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

}  // namespace area::features::testing
