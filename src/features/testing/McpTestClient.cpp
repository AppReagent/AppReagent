#include "features/testing/McpTestClient.h"

#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <cstdlib>
#include <stdexcept>
#include <utility>

#include "nlohmann/detail/json_ref.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

namespace area::features::testing {
McpTestClient::McpTestClient(std::string binary, std::string dataDir)
    : binary_(std::move(binary)), dataDir_(std::move(dataDir)) {}

McpTestClient::~McpTestClient() {
    stop();
}

bool McpTestClient::start() {
    int toChild[2], fromChild[2];
    if (pipe(toChild) < 0 || pipe(fromChild) < 0) return false;

    pid_t pid = fork();
    if (pid < 0) {
        close(toChild[0]); close(toChild[1]);
        close(fromChild[0]); close(fromChild[1]);
        return false;
    }

    if (pid == 0) {
        close(toChild[1]);
        close(fromChild[0]);
        dup2(toChild[0], STDIN_FILENO);
        dup2(fromChild[1], STDOUT_FILENO);
        close(toChild[0]);
        close(fromChild[1]);
        setenv("AREA_DATA_DIR", dataDir_.c_str(), 1);
        execl(binary_.c_str(), binary_.c_str(), "mcp", nullptr);
        _exit(127);
    }

    close(toChild[0]);
    close(fromChild[1]);
    writeFd_ = toChild[1];
    readFd_ = fromChild[0];
    child_ = pid;

    auto resp = sendRequest("initialize", {});
    return resp.contains("result");
}

void McpTestClient::stop() {
    if (writeFd_ >= 0) {
        close(writeFd_); writeFd_ = -1;
    }
    if (readFd_ >= 0) {
        close(readFd_); readFd_ = -1;
    }
    if (child_ > 0) {
        kill(child_, SIGTERM);
        int status;
        waitpid(child_, &status, 0);
        child_ = -1;
    }
}

void McpTestClient::writeLine(const std::string& line) {
    std::string data = line + "\n";
    size_t written = 0;
    while (written < data.size()) {
        ssize_t n = write(writeFd_, data.data() + written, data.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::runtime_error("write to MCP process failed");
        }
        written += static_cast<size_t>(n);
    }
}

std::string McpTestClient::readLine() {
    std::string line;
    char c;
    while (true) {
        struct pollfd pfd = {readFd_, POLLIN, 0};
        int r = poll(&pfd, 1, 30000);
        if (r <= 0) throw std::runtime_error("timeout reading from MCP process");

        ssize_t n = read(readFd_, &c, 1);
        if (n <= 0) throw std::runtime_error("MCP process closed");
        if (c == '\n') return line;
        line += c;
    }
}

json McpTestClient::sendRequest(const std::string& method, const json& params) {
    int id = nextId_++;
    json req = {{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", params}};
    writeLine(req.dump());
    auto respStr = readLine();
    return json::parse(respStr);
}

json McpTestClient::callToolRaw(const std::string& name, const json& args) {
    return sendRequest("tools/call", {{"name", name}, {"arguments", args}});
}

std::string McpTestClient::callTool(const std::string& name, const json& args) {
    auto resp = callToolRaw(name, args);
    if (resp.contains("error"))
        throw std::runtime_error("MCP error: " + resp["error"].value("message", "unknown"));
    auto& content = resp["result"]["content"];
    if (content.is_array() && !content.empty())
        return content[0].value("text", "");
    return "";
}

void McpTestClient::serverStart() {
    callTool("area_server_start");
}

void McpTestClient::serverStop() {
    callTool("area_server_stop");
}

std::string McpTestClient::chat(const std::string& message, const std::string& chatId) {
    return callTool("area_chat", {{"message", message}, {"chat_id", chatId}});
}

std::string McpTestClient::tuiScreen(int waitMs) {
    return callTool("area_tui_screen", {{"wait_ms", waitMs}});
}

std::string McpTestClient::tuiClick(int row, int col, const std::string& button) {
    return callTool("area_tui_click", {{"row", row}, {"col", col}, {"button", button}});
}

std::string McpTestClient::tuiKey(const std::string& key) {
    return callTool("area_tui_key", {{"key", key}});
}

std::string McpTestClient::tuiType(const std::string& text) {
    return callTool("area_tui_type", {{"text", text}});
}
}  // namespace area::features::testing
