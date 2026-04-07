#include "features/chat/ChatService.h"
#include "infra/ipc/IPC.h"

#include <filesystem>
#include <poll.h>

namespace fs = std::filesystem;

namespace area::features::chat {

static constexpr int kChatPollTimeoutMs = 300000; // 5 min for scans

ChatService::ChatService(const std::string& sockPath)
    : sockPath_(sockPath) {}

ChatService::Response ChatService::send(const std::string& message,
                                         const std::string& chatId,
                                         int timeoutMs) {
    if (message.empty()) return {"'message' is required.", {}, true};
    if (!fs::exists(sockPath_))
        return {"Server not running — call area_server_start first.", {}, true};

    int fd = ipc::connectTo(sockPath_);
    if (fd < 0) return {"Could not connect to server.", {}, true};

    // Attach + dangerous mode
    ipc::sendLine(fd, {{"type", "attach"},        {"chat_id", chatId}});
    ipc::sendLine(fd, {{"type", "set_dangerous"}, {"chat_id", chatId},
                       {"enabled", true}});

    // Drain history / initial state
    for (int i = 0; i < 50; i++) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 200) > 0) {
            bool gotState = false;
            while (auto msg = ipc::readLine(fd)) {
                if (msg->value("type", "") == "state") gotState = true;
            }
            if (gotState) break;
        }
    }

    ipc::sendLine(fd, {{"type", "user_input"}, {"chat_id", chatId},
                       {"content", message}});

    int timeout = (timeoutMs > 0) ? timeoutMs : kChatPollTimeoutMs;
    Response resp;
    bool done = false;
    while (!done) {
        struct pollfd rpfd = {fd, POLLIN, 0};
        if (poll(&rpfd, 1, timeout) <= 0) {
            resp.text += "\n[timeout after " + std::to_string(timeout / 1000) + " seconds]";
            break;
        }
        while (auto msg = ipc::readLine(fd)) {
            auto type = msg->value("type", "");
            if (type == "agent_msg") {
                resp.messages.push_back(*msg);
                auto t = (*msg)["msg"].value("type", "");
                auto c = (*msg)["msg"].value("content", "");
                if      (t == "answer")   resp.text += c + "\n";
                else if (t == "sql")      resp.text += "[sql] " + c + "\n";
                else if (t == "result")   resp.text += "[result] " + c + "\n";
                else if (t == "error")    resp.text += "[error] " + c + "\n";
                else if (t == "thinking") resp.text += "[thinking] " + c + "\n";
            } else if (type == "state") {
                if (!msg->value("processing", true)) done = true;
            }
        }
    }

    ipc::closeFd(fd);

    if (resp.text.empty()) resp.text = "(no response)";
    while (!resp.text.empty() && (resp.text.back() == '\n' || resp.text.back() == ' '))
        resp.text.pop_back();
    return resp;
}

ChatService::Response ChatService::clear(const std::string& chatId) {
    int fd = ipc::connectTo(sockPath_);
    if (fd < 0) return {"Server not running.", {}, true};

    ipc::sendLine(fd, {{"type", "attach"},        {"chat_id", chatId}});
    usleep(200000);
    ipc::sendLine(fd, {{"type", "clear_context"}, {"chat_id", chatId}});
    usleep(200000);
    ipc::closeFd(fd);

    return {"Chat \"" + chatId + "\" cleared.", {}, false};
}

} // namespace area::features::chat
