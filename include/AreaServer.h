#pragma once

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>

#include "Agent.h"
#include "infra/llm/BackendPool.h"
#include "Config.h"
#include "infra/db/Database.h"
#include "infra/sandbox/Sandbox.h"
#include "ScanState.h"
#include "infra/tools/ToolRegistry.h"
#include "events/EventBus.h"

namespace area {

struct ChatSession {
    std::string id;
    std::string name;

    std::unique_ptr<Agent> agent;
    std::unique_ptr<Sandbox> sandbox;
    std::unique_ptr<ToolRegistry> tools;

    // Display messages (what the TUI shows)
    struct DisplayMsg {
        std::string who; // "user" or "agent"
        std::string type; // "thinking", "sql", "result", "answer", "error"
        std::string content;
    };
    std::vector<DisplayMsg> messages;
    std::mutex messagesMu;

    // Processing state
    std::atomic<bool> processing{false};
    std::thread processingThread;

    // Confirm state
    std::mutex confirmMu;
    std::condition_variable confirmCv;
    std::atomic<bool> confirmPending{false};
    int confirmReqId = 0;
    std::string confirmDescription;
    bool confirmIsPath = false;
    ConfirmResult confirmResult;
    bool confirmResponded = false;

    // Mode
    std::atomic<bool> dangerousMode{false};

    // Attached client fd (-1 = none)
    std::atomic<int> clientFd{-1};

    // Chat data directory
    std::string dataDir;

    void saveConvo();
    void loadConvo();
};

class AreaServer {
public:
    AreaServer(Config config, const std::string& dataDir = "/opt/area");
    ~AreaServer();

    void run();
    void shutdown();

private:
    void handleClient(int clientFd);
    void handleMessage(int clientFd, const nlohmann::json& msg);

    void processUserInput(ChatSession& chat, const std::string& input);
    void sendToClient(int fd, const nlohmann::json& msg);
    void broadcastToChat(const std::string& chatId, const nlohmann::json& msg);

    ChatSession& getOrCreateChat(const std::string& id, const std::string& name = "");
    std::string generateId();

    Config config_;
    std::string dataDir_;
    Database db_;
    int listenFd_ = -1;
    std::atomic<bool> running_{false};

    ScanState scanState_;
    EventBus eventBus_;
    std::unique_ptr<BackendPool> chatPool_; // shared across all chat agents
    std::unordered_map<std::string, std::unique_ptr<ChatSession>> chats_;
    std::mutex chatsMu_;

    // Connected clients
    std::vector<int> clientFds_;
    std::mutex clientsMu_;
};

} // namespace area
