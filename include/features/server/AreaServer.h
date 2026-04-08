#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "infra/agent/Agent.h"
#include "infra/llm/BackendPool.h"
#include "infra/config/Config.h"
#include "infra/db/Database.h"
#include "infra/sandbox/Sandbox.h"
#include "features/scan/ScanState.h"
#include "infra/tools/ToolRegistry.h"
#include "infra/events/EventBus.h"
#include <nlohmann/json.hpp>

namespace area {

struct ChatSession {
    std::string id;
    std::string name;

    std::unique_ptr<Agent> agent;
    std::unique_ptr<Sandbox> sandbox;
    std::unique_ptr<ToolRegistry> tools;

    struct DisplayMsg {
        std::string who;
        std::string type;
        std::string content;
    };
    std::vector<DisplayMsg> messages;
    std::mutex messagesMu;

    std::mutex processingMu;
    std::atomic<bool> processing{false};
    std::thread processingThread;

    std::mutex confirmMu;
    std::condition_variable confirmCv;
    std::atomic<bool> confirmPending{false};
    int confirmReqId = 0;
    std::string confirmDescription;
    bool confirmIsPath = false;
    ConfirmResult confirmResult;
    bool confirmResponded = false;

    std::atomic<bool> dangerousMode{false};

    std::atomic<int> clientFd{-1};

    std::string dataDir;

    void saveConvo();
    void loadConvo();
};

class AreaServer {
 public:
    explicit AreaServer(Config config, const std::string& dataDir = "/opt/area");
    ~AreaServer();

    void run();
    void shutdown();

    EventBus& eventBus() { return eventBus_; }

    using ReplyCallback = std::function<void(const nlohmann::json&)>;
    void handleExternalMessage(const nlohmann::json& msg, ReplyCallback reply);

 private:
    void handleClient(int clientFd);
    void handleMessage(int clientFd, const nlohmann::json& msg);

    void processUserInput(std::shared_ptr<ChatSession> chat, const std::string& input);
    void sendToClient(int fd, const nlohmann::json& msg);
    void broadcastToChat(const std::string& chatId, const nlohmann::json& msg);

    std::shared_ptr<ChatSession> getOrCreateChat(const std::string& id,
                                                  const std::string& name = "");
    std::string generateId();

    Config config_;
    std::string dataDir_;
    Database db_;
    int listenFd_ = -1;
    std::atomic<bool> running_{false};

    ScanState scanState_;
    EventBus eventBus_;
    std::unique_ptr<BackendPool> chatPool_;
    std::unordered_map<std::string, std::shared_ptr<ChatSession>> chats_;
    std::mutex chatsMu_;

    std::vector<int> clientFds_;
    std::mutex clientsMu_;
};

}  // namespace area
