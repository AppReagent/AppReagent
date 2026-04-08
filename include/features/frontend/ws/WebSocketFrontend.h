#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

#include "infra/events/EventBus.h"
#include "features/frontend/ws/WebSocketServer.h"
#include <nlohmann/json.hpp>

namespace area {

class AreaServer;

class WebSocketFrontend {
 public:
    WebSocketFrontend(AreaServer& server, EventBus& bus, int port);
    ~WebSocketFrontend();

    WebSocketFrontend(const WebSocketFrontend&) = delete;
    WebSocketFrontend& operator=(const WebSocketFrontend&) = delete;

    void start();
    void stop();

 private:
    void onConnect(ws::ClientId id);
    void onDisconnect(ws::ClientId id);
    void onMessage(ws::ClientId id, const std::string& text);
    void onEvent(const Event& event);

    AreaServer& server_;
    EventBus& bus_;
    ws::WebSocketServer ws_;
    SubscriptionId subId_ = 0;

    std::mutex clientsMu_;
    struct ClientState {
        std::string chatId;
    };
    std::unordered_map<ws::ClientId, ClientState> clients_;
};

}  // namespace area
