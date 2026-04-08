#include "features/frontend/ws/WebSocketFrontend.h"

#include <iostream>

#include "features/server/AreaServer.h"

using json = nlohmann::json;

namespace area {

static std::string eventTypeStr(EventType type) {
    switch (type) {
        case EventType::AGENT_THOUGHT:       return "thinking";
        case EventType::AGENT_ANSWER:        return "answer";
        case EventType::AGENT_MSG_SQL:       return "sql";
        case EventType::AGENT_MSG_RESULT:    return "result";
        case EventType::AGENT_MSG_ERROR:     return "error";
        case EventType::AGENT_MSG_TUI_CONTROL: return "tui_control";
        case EventType::AGENT_MSG_STATE:     return "state";
        case EventType::SCAN_FILE_START:     return "scan_file_start";
        case EventType::SCAN_FILE_END:       return "scan_file_end";
        case EventType::SCAN_PROGRESS:       return "scan_progress";
        case EventType::NODE_START:          return "node_start";
        case EventType::NODE_END:            return "node_end";
        case EventType::LLM_CALL:            return "llm_call";
        case EventType::TOOL_START:          return "tool_start";
        case EventType::TOOL_END:            return "tool_end";
    }
    return "unknown";
}

WebSocketFrontend::WebSocketFrontend(AreaServer& server, EventBus& bus, int port)
    : server_(server), bus_(bus), ws_(port) {}

WebSocketFrontend::~WebSocketFrontend() {
    stop();
}

void WebSocketFrontend::start() {
    ws_.setOnConnect([this](ws::ClientId id) { onConnect(id); });
    ws_.setOnDisconnect([this](ws::ClientId id) { onDisconnect(id); });
    ws_.setOnMessage([this](ws::ClientId id, const std::string& text) {
        onMessage(id, text);
    });

    subId_ = bus_.subscribe([this](const Event& event) { onEvent(event); });

    ws_.start();
}

void WebSocketFrontend::stop() {
    if (subId_ != 0) {
        bus_.unsubscribe(subId_);
        subId_ = 0;
    }
    ws_.stop();
}

void WebSocketFrontend::onConnect(ws::ClientId id) {
    std::lock_guard lk(clientsMu_);
    clients_[id] = {};
    std::cerr << "[ws-frontend] client connected: " << id << std::endl;
}

void WebSocketFrontend::onDisconnect(ws::ClientId id) {
    std::lock_guard lk(clientsMu_);
    clients_.erase(id);
    std::cerr << "[ws-frontend] client disconnected: " << id << std::endl;
}

void WebSocketFrontend::onMessage(ws::ClientId id, const std::string& text) {
    json msg;
    try {
        msg = json::parse(text);
    } catch (...) {
        return;
    }

    std::string type = msg.value("type", "");

    if (type == "subscribe") {
        std::string chatId = msg.value("chat_id", "default");
        {
            std::lock_guard lk(clientsMu_);
            clients_[id].chatId = chatId;
        }
        server_.handleExternalMessage(
            json{{"type", "get_history"}, {"chat_id", chatId}},
            [this, id](const json& reply) {
                ws_.sendText(id, reply.dump());
            });
        return;
    }

    server_.handleExternalMessage(msg,
        [this, id](const json& reply) {
            ws_.sendText(id, reply.dump());
        });
}

void WebSocketFrontend::onEvent(const Event& event) {
    json msg = {
        {"type", "event"},
        {"event_type", eventTypeStr(event.type)},
        {"source", event.source},
        {"detail", event.detail},
        {"chat_id", event.chatId}
    };

    std::string payload = msg.dump();

    std::lock_guard lk(clientsMu_);
    for (auto& [id, state] : clients_) {
        if (state.chatId.empty() || state.chatId == event.chatId || event.chatId.empty()) {
            ws_.sendText(id, payload);
        }
    }
}

}  // namespace area
