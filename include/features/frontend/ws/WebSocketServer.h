#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace area::ws {

using ClientId = uint64_t;

class WebSocketServer {
 public:
    using OnConnect    = std::function<void(ClientId)>;
    using OnDisconnect = std::function<void(ClientId)>;
    using OnMessage    = std::function<void(ClientId, const std::string&)>;

    explicit WebSocketServer(int port);
    ~WebSocketServer();

    WebSocketServer(const WebSocketServer&) = delete;
    WebSocketServer& operator=(const WebSocketServer&) = delete;

    void setOnConnect(OnConnect cb)       { onConnect_ = std::move(cb); }
    void setOnDisconnect(OnDisconnect cb) { onDisconnect_ = std::move(cb); }
    void setOnMessage(OnMessage cb)       { onMessage_ = std::move(cb); }

    void start();
    void stop();
    bool running() const { return running_.load(); }

    void sendText(ClientId id, const std::string& text);
    void broadcast(const std::string& text);

 private:
    struct ClientConn {
        int fd = -1;
        bool upgraded = false;
        std::string readBuf;
    };

    void listenLoop();
    bool doHandshake(ClientConn& client);
    void processFrames(ClientId id, ClientConn& client);
    void sendFrame(int fd, uint8_t opcode, const std::string& payload);
    void removeClient(ClientId id);

    int port_;
    int listenFd_ = -1;
    std::atomic<bool> running_{false};
    std::thread listenThread_;

    std::mutex clientsMu_;
    uint64_t nextClientId_ = 1;
    std::unordered_map<ClientId, ClientConn> clients_;

    OnConnect onConnect_;
    OnDisconnect onDisconnect_;
    OnMessage onMessage_;
};

}  // namespace area::ws
