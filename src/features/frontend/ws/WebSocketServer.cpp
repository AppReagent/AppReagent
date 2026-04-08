#include "features/frontend/ws/WebSocketServer.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/sha.h>

namespace area::ws {

static const char* kWebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static std::string base64Encode(const unsigned char* data, int len) {
    int outLen = 4 * ((len + 2) / 3);
    std::string result(outLen, '\0');
    EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()), data, len);
    while (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

static std::string computeAcceptKey(const std::string& clientKey) {
    std::string input = clientKey + kWebSocketGuid;
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()),
         input.size(), hash);
    return base64Encode(hash, SHA_DIGEST_LENGTH);
}

static std::string findHeader(const std::string& headers, const std::string& name) {
    std::string lower;
    lower.reserve(headers.size());
    for (char c : headers) lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    std::string lowerName;
    lowerName.reserve(name.size());
    for (char c : name) lowerName += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    auto pos = lower.find(lowerName + ":");
    if (pos == std::string::npos) return "";

    auto start = headers.find(':', pos) + 1;
    while (start < headers.size() && headers[start] == ' ') start++;
    auto end = headers.find('\r', start);
    if (end == std::string::npos) end = headers.find('\n', start);
    if (end == std::string::npos) end = headers.size();
    return headers.substr(start, end - start);
}

WebSocketServer::WebSocketServer(int port) : port_(port) {}

WebSocketServer::~WebSocketServer() {
    stop();
}

void WebSocketServer::start() {
    if (running_.load()) return;

    listenFd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd_ < 0) {
        std::cerr << "[ws] socket() failed" << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port_));

    if (bind(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[ws] bind() failed on port " << port_ << std::endl;
        close(listenFd_);
        listenFd_ = -1;
        return;
    }

    if (listen(listenFd_, 8) < 0) {
        std::cerr << "[ws] listen() failed" << std::endl;
        close(listenFd_);
        listenFd_ = -1;
        return;
    }

    int flags = fcntl(listenFd_, F_GETFL, 0);
    if (flags >= 0) fcntl(listenFd_, F_SETFL, flags | O_NONBLOCK);

    running_ = true;
    listenThread_ = std::thread([this]() { listenLoop(); });

    std::cerr << "[ws] listening on 127.0.0.1:" << port_ << std::endl;
}

void WebSocketServer::stop() {
    running_ = false;
    if (listenThread_.joinable()) listenThread_.join();

    std::lock_guard lk(clientsMu_);
    for (auto& [id, client] : clients_) {
        if (client.fd >= 0) close(client.fd);
    }
    clients_.clear();

    if (listenFd_ >= 0) {
        close(listenFd_);
        listenFd_ = -1;
    }
}

void WebSocketServer::listenLoop() {
    while (running_.load()) {
        std::vector<struct pollfd> pfds;
        pfds.push_back({listenFd_, POLLIN, 0});

        {
            std::lock_guard lk(clientsMu_);
            for (auto& [id, client] : clients_) {
                pfds.push_back({client.fd, POLLIN, 0});
            }
        }

        int ret = poll(pfds.data(), pfds.size(), 100);
        if (ret < 0) continue;

        if (pfds[0].revents & POLLIN) {
            int clientFd = accept(listenFd_, nullptr, nullptr);
            if (clientFd >= 0) {
                int fl = fcntl(clientFd, F_GETFL, 0);
                if (fl >= 0) fcntl(clientFd, F_SETFL, fl | O_NONBLOCK);

                std::lock_guard lk(clientsMu_);
                ClientId cid = nextClientId_++;
                clients_[cid] = {clientFd, false, ""};
            }
        }

        std::vector<ClientId> toRemove;
        std::vector<ClientId> clientOrder;
        {
            std::lock_guard lk(clientsMu_);
            for (auto& [id, client] : clients_) {
                clientOrder.push_back(id);
            }

            for (size_t i = 0; i < clientOrder.size(); i++) {
                size_t idx = i + 1;
                if (idx >= pfds.size()) break;

                auto& client = clients_[clientOrder[i]];
                ClientId id = clientOrder[i];

                if (pfds[idx].revents & (POLLIN | POLLHUP)) {
                    char buf[8192];
                    ssize_t n = recv(client.fd, buf, sizeof(buf), 0);
                    if (n <= 0) {
                        toRemove.push_back(id);
                    } else {
                        client.readBuf.append(buf, n);
                        if (client.readBuf.size() > 1048576) {
                            toRemove.push_back(id);
                        } else if (!client.upgraded) {
                            if (!doHandshake(client)) {
                                if (client.readBuf.size() > 8192) toRemove.push_back(id);
                            } else {
                                if (onConnect_) onConnect_(id);
                            }
                        }
                        if (client.upgraded && client.readBuf.size() <= 1048576) {
                            processFrames(id, client);
                        }
                    }
                }
                if (pfds[idx].revents & (POLLHUP | POLLERR)) {
                    toRemove.push_back(id);
                }
            }
        }

        for (ClientId id : toRemove) {
            removeClient(id);
        }
    }
}

bool WebSocketServer::doHandshake(ClientConn& client) {
    auto pos = client.readBuf.find("\r\n\r\n");
    if (pos == std::string::npos) return false;

    std::string headers = client.readBuf.substr(0, pos);
    client.readBuf.erase(0, pos + 4);

    std::string key = findHeader(headers, "Sec-WebSocket-Key");
    if (key.empty()) return false;

    std::string acceptKey = computeAcceptKey(key);

    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " + acceptKey + "\r\n"
        "\r\n";

    ssize_t written = 0;
    while (written < static_cast<ssize_t>(response.size())) {
        ssize_t n = ::send(client.fd, response.data() + written,
                           response.size() - written, MSG_NOSIGNAL);
        if (n < 0) return false;
        written += n;
    }

    client.upgraded = true;
    return true;
}

void WebSocketServer::processFrames(ClientId id, ClientConn& client) {
    while (true) {
        if (client.readBuf.size() < 2) return;

        auto* data = reinterpret_cast<const uint8_t*>(client.readBuf.data());
        uint8_t opcode = data[0] & 0x0F;
        bool masked = (data[1] & 0x80) != 0;
        uint64_t payloadLen = data[1] & 0x7F;
        size_t headerLen = 2;

        if (payloadLen == 126) {
            if (client.readBuf.size() < 4) return;
            payloadLen = (static_cast<uint64_t>(data[2]) << 8) | data[3];
            headerLen = 4;
        } else if (payloadLen == 127) {
            if (client.readBuf.size() < 10) return;
            payloadLen = 0;
            for (int i = 0; i < 8; i++) {
                payloadLen = (payloadLen << 8) | data[2 + i];
            }
            headerLen = 10;
        }

        if (!masked) {
            client.readBuf.clear();
            return;
        }

        size_t totalLen = headerLen + 4 + payloadLen;
        if (client.readBuf.size() < totalLen) return;

        std::string payload(client.readBuf.begin() + headerLen + 4,
                            client.readBuf.begin() + totalLen);

        const uint8_t* mask = data + headerLen;
        for (size_t i = 0; i < payload.size(); i++) {
            payload[i] ^= mask[i % 4];
        }

        client.readBuf.erase(0, totalLen);

        if (opcode == 0x8) {
            sendFrame(client.fd, 0x8, "");
            return;
        }
        if (opcode == 0x9) {
            sendFrame(client.fd, 0xA, payload);
            continue;
        }
        if (opcode == 0x1 && onMessage_) {
            onMessage_(id, payload);
        }
    }
}

void WebSocketServer::sendFrame(int fd, uint8_t opcode, const std::string& payload) {
    std::vector<uint8_t> frame;
    frame.push_back(0x80 | opcode);

    if (payload.size() < 126) {
        frame.push_back(static_cast<uint8_t>(payload.size()));
    } else if (payload.size() < 65536) {
        frame.push_back(126);
        frame.push_back(static_cast<uint8_t>((payload.size() >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(payload.size() & 0xFF));
    } else {
        frame.push_back(127);
        for (int i = 7; i >= 0; i--) {
            frame.push_back(static_cast<uint8_t>((payload.size() >> (i * 8)) & 0xFF));
        }
    }

    frame.insert(frame.end(), payload.begin(), payload.end());

    ssize_t written = 0;
    auto total = static_cast<ssize_t>(frame.size());
    while (written < total) {
        ssize_t n = ::send(fd, frame.data() + written,
                           frame.size() - written, MSG_NOSIGNAL);
        if (n < 0) return;
        written += n;
    }
}

void WebSocketServer::sendText(ClientId id, const std::string& text) {
    std::lock_guard lk(clientsMu_);
    auto it = clients_.find(id);
    if (it == clients_.end() || !it->second.upgraded) return;
    sendFrame(it->second.fd, 0x1, text);
}

void WebSocketServer::broadcast(const std::string& text) {
    std::lock_guard lk(clientsMu_);
    for (auto& [id, client] : clients_) {
        if (client.upgraded) {
            sendFrame(client.fd, 0x1, text);
        }
    }
}

void WebSocketServer::removeClient(ClientId id) {
    int fd = -1;
    {
        std::lock_guard lk(clientsMu_);
        auto it = clients_.find(id);
        if (it == clients_.end()) return;
        fd = it->second.fd;
        clients_.erase(it);
    }
    if (fd >= 0) close(fd);
    if (onDisconnect_) onDisconnect_(id);
}

}  // namespace area::ws
