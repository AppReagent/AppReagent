#pragma once

#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
namespace area::features::chat {

class ChatService {
 public:
    explicit ChatService(const std::string& sockPath);

    struct Response {
        std::string text;
        std::vector<nlohmann::json> messages;
        bool error = false;
    };

    Response send(const std::string& message,
                  const std::string& chatId = "default",
                  int timeoutMs = 300000);

    Response clear(const std::string& chatId = "default");

 private:
    std::string sockPath_;
};

}  // namespace area::features::chat
