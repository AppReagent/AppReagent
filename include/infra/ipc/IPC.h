#pragma once

#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace area::ipc {

int createListener(const std::string& path);

int connectTo(const std::string& path);

bool sendLine(int fd, const nlohmann::json& j);

std::optional<nlohmann::json> readLine(int fd);

void removeSock(const std::string& path);

void closeFd(int fd);

}  // namespace area::ipc
