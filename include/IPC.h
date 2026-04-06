#pragma once

#include <optional>
#include <string>
#include <nlohmann/json.hpp>

namespace area::ipc {

// Create a Unix domain socket listener, returns fd
int createListener(const std::string& path);

// Connect to a Unix domain socket, returns fd or -1
int connectTo(const std::string& path);

// Send a JSON line (object + newline), returns false on error
bool sendLine(int fd, const nlohmann::json& j);

// Non-blocking read of a complete JSON line. Uses internal per-fd buffering.
// Returns nullopt if no complete line available yet.
std::optional<nlohmann::json> readLine(int fd);

// Clean up socket file
void removeSock(const std::string& path);

// Close fd
void closeFd(int fd);

} // namespace area::ipc
