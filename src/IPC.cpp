#include "IPC.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <mutex>
#include <unordered_map>

static void setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

namespace area::ipc {

static std::mutex g_readBufsMu;
static std::unordered_map<int, std::string> g_readBufs;

int createListener(const std::string& path) {
    removeSock(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 4) < 0) {
        close(fd);
        removeSock(path);
        return -1;
    }

    return fd;
}

int connectTo(const std::string& path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    setNonBlocking(fd);
    return fd;
}

bool sendLine(int fd, const nlohmann::json& j) {
    std::string line = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) + "\n";
    const char* data = line.c_str();
    size_t remaining = line.size();

    while (remaining > 0) {
        ssize_t n = write(fd, data, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                // Wait up to 5s for the socket to become writable
                struct pollfd pfd = {fd, POLLOUT, 0};
                if (poll(&pfd, 1, 5000) <= 0) return false;
                continue;
            }
            return false;
        }
        data += n;
        remaining -= n;
    }
    return true;
}

std::optional<nlohmann::json> readLine(int fd) {
    std::lock_guard lk(g_readBufsMu);
    auto& buf = g_readBufs[fd];

    // Check if we already have a complete line buffered
    auto nl = buf.find('\n');
    if (nl != std::string::npos) {
        std::string line = buf.substr(0, nl);
        buf.erase(0, nl + 1);
        try {
            return nlohmann::json::parse(line);
        } catch (...) {
            return std::nullopt;
        }
    }

    // Try to read more data (non-blocking)
    char tmp[4096];
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n > 0) {
        buf.append(tmp, n);
        nl = buf.find('\n');
        if (nl != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            try {
                return nlohmann::json::parse(line);
            } catch (...) {
                return std::nullopt;
            }
        }
    }

    return std::nullopt;
}

void removeSock(const std::string& path) {
    unlink(path.c_str());
}

void closeFd(int fd) {
    {
        std::lock_guard lk(g_readBufsMu);
        g_readBufs.erase(fd);
    }
    close(fd);
}

} // namespace area::ipc
