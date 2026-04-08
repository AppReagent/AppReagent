#include "features/frontend/tui/HeadlessTui.h"

#include <poll.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <utility>

namespace area {
HeadlessTui::HeadlessTui(std::string binary, std::string socketPath)
    : binary_(std::move(binary)), socketPath_(std::move(socketPath)) {
    auto slash = socketPath_.rfind('/');
    if (slash != std::string::npos)
        dataDir_ = socketPath_.substr(0, slash);
    else
        dataDir_ = "/opt/area";
}

HeadlessTui::~HeadlessTui() {
    stop();
}

bool HeadlessTui::start(int rows, int cols) {
    if (isRunning()) return true;

    screen_.resize(rows, cols);

    struct winsize ws{};
    ws.ws_row = static_cast<uint16_t>(rows);
    ws.ws_col = static_cast<uint16_t>(cols);

    pid_t pid = forkpty(&masterFd_, nullptr, nullptr, &ws);
    if (pid < 0) return false;

    if (pid == 0) {
        setenv("TERM", "xterm-256color", 1);
        setenv("AREA_DATA_DIR", dataDir_.c_str(), 1);
        execl(binary_.c_str(), binary_.c_str(), "tui", nullptr);
        _exit(127);
    }

    childPid_ = pid;

    drainAndSettle(500);
    return true;
}

void HeadlessTui::stop() {
    if (childPid_ > 0) {
        kill(childPid_, SIGTERM);
        int status;
        waitpid(childPid_, &status, 0);
        childPid_ = -1;
    }
    if (masterFd_ >= 0) {
        close(masterFd_);
        masterFd_ = -1;
    }
}

bool HeadlessTui::isRunning() {
    if (childPid_ <= 0) return false;
    int status;
    pid_t r = waitpid(childPid_, &status, WNOHANG);
    if (r == childPid_) {
        childPid_ = -1;
        if (masterFd_ >= 0) {
            close(masterFd_); masterFd_ = -1;
        }
        return false;
    }
    return true;
}

void HeadlessTui::drain() {
    if (masterFd_ < 0) return;
    char buf[8192];
    for (;;) {
        struct pollfd pfd{masterFd_, POLLIN, 0};
        int r = poll(&pfd, 1, 0);
        if (r <= 0) break;
        ssize_t n = read(masterFd_, buf, sizeof(buf));
        if (n <= 0) break;
        screen_.feed(buf, static_cast<size_t>(n));
    }
}

void HeadlessTui::drainAndSettle(int ms) {
    drain();
    if (ms > 0 && masterFd_ >= 0) {
        struct pollfd pfd{masterFd_, POLLIN, 0};
        int r = poll(&pfd, 1, ms);
        if (r > 0) drain();
    }
}

void HeadlessTui::writePty(const std::string& data) {
    if (masterFd_ < 0) return;
    size_t written = 0;
    while (written < data.size()) {
        ssize_t n = write(masterFd_, data.data() + written, data.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        written += static_cast<size_t>(n);
    }
}

void HeadlessTui::sendText(const std::string& text) {
    writePty(text);
}

void HeadlessTui::sendKey(const std::string& keyName) {
    static const struct { const char* name; const char* seq; } keys[] = {
        {"enter",     "\r"},
        {"escape",    "\033"},
        {"up",        "\033[A"},
        {"down",      "\033[B"},
        {"right",     "\033[C"},
        {"left",      "\033[D"},
        {"backspace", "\x7f"},
        {"tab",       "\t"},
        {"pageup",    "\033[5~"},
        {"pagedown",  "\033[6~"},
        {"home",      "\033[H"},
        {"end",       "\033[F"},
        {"ctrl+a",    "\x01"},
        {"ctrl+b",    "\x02"},
        {"ctrl+c",    "\x03"},
        {"ctrl+e",    "\x05"},
        {"ctrl+k",    "\x0b"},
        {"ctrl+l",    "\x0c"},
        {"ctrl+u",    "\x15"},
        {"ctrl+w",    "\x17"},
    };
    for (auto& k : keys) {
        if (keyName == k.name) {
            writePty(k.seq);
            return;
        }
    }

    writePty(keyName);
}

std::string HeadlessTui::mouseSeq(int button, int col, int row, bool press) {
    std::string s = "\033[<";
    s += std::to_string(button);
    s += ';';
    s += std::to_string(col);
    s += ';';
    s += std::to_string(row);
    s += press ? 'M' : 'm';
    return s;
}

void HeadlessTui::sendMouseClick(int row, int col, int button) {
    writePty(mouseSeq(button, col, row, true));
}

void HeadlessTui::sendMouseRelease(int row, int col, int button) {
    writePty(mouseSeq(button, col, row, false));
}

void HeadlessTui::resize(int rows, int cols) {
    screen_.resize(rows, cols);
    if (masterFd_ >= 0) {
        struct winsize ws{};
        ws.ws_row = static_cast<uint16_t>(rows);
        ws.ws_col = static_cast<uint16_t>(cols);
        ioctl(masterFd_, TIOCSWINSZ, &ws);
    }
    if (childPid_ > 0) {
        kill(childPid_, SIGWINCH);
    }
}
}  // namespace area
