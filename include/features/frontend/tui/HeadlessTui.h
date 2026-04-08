#pragma once

#include <sys/types.h>

#include <string>

#include "features/frontend/tui/VtScreen.h"
namespace area {

class HeadlessTui {
 public:
    HeadlessTui(std::string binary, std::string socketPath);
    ~HeadlessTui();

    HeadlessTui(const HeadlessTui&) = delete;
    HeadlessTui& operator=(const HeadlessTui&) = delete;

    bool start(int rows = 24, int cols = 80);
    void stop();
    bool isRunning();

    void drain();

    void drainAndSettle(int ms = 200);

    std::string screenText() const { return screen_.text(); }
    int rows() const { return screen_.rows(); }
    int cols() const { return screen_.cols(); }
    int cursorRow() const { return screen_.cursorRow(); }
    int cursorCol() const { return screen_.cursorCol(); }

    void sendText(const std::string& text);
    void sendKey(const std::string& keyName);
    void sendMouseClick(int row, int col, int button = 0);
    void sendMouseRelease(int row, int col, int button = 0);
    void resize(int rows, int cols);

 private:
    void writePty(const std::string& data);
    std::string mouseSeq(int button, int col, int row, bool press);

    std::string binary_;
    std::string socketPath_;
    std::string dataDir_;
    int masterFd_ = -1;
    pid_t childPid_ = -1;
    VtScreen screen_;
};

}  // namespace area
