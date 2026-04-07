#include "features/tui/Tui.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <sstream>
#include "IPC.h"
#include "features/tui/tui_util.h"
#include "util/convo_io.h"
#include "util/string_util.h"
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

namespace area {

// ANSI color codes
static constexpr int COLOR_BLACK   = 30;
static constexpr int COLOR_RESET   = 0;
static constexpr int COLOR_RED     = 31;
static constexpr int COLOR_GREEN   = 32;
static constexpr int COLOR_YELLOW  = 33;
static constexpr int COLOR_BLUE    = 34;
static constexpr int COLOR_MAGENTA = 35;
static constexpr int COLOR_CYAN    = 36;
static constexpr int COLOR_WHITE   = 37;
static constexpr int COLOR_GRAY    = 90;

static volatile sig_atomic_t g_resized = 0;
static volatile sig_atomic_t g_interrupted = 0;
static void handleWinch(int) { g_resized = 1; }
static void handleInt(int) { g_interrupted = 1; }

using area::tui::flowNoise;
using area::tui::noise2d;

using area::util::truncateUTF8;

using CT = Tui::ColorTheme;
using RGB = CT::RGB;

static const CT darkTheme = {
    {62, 50, 76},       // waveBase
    {70, 18, 84},       // waveAccent
    {255, 255, 255},    // pulseBase  (white)
    {-255, -255, -255}, // pulseShift (toward black)
    {60, 50, 20},       // procBase   (dark amber)
    {140, 100, 0},      // procAccent (yellow)
    COLOR_WHITE,
    COLOR_WHITE,
};

static const CT lightTheme = {
    {180, 170, 200},  // waveBase
    {60, 20, 80},     // waveAccent
    {60, 40, 80},     // pulseBase
    {80, 30, 90},     // pulseShift
    {180, 160, 60},   // procBase
    {80, 60, 0},      // procAccent
    COLOR_BLACK,
    COLOR_BLACK,
};

static RGB pulseColor(const CT& th, int x, int y, int frame, double intensity) {
    double n = noise2d(static_cast<double>(x), static_cast<double>(y), static_cast<double>(frame));
    double t = n * intensity;
    // Quantize to steps of 8 so adjacent chars share escapes
    return {
        std::clamp(((th.pulseBase.r + static_cast<int>(t * th.pulseShift.r)) >> 3) << 3, 0, 255),
        std::clamp(((th.pulseBase.g + static_cast<int>(t * th.pulseShift.g)) >> 3) << 3, 0, 255),
        std::clamp(((th.pulseBase.b + static_cast<int>(t * th.pulseShift.b)) >> 3) << 3, 0, 255)
    };
}

// Append an RGB foreground escape
static void appendRGB(std::string& buf, int r, int g, int b, bool bold = false) {
    r = std::clamp(r, 0, 255);
    g = std::clamp(g, 0, 255);
    b = std::clamp(b, 0, 255);
    char esc[32];
    if (bold)
        snprintf(esc, sizeof(esc), "\033[1;38;2;%d;%d;%dm", r, g, b);
    else
        snprintf(esc, sizeof(esc), "\033[38;2;%d;%d;%dm", r, g, b);
    buf += esc;
}

Tui::Tui(int sockFd, const std::string& theme)
    : sockFd_(sockFd),
      theme_(theme == "light" ? lightTheme : darkTheme) {
    outputBuf_.reserve(16384);
}

Tui::~Tui() {
    freeLayout();
    if (rawMode_) disableRawMode();
    exitAltScreen();
}

Tui::TermSize Tui::getTermSize() {
    struct winsize ws{};
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);
    int rows = ws.ws_row > 0 ? ws.ws_row : 24;
    int cols = ws.ws_col > 0 ? ws.ws_col : 80;
    return {rows, cols};
}

void Tui::enableRawMode() {
    tcgetattr(STDIN_FILENO, &origTermios_);
    struct termios raw = origTermios_;
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_iflag &= ~(ICRNL | IXON);
    raw.c_cflag |= CS8;
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    rawMode_ = true;
}

void Tui::disableRawMode() {
    if (rawMode_) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &origTermios_);
        rawMode_ = false;
    }
}

void Tui::enableMouseTracking() {
    outputBuf_ += "\033[?1000h"; // enable mouse click reporting
    outputBuf_ += "\033[?1006h"; // SGR mouse mode (for scroll wheel)
    mouseMode_ = true;
}

void Tui::disableMouseTracking() {
    outputBuf_ += "\033[?1006l";
    outputBuf_ += "\033[?1000l";
    mouseMode_ = false;
}

void Tui::enterAltScreen() {
    outputBuf_ += "\033[?1049h"; // alt screen
    outputBuf_ += "\033[?25l";   // hide cursor
    enableMouseTracking();       // Ctrl+B toggles off for text selection
    flush();
}

void Tui::exitAltScreen() {
    if (mouseMode_) disableMouseTracking();
    outputBuf_ += "\033[?25h";   // show cursor
    outputBuf_ += "\033[?1049l"; // exit alt screen
    flush();
}

void Tui::buildLayout() {
    freeLayout();

    auto ts = getTermSize();

    root_ = YGNodeNew();
    YGNodeStyleSetFlexDirection(root_, YGFlexDirectionColumn);
    YGNodeStyleSetWidth(root_, (float)ts.cols);
    YGNodeStyleSetHeight(root_, (float)ts.rows);

    int idx = 0;

    headerNode_ = YGNodeNew();
    YGNodeStyleSetHeight(headerNode_, showHeader_ ? 1.0f : 0.0f);
    YGNodeInsertChild(root_, headerNode_, idx++);

    clusterNode_ = YGNodeNew();
    YGNodeStyleSetHeight(clusterNode_, 0.0f);
    YGNodeInsertChild(root_, clusterNode_, idx++);

    // Task pane: visible when agent explicitly shows it via TUI tool
    int taskPaneHeight = 0;
    if (showTaskPane_) {
        // Count thinking lines to size the pane (min 4, max 8 including border)
        int thinkingCount = 0;
        {
            std::unique_lock lk(messagesMu_, std::try_to_lock);
            if (lk.owns_lock()) {
                for (auto& m : messages_) {
                    if (m.who == Message::AGENT && m.agentType == AgentMessage::THINKING)
                        thinkingCount++;
                }
            }
        }
        if (thinkingCount > 0)
            taskPaneHeight = std::clamp(thinkingCount + 2, 4, 8); // +2 for top/bottom border
        else
            taskPaneHeight = 4;
    }
    taskPaneNode_ = YGNodeNew();
    YGNodeStyleSetHeight(taskPaneNode_, (float)taskPaneHeight);
    YGNodeInsertChild(root_, taskPaneNode_, idx++);

    contentNode_ = YGNodeNew();
    YGNodeStyleSetFlexGrow(contentNode_, 1);
    YGNodeInsertChild(root_, contentNode_, idx++);

    separatorNode_ = YGNodeNew();
    YGNodeStyleSetHeight(separatorNode_, 1);
    YGNodeInsertChild(root_, separatorNode_, idx++);

    inputNode_ = YGNodeNew();
    YGNodeStyleSetHeight(inputNode_, 1);
    YGNodeInsertChild(root_, inputNode_, idx++);

    YGNodeCalculateLayout(root_, (float)ts.cols, (float)ts.rows, YGDirectionLTR);
}

void Tui::freeLayout() {
    if (root_) {
        YGNodeFreeRecursive(root_);
        root_ = nullptr;
        headerNode_ = nullptr;
        clusterNode_ = nullptr;
        taskPaneNode_ = nullptr;
        contentNode_ = nullptr;
        separatorNode_ = nullptr;
        inputNode_ = nullptr;
    }
}

void Tui::moveCursor(int row, int col) {
    char buf[24];
    int len = snprintf(buf, sizeof(buf), "\033[%d;%dH", row, col);
    outputBuf_.append(buf, len);
}

void Tui::clearLine(int row, int width) {
    moveCursor(row, 1);
    outputBuf_ += "\033[2K";
}

void Tui::setColor(int fg) {
    char buf[12];
    int len = snprintf(buf, sizeof(buf), "\033[%dm", fg);
    outputBuf_.append(buf, len);
}

void Tui::setBold() {
    outputBuf_ += "\033[1m";
}

void Tui::resetStyle() {
    outputBuf_ += "\033[0m";
}

void Tui::flush() {
    const char* data = outputBuf_.c_str();
    size_t remaining = outputBuf_.size();
    while (remaining > 0) {
        ssize_t written = write(STDOUT_FILENO, data, remaining);
        if (written <= 0) break;
        data += written;
        remaining -= written;
    }
    outputBuf_.clear();
}

std::vector<Tui::DisplayLine> Tui::wrapMessage(const AgentMessage& msg, int width) {
    std::vector<DisplayLine> lines;
    std::string text = msg.content;
    // Split by newlines first
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line;
        if (nl == std::string::npos) {
            line = text.substr(pos);
            pos = text.size();
        } else {
            line = text.substr(pos, nl - pos);
            pos = nl + 1;
        }
        // Word wrap at width
        if (width > 0) {
            while ((int)line.size() > width) {
                int bp = std::min(width, (int)line.size() - 1);
                while (bp > 0 && line[bp] != ' ') bp--;
                if (bp == 0) bp = std::min(width, (int)line.size());
                lines.push_back({msg.type, line.substr(0, bp)});
                line = line.substr(bp);
                if (!line.empty() && line[0] == ' ') line.erase(0, 1);
            }
        }
        lines.push_back({msg.type, line});
    }
    return lines;
}

void Tui::renderHeader(int row, int width) {
    moveCursor(row + 1, 1);
    setColor(COLOR_WHITE);
    setBold();
    // Inverse video for header bar
    outputBuf_ += "\033[7m";
    std::string title = " App Reagent (aREa) ";
    std::string header = title;

    // Format token counts for right-aligned label
    auto fmtTokens = [](int n) -> std::string {
        if (n >= 1000000) {
            return std::to_string(n / 1000000) + "." + std::to_string((n % 1000000) / 100000) + "M";
        } else if (n >= 100000) {
            return std::to_string(n / 1000) + "k";
        } else if (n >= 1000) {
            return std::to_string(n / 1000) + "." + std::to_string((n % 1000) / 100) + "k";
        }
        return std::to_string(n);
    };

    int pct = (contextWindow_ > 0) ? std::min(contextTokens_ * 100 / contextWindow_, 100) : 0;
    std::string ctxLabel;
    if (contextWindow_ > 0) {
        ctxLabel = fmtTokens(contextTokens_) + " / " + fmtTokens(contextWindow_);
    } else {
        ctxLabel = "ctx " + std::to_string(pct) + "%";
    }

    int rightPad = width - (int)header.size() - (int)ctxLabel.size() - 1;
    outputBuf_ += header;
    if (rightPad > 0) {
        outputBuf_ += std::string(rightPad, ' ');
    }
    // Color the context label based on usage
    if (pct >= 90) {
        outputBuf_ += "\033[31m"; // red
    } else if (pct >= 70) {
        outputBuf_ += "\033[33m"; // yellow
    }
    outputBuf_ += ctxLabel + " ";
    outputBuf_ += "\033[7m"; // restore inverse
    resetStyle();
}

void Tui::renderContextMenu(int screenRows, int screenCols) {
    if (!contextMenuOpen_) return;

    const int numItems = 2;
    const int menuWidth = 17;
    const int menuHeight = numItems + 2; // top/bottom borders + items

    int row = std::clamp(contextMenuRow_, 1, std::max(1, screenRows - menuHeight + 1));
    int col = std::clamp(contextMenuCol_, 1, std::max(1, screenCols - menuWidth + 1));

    // Top border: ┌─ View ────────┐
    moveCursor(row, col);
    setColor(COLOR_GRAY);
    outputBuf_ += "\xe2\x94\x8c\xe2\x94\x80 View ";
    for (int i = 0; i < menuWidth - 9; i++) outputBuf_ += "\xe2\x94\x80";
    outputBuf_ += "\xe2\x94\x90";
    resetStyle();

    // Items
    struct { const char* label; bool checked; } items[] = {
        {"Header", showHeader_},
        {"Task pane", showTaskPane_.load()},
    };
    for (int i = 0; i < numItems; i++) {
        moveCursor(row + 1 + i, col);
        bool sel = (i == contextMenuSel_);
        if (sel) outputBuf_ += "\033[7m"; // inverse for selected
        setColor(sel ? COLOR_WHITE : COLOR_GRAY);
        outputBuf_ += "\xe2\x94\x82 "; // │
        if (items[i].checked) {
            setColor(COLOR_GREEN);
            outputBuf_ += "\xe2\x9c\x93"; // ✓
            if (sel) setColor(COLOR_WHITE); else setColor(COLOR_GRAY);
        } else {
            outputBuf_ += " ";
        }
        outputBuf_ += " ";
        setColor(sel ? COLOR_WHITE : theme_.headerFg);
        std::string label = items[i].label;
        outputBuf_ += label;
        int pad = menuWidth - 6 - (int)label.size();
        if (pad > 0) outputBuf_ += std::string(pad, ' ');
        outputBuf_ += " ";
        if (sel) setColor(COLOR_WHITE); else setColor(COLOR_GRAY);
        outputBuf_ += "\xe2\x94\x82"; // │
        resetStyle();
    }

    // Bottom border: └───────────────┘
    moveCursor(row + menuHeight - 1, col);
    setColor(COLOR_GRAY);
    outputBuf_ += "\xe2\x94\x94"; // └
    for (int i = 0; i < menuWidth - 2; i++) outputBuf_ += "\xe2\x94\x80";
    outputBuf_ += "\xe2\x94\x98"; // ┘
    resetStyle();
}

void Tui::renderCluster(int /*startRow*/, int /*height*/, int /*width*/) {
}

void Tui::renderMessages(int startRow, int height, int width) {
    std::unique_lock lk(messagesMu_, std::try_to_lock);
    if (!lk.owns_lock()) return;

    bool filterThinking = showTaskPane_.load();
    int msgCount = (int)messages_.size();

    // Rebuild cached display lines only when content or layout changed
    if (msgCount != cachedDisplayCount_ || width != cachedDisplayWidth_
        || filterThinking != cachedDisplayFilter_) {
        cachedDisplayLines_.clear();

        for (auto& msg : messages_) {
            if (filterThinking && msg.who == Message::AGENT && msg.agentType == AgentMessage::THINKING)
                continue;

            if (msg.who == Message::USER) {
                std::string text = msg.content;
                size_t pos = 0;
                while (pos < text.size()) {
                    size_t nl = text.find('\n', pos);
                    std::string line;
                    if (nl == std::string::npos) {
                        line = text.substr(pos);
                        pos = text.size();
                    } else {
                        line = text.substr(pos, nl - pos);
                        pos = nl + 1;
                    }
                    int wrapAt = std::max(1, width - 4);
                    while ((int)line.size() > wrapAt) {
                        cachedDisplayLines_.push_back({AgentMessage::THINKING, line.substr(0, wrapAt), msg.addedAtFrame, true});
                        line = line.substr(wrapAt);
                    }
                    cachedDisplayLines_.push_back({AgentMessage::THINKING, line, msg.addedAtFrame, true});
                }
            } else {
                AgentMessage am{msg.agentType, msg.content};
                auto wrapped = wrapMessage(am, std::max(1, width - 2));
                for (auto& dl : wrapped) {
                    dl.addedAtFrame = msg.addedAtFrame;
                    cachedDisplayLines_.push_back(dl);
                }
            }
            cachedDisplayLines_.push_back({AgentMessage::THINKING, "", msg.addedAtFrame});
        }

        cachedDisplayCount_ = msgCount;
        cachedDisplayWidth_ = width;
        cachedDisplayFilter_ = filterThinking;
    }

    // Auto-scroll to bottom (like Claude Code)
    int totalLines = (int)cachedDisplayLines_.size();
    int maxScroll = std::max(0, totalLines - height);
    scrollOffset_ = std::min(scrollOffset_, maxScroll);
    int visibleStart = std::max(0, maxScroll - scrollOffset_);

    for (int i = 0; i < height; i++) {
        int lineIdx = visibleStart + i;
        clearLine(startRow + i + 1, width);
        moveCursor(startRow + i + 1, 1);

        if (lineIdx >= 0 && lineIdx < totalLines) {
            auto& dl = cachedDisplayLines_[lineIdx];
            outputBuf_ += " ";

            if (dl.isUser) {
                setColor(COLOR_CYAN);
                setBold();
            } else switch (dl.type) {
                case AgentMessage::THINKING:
                    setColor(COLOR_GRAY);
                    break;
                case AgentMessage::SQL:
                    setColor(COLOR_GREEN);
                    break;
                case AgentMessage::RESULT:
                    setColor(COLOR_CYAN);
                    break;
                case AgentMessage::ANSWER:
                    setColor(COLOR_WHITE);
                    setBold();
                    break;
                case AgentMessage::ERROR:
                    setColor(COLOR_RED);
                    break;
            }

            std::string text = dl.text;
            if (width > 2 && (int)text.size() > width - 2) text = truncateUTF8(text, width - 2);
            outputBuf_ += text;
            resetStyle();
        }
    }
}

void Tui::renderTaskPane(int startRow, int height, int width) {
    if (height < 3) return; // need at least top border + 1 line + bottom border

    std::unique_lock lk(messagesMu_, std::try_to_lock);
    if (!lk.owns_lock()) return;

    std::vector<std::string> taskLines;
    for (auto& msg : messages_) {
        if (msg.who == Message::AGENT && msg.agentType == AgentMessage::THINKING && !msg.content.empty()) {
            // Split by newlines and wrap
            size_t pos = 0;
            int innerWidth = std::max(1, width - 4); // 2 border + 2 padding
            while (pos < msg.content.size()) {
                size_t nl = msg.content.find('\n', pos);
                std::string line;
                if (nl == std::string::npos) {
                    line = msg.content.substr(pos);
                    pos = msg.content.size();
                } else {
                    line = msg.content.substr(pos, nl - pos);
                    pos = nl + 1;
                }
                while ((int)line.size() > innerWidth) {
                    taskLines.push_back(line.substr(0, innerWidth));
                    line = line.substr(innerWidth);
                }
                taskLines.push_back(line);
            }
        }
    }

    int innerHeight = height - 2; // rows available for content
    int totalLines = (int)taskLines.size();
    int maxScroll = std::max(0, totalLines - innerHeight);
    taskScrollOffset_ = std::min(taskScrollOffset_, maxScroll);
    // Auto-scroll to bottom
    int visibleStart = std::max(0, totalLines - innerHeight);

    auto setYellow = [&]() {
        appendRGB(outputBuf_, 200, 160, 40);
    };

    // Top border: ╭─── task ───╮
    int row = startRow + 1;
    clearLine(row, width);
    moveCursor(row, 1);
    setYellow();
    outputBuf_ += " \xe2\x95\xad"; // ╭
    std::string title = " task ";
    int barWidth = width - 4; // 1 space + ╭ + ╮ + 1 space
    int leftBar = 2;
    int rightBar = barWidth - leftBar - (int)title.size();
    if (rightBar < 0) rightBar = 0;
    for (int i = 0; i < leftBar; i++) outputBuf_ += "\xe2\x94\x80"; // ─
    setBold();
    outputBuf_ += title;
    resetStyle();
    setYellow();
    for (int i = 0; i < rightBar; i++) outputBuf_ += "\xe2\x94\x80"; // ─
    outputBuf_ += "\xe2\x95\xae"; // ╮
    resetStyle();
    row++;

    // Content rows
    for (int i = 0; i < innerHeight; i++) {
        clearLine(row, width);
        moveCursor(row, 1);
        setYellow();
        outputBuf_ += " \xe2\x94\x82"; // │
        resetStyle();

        int lineIdx = visibleStart + i;
        if (lineIdx >= 0 && lineIdx < totalLines) {
            outputBuf_ += " ";
            setColor(COLOR_GRAY);
            std::string text = taskLines[lineIdx];
            int innerW = width - 5; // space + │ + space + ... + │ + space
            if ((int)text.size() > innerW) text = truncateUTF8(text, innerW);
            outputBuf_ += text;
            int pad = innerW - (int)text.size();
            if (pad > 0) outputBuf_ += std::string(pad, ' ');
            resetStyle();
        } else {
            int innerW = width - 4;
            outputBuf_ += std::string(innerW, ' ');
        }

        setYellow();
        outputBuf_ += "\xe2\x94\x82"; // │
        resetStyle();
        row++;
    }

    // Bottom border: ╰───╯
    clearLine(row, width);
    moveCursor(row, 1);
    setYellow();
    outputBuf_ += " \xe2\x95\xb0"; // ╰
    for (int i = 0; i < barWidth; i++) outputBuf_ += "\xe2\x94\x80"; // ─
    outputBuf_ += "\xe2\x95\xaf"; // ╯
    resetStyle();
}

void Tui::tabCompletePath() {
    // Tab completion for filesystem paths
    namespace fs = std::filesystem;

    std::string& path = confirmCustom_;
    if (path.empty()) path = "/";

    std::string dir, prefix;
    auto lastSlash = path.rfind('/');
    if (lastSlash != std::string::npos) {
        dir = path.substr(0, lastSlash + 1);
        prefix = path.substr(lastSlash + 1);
    } else {
        dir = ".";
        prefix = path;
    }

    std::vector<std::string> matches;
    try {
        if (!fs::exists(dir)) return;
        for (auto& entry : fs::directory_iterator(dir)) {
            std::string name = entry.path().filename().string();
            if (name.size() >= prefix.size() &&
                name.substr(0, prefix.size()) == prefix) {
                if (entry.is_directory())
                    matches.push_back(name + "/");
                else
                    matches.push_back(name);
            }
        }
    } catch (...) { return; }

    if (matches.empty()) return;

    std::sort(matches.begin(), matches.end());

    if (matches.size() == 1) {
        path = dir + matches[0];
    } else {
        // Complete to common prefix
        std::string common = matches[0];
        for (size_t i = 1; i < matches.size(); i++) {
            size_t j = 0;
            while (j < common.size() && j < matches[i].size() &&
                   common[j] == matches[i][j]) j++;
            common = common.substr(0, j);
        }
        if (common.size() > prefix.size()) {
            path = dir + common;
        }
    }
    confirmCursorPos_ = (int)path.size();
}

void Tui::handleCtrlC() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastCtrlC_).count();

    if (processing_) {
        // Second Ctrl-C within 2s while processing: force quit
        if (ctrlCPending_ && elapsed < 2000) {
            running_ = false;
            return;
        }

        // Only send interrupt once (guard against repeated Ctrl-C)
        if (!interruptSuppressing_) {
            sendToServer({{"type", "interrupt"}, {"chat_id", currentChatId_}});
            // Show (interrupted) immediately without waiting for server
            {
                std::lock_guard lk(messagesMu_);
                messages_.push_back({Message::AGENT, AgentMessage::ANSWER, "(interrupted)"});
                messagesDirty_ = true;
            }
            interruptShown_ = true;
            // Suppress in-flight messages from old query
            // but clear processing_ immediately so the user can type and
            // submit a new message without waiting for the server to
            // confirm the old query finished.
            interruptSuppressing_ = true;
            processing_ = false;
        }
        scrollOffset_ = 0;
        render();
    } else {
        // Not processing: double Ctrl-C to quit
        if (ctrlCPending_ && elapsed < 2000) {
            running_ = false;
            return;
        }
        // First Ctrl-C clears input (standard terminal behavior)
        inputBuffer_.clear();
        cursorPos_ = 0;
    }

    ctrlCPending_ = true;
    lastCtrlC_ = now;
}

void Tui::approveConfirm() {
    // Caller must hold confirmMu_
    sendToServer({{"type", "confirm_resp"}, {"chat_id", currentChatId_},
        {"req_id", confirmReqId_}, {"action", "approve"}});
    confirmPending_ = false;
    messagesDirty_ = true;
}

void Tui::denyConfirm() {
    // Caller must hold confirmMu_
    sendToServer({{"type", "confirm_resp"}, {"chat_id", currentChatId_},
        {"req_id", confirmReqId_}, {"action", "deny"}});
    confirmPending_ = false;
    messagesDirty_ = true;
}

void Tui::submitConfirmCustom() {
    // Caller must hold confirmMu_
    sendToServer({{"type", "confirm_resp"}, {"chat_id", currentChatId_},
        {"req_id", confirmReqId_}, {"action", "custom"}, {"text", confirmCustom_}});
    confirmPending_ = false;
    messagesDirty_ = true;
}

void Tui::renderConfirm(int row, int width) {
    std::lock_guard lk(confirmMu_);
    if (!confirmPending_) return;

    moveCursor(row, 1);
    outputBuf_ += "\033[2K";

    if (confirmIsPath_) {
        // Path input mode for SCAN
        setColor(COLOR_YELLOW);
        setBold();
        outputBuf_ += " scan path: ";
        resetStyle();
        setColor(COLOR_WHITE);
        int labelLen = 12;
        int available = width - labelLen - 1;
        std::string vis = confirmCustom_;
        if ((int)vis.size() > available) {
            int start = (int)vis.size() - available;
            vis = vis.substr(start);
        }
        outputBuf_ += vis;
        resetStyle();

        // Show cursor in path input
        outputBuf_ += "\033[?25h";
        int cursorCol = labelLen + 1 + std::min((int)confirmCustom_.size(), available);
        moveCursor(row, cursorCol);
    } else {
        // Standard Yes/No/Custom confirm
        setColor(COLOR_YELLOW);
        setBold();
        outputBuf_ += " \xe2\x96\xb6 "; // ▶
        resetStyle();
        setColor(COLOR_WHITE);
        std::string desc = confirmDescription_;
        if ((int)desc.size() > width - 20) desc = truncateUTF8(desc, width - 20) + "...";
        outputBuf_ += desc;
        resetStyle();

        int cursorCol = 3 + (int)desc.size() + 2;
        moveCursor(row, cursorCol);

        auto renderOpt = [&](int idx, const char* label) {
            if (confirmSelection_ == idx) {
                outputBuf_ += "\033[7m";
                setColor(COLOR_WHITE);
            } else {
                setColor(COLOR_GRAY);
            }
            outputBuf_ += " ";
            outputBuf_ += label;
            outputBuf_ += " ";
            resetStyle();
            outputBuf_ += " ";
        };

        renderOpt(0, "Yes");
        renderOpt(1, "No");
        renderOpt(2, "Tab:Custom");
        setColor(COLOR_GRAY);
        outputBuf_ += " y/n/esc";
        resetStyle();

        if (confirmSelection_ == 2 && !confirmCustom_.empty()) {
            setColor(COLOR_WHITE);
            outputBuf_ += confirmCustom_;
            resetStyle();
        }
    }
}

void Tui::renderInput(int row, int width) {
    // input line
    moveCursor(row, 1);
    outputBuf_ += "\033[2K";
    outputBuf_ += "  ";
    setColor(confirmPending_ ? COLOR_GRAY : COLOR_WHITE);

    // Compute right-side indicator: ^C hint > flash > thinking dots
    bool showCtrlCHint = false;
    std::string rightHint;
    if (ctrlCPending_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - lastCtrlC_).count();
        if (elapsed >= 2000) {
            ctrlCPending_ = false;
        } else {
            showCtrlCHint = true;
            rightHint = processing_ ? "^C to force quit" : "^C again to quit";
        }
    }
    if (!showCtrlCHint && !inputFlash_.empty()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - flashTime_).count();
        if (elapsed < 1500) {
            rightHint = inputFlash_;
        } else {
            inputFlash_.clear();
        }
    }

    int rightWidth = 0;
    if (!rightHint.empty()) rightWidth = (int)rightHint.size() + 1;
    else if (processing_) rightWidth = 8;

    int available = width - 3;
    int scrollStart = 0;
    if (cursorPos_ > available - rightWidth) {
        scrollStart = cursorPos_ - (available - rightWidth);
    }
    std::string visible = inputBuffer_.substr(scrollStart,
        std::min(available - rightWidth, (int)inputBuffer_.size() - scrollStart));
    outputBuf_ += visible;

    // Right-side indicator
    if (!rightHint.empty()) {
        int textEnd = 3 + static_cast<int>(visible.size());
        int hintStart = width - (int)rightHint.size() - 1;
        if (hintStart > textEnd) {
            outputBuf_ += std::string(hintStart - textEnd, ' ');
        }
        setColor(COLOR_GRAY);
        outputBuf_ += rightHint;
    } else if (processing_) {
        int textEnd = 3 + static_cast<int>(visible.size());
        int dotsStart = width - 7;
        if (dotsStart > textEnd) {
            outputBuf_ += std::string(dotsStart - textEnd, ' ');
        }
        for (int ci = 0; ci < 3; ci++) {
            double pulse = flowNoise(static_cast<double>(ci) * 2.5, static_cast<double>(animFrame_) * 0.3);
            double t = (pulse + 1.0) * 0.5;
            int r = 180 + static_cast<int>(t * 75);
            int g = 140 + static_cast<int>(t * 60);
            int b = 20 + static_cast<int>(t * 20);
            appendRGB(outputBuf_, r, g, b, true);
            outputBuf_ += (ci < 2) ? "\xe2\x97\x8f " : "\xe2\x97\x8f";
        }
    }
    resetStyle();

    renderWaveBar(row + 1, width);
    animFrame_++;

    // Position cursor (skip during confirm — renderConfirm owns cursor)
    if (!confirmPending_) {
        outputBuf_ += "\033[?25h";
        int cursorCol = 3 + (cursorPos_ - scrollStart);
        moveCursor(row, cursorCol);
    }
}

void Tui::renderWaveBar(int row, int width) {
    moveCursor(row, 1);
    auto& wBase = processing_ ? theme_.procBase : theme_.waveBase;
    auto& wAccent = processing_ ? theme_.procAccent : theme_.waveAccent;
    int waveLen = std::min(width, 30);
    int prevR = -1, prevG = -1, prevB = -1;
    for (int i = 0; i < width; i++) {
        int r, g, b;
        if (i < waveLen) {
            double env = (1.0 - static_cast<double>(i) / static_cast<double>(waveLen));
            env = env * env * (3.0 - 2.0 * env);
            double n = flowNoise(static_cast<double>(i), static_cast<double>(animFrame_));
            double wave = (n + 1.0) * 0.5 * env;
            r = wBase.r + static_cast<int>(wave * wAccent.r);
            g = wBase.g + static_cast<int>(wave * wAccent.g);
            b = wBase.b + static_cast<int>(wave * wAccent.b);
        } else {
            r = wBase.r; g = wBase.g; b = wBase.b;
        }
        if (r != prevR || g != prevG || b != prevB) {
            appendRGB(outputBuf_, r, g, b);
            prevR = r; prevG = g; prevB = b;
        }
        outputBuf_ += (i == 0) ? "\xe2\x94\x97" : "\xe2\x94\x81";
    }
    resetStyle();
}

void Tui::render() {
    outputBuf_ += "\033[?2026h"; // begin synchronized output
    outputBuf_ += "\033[?25l";  // hide cursor during render
    auto ts = getTermSize();
    bool showTP = showTaskPane_.load();
    if (!root_ || ts.rows != layoutRows_ || ts.cols != layoutCols_
        || showTP != layoutShowTaskPane_
        || layoutNeedsRebuild_) {
        buildLayout();
        layoutRows_ = ts.rows;
        layoutCols_ = ts.cols;
        layoutShowTaskPane_ = showTP;
        layoutNeedsRebuild_ = false;
    }

    int headerRow = (int)YGNodeLayoutGetTop(headerNode_);
    int headerWidth = (int)YGNodeLayoutGetWidth(headerNode_);

    int taskPaneRow = (int)YGNodeLayoutGetTop(taskPaneNode_);
    int taskPaneHeight = (int)YGNodeLayoutGetHeight(taskPaneNode_);
    int taskPaneWidth = (int)YGNodeLayoutGetWidth(taskPaneNode_);

    int contentRow = (int)YGNodeLayoutGetTop(contentNode_);
    int contentHeight = (int)YGNodeLayoutGetHeight(contentNode_);
    int contentWidth = (int)YGNodeLayoutGetWidth(contentNode_);

    int sepRow = (int)YGNodeLayoutGetTop(separatorNode_);
    int inputRow = (int)YGNodeLayoutGetTop(inputNode_);
    int inputWidth = (int)YGNodeLayoutGetWidth(inputNode_);

    int clusterRow = (int)YGNodeLayoutGetTop(clusterNode_);
    int clusterHeight = (int)YGNodeLayoutGetHeight(clusterNode_);
    int clusterWidth = (int)YGNodeLayoutGetWidth(clusterNode_);

    if (showHeader_) renderHeader(headerRow, headerWidth);
    if (taskPaneHeight > 0) {
        renderTaskPane(taskPaneRow, taskPaneHeight, taskPaneWidth);
    }
    renderMessages(contentRow, confirmPending_ ? contentHeight - 1 : contentHeight, contentWidth);
    if (confirmPending_) {
        renderConfirm(contentRow + contentHeight, contentWidth);
    }
    renderInput(sepRow + 1, inputWidth);
    renderContextMenu(ts.rows, ts.cols);

    outputBuf_ += "\033[?2026l"; // end synchronized output
    flush();
}

void Tui::renderInputOnly() {
    outputBuf_ += "\033[?2026h";
    auto ts = getTermSize();
    if (!root_ || ts.rows != layoutRows_ || ts.cols != layoutCols_) {
        render(); // size changed, do full render instead
        return;
    }
    int sepRow = (int)YGNodeLayoutGetTop(separatorNode_);
    int inputWidth = (int)YGNodeLayoutGetWidth(inputNode_);
    renderInput(sepRow + 1, inputWidth);
    outputBuf_ += "\033[?2026l";
    flush();
}

// ── Shared input helpers ──────────────────────────────────────────────

Tui::MouseEvent Tui::readSGRMouse() {
    char buf[32];
    int bi = 0;
    while (bi < 31) {
        if (read(STDIN_FILENO, &buf[bi], 1) <= 0) break;
        if (buf[bi] == 'M' || buf[bi] == 'm') { bi++; break; }
        bi++;
    }
    buf[bi] = 0;
    MouseEvent ev{};
    ev.press = (bi > 0 && buf[bi - 1] == 'M');
    sscanf(buf, "%d;%d;%d", &ev.button, &ev.x, &ev.y);
    return ev;
}

void Tui::toggleContextMenuItem(int item) {
    if (item == 0) { showHeader_ = !showHeader_; layoutNeedsRebuild_ = true; }
    else if (item == 1) { showTaskPane_.store(!showTaskPane_.load()); layoutNeedsRebuild_ = true; }
}

// ── Context menu input ───────────────────────────────────────────────

bool Tui::handleContextMenuInput(char c) {
    const int numItems = 2;

    if (c == 27) {
        struct pollfd ep = {STDIN_FILENO, POLLIN, 0};
        if (poll(&ep, 1, 30) > 0 && (ep.revents & POLLIN)) {
            char seq0;
            if (read(STDIN_FILENO, &seq0, 1) <= 0) { contextMenuOpen_ = false; return false; }
            if (seq0 == '[') {
                char seq1;
                if (read(STDIN_FILENO, &seq1, 1) <= 0) { contextMenuOpen_ = false; return false; }
                if (seq1 == 'A') { if (contextMenuSel_ > 0) contextMenuSel_--; return true; }
                if (seq1 == 'B') { if (contextMenuSel_ < numItems - 1) contextMenuSel_++; return true; }
                if (seq1 == '<') {
                    auto mouse = readSGRMouse();
                    if (mouse.button == 2 && mouse.press) {
                        contextMenuRow_ = mouse.y; contextMenuCol_ = mouse.x;
                        contextMenuSel_ = 0;
                        return true;
                    }
                    if (mouse.button == 0 && mouse.press) {
                        auto ts = getTermSize();
                        const int menuWidth = 17, menuHeight = numItems + 2;
                        int mr = std::clamp(contextMenuRow_, 1, std::max(1, ts.rows - menuHeight + 1));
                        int mc = std::clamp(contextMenuCol_, 1, std::max(1, ts.cols - menuWidth + 1));
                        if (mouse.y >= mr + 1 && mouse.y <= mr + numItems && mouse.x >= mc && mouse.x < mc + menuWidth) {
                            toggleContextMenuItem(mouse.y - mr - 1);
                        }
                        contextMenuOpen_ = false;
                        return true;
                    }
                    if (mouse.button == 64) { scrollOffset_ += 3; contextMenuOpen_ = false; return true; }
                    if (mouse.button == 65) { scrollOffset_ = std::max(0, scrollOffset_ - 3); contextMenuOpen_ = false; return true; }
                    return true;
                }
                if (seq1 == '5' || seq1 == '6') { char t; if (read(STDIN_FILENO, &t, 1)) {} }
            }
            contextMenuOpen_ = false;
            return true;
        }
        contextMenuOpen_ = false;
        return true;
    }

    if (c == 13 || c == 10) {
        toggleContextMenuItem(contextMenuSel_);
        contextMenuOpen_ = false;
        return true;
    }

    contextMenuOpen_ = false;
    return true;
}

// ── Escape sequence handling ─────────────────────────────────────────

bool Tui::handleEscapeSequence() {
    char seq[2];
    if (read(STDIN_FILENO, &seq[0], 1) <= 0) return false;
    if (read(STDIN_FILENO, &seq[1], 1) <= 0) return false;

    if (seq[0] != '[') return true;

    if (seq[1] == '<') {
        auto mouse = readSGRMouse();
        if (mouse.button == 2 && mouse.press) {
            contextMenuOpen_ = true;
            contextMenuRow_ = mouse.y;
            contextMenuCol_ = mouse.x;
            contextMenuSel_ = 0;
            return true;
        }
        if (mouse.button == 64) { scrollOffset_ += 3; return true; }
        if (mouse.button == 65) { scrollOffset_ = std::max(0, scrollOffset_ - 3); return true; }
        return true;
    }

    if (seq[1] == '5') {
        char tilde; if (read(STDIN_FILENO, &tilde, 1) < 0) return true;
        scrollOffset_ += 15;
        return true;
    }
    if (seq[1] == '6') {
        char tilde; if (read(STDIN_FILENO, &tilde, 1) < 0) return true;
        scrollOffset_ = std::max(0, scrollOffset_ - 15);
        return true;
    }

    if (seq[1] == 'A') { // Up - history previous
        if (!history_.empty()) {
            if (historyIdx_ == -1) {
                savedInput_ = inputBuffer_;
                historyIdx_ = (int)history_.size() - 1;
            } else if (historyIdx_ > 0) {
                historyIdx_--;
            }
            inputBuffer_ = history_[historyIdx_];
            cursorPos_ = (int)inputBuffer_.size();
        }
    } else if (seq[1] == 'B') { // Down - history next
        if (historyIdx_ != -1) {
            if (historyIdx_ < (int)history_.size() - 1) {
                historyIdx_++;
                inputBuffer_ = history_[historyIdx_];
            } else {
                historyIdx_ = -1;
                inputBuffer_ = savedInput_;
                savedInput_.clear();
            }
            cursorPos_ = (int)inputBuffer_.size();
        }
    } else if (seq[1] == 'C') { // Right
        if (cursorPos_ < (int)inputBuffer_.size()) cursorPos_++;
    } else if (seq[1] == 'D') { // Left
        if (cursorPos_ > 0) cursorPos_--;
    }

    return true;
}

// ── Main input dispatcher ────────────────────────────────────────────

bool Tui::handleInput() {
    char c;
    if (read(STDIN_FILENO, &c, 1) <= 0) return false;

    if (contextMenuOpen_) return handleContextMenuInput(c);

    if (c == 3) { handleCtrlC(); return true; }

    ctrlCPending_ = false;

    if (c == 13 || c == 10) {
        if (!inputBuffer_.empty()) submit();
        return true;
    }
    if (c == 127 || c == 8) {
        if (cursorPos_ > 0) { inputBuffer_.erase(cursorPos_ - 1, 1); cursorPos_--; }
        return true;
    }
    if (c == 1)  { cursorPos_ = 0; return true; }                        // Ctrl+A
    if (c == 5)  { cursorPos_ = (int)inputBuffer_.size(); return true; }  // Ctrl+E
    if (c == 21) { inputBuffer_.erase(0, cursorPos_); cursorPos_ = 0; return true; }  // Ctrl+U
    if (c == 11) { inputBuffer_.erase(cursorPos_); return true; }         // Ctrl+K
    if (c == 23) { // Ctrl+W
        if (cursorPos_ > 0) {
            int end = cursorPos_;
            while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] == ' ') cursorPos_--;
            while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] != ' ') cursorPos_--;
            inputBuffer_.erase(cursorPos_, end - cursorPos_);
        }
        return true;
    }
    if (c == 12) { outputBuf_ += "\033[2J"; return true; }  // Ctrl+L
    if (c == 2) { // Ctrl+B - toggle mouse mode
        if (mouseMode_) {
            disableMouseTracking();
            inputFlash_ = "mouse off - select text to copy";
        } else {
            enableMouseTracking();
            inputFlash_ = "mouse on - scroll wheel + right-click";
        }
        flashTime_ = std::chrono::steady_clock::now();
        flush();
        return true;
    }
    if (c == 27) return handleEscapeSequence();

    if (c >= 32 && c < 127) {
        inputBuffer_.insert(inputBuffer_.begin() + cursorPos_, c);
        cursorPos_++;
        return true;
    }

    // UTF-8 multi-byte sequence: lead byte >= 0xC0
    if ((unsigned char)c >= 0xC0) {
        std::string mb(1, c);
        int expect = ((unsigned char)c >= 0xF0) ? 3 : ((unsigned char)c >= 0xE0) ? 2 : 1;
        for (int i = 0; i < expect; i++) {
            char cb;
            if (read(STDIN_FILENO, &cb, 1) <= 0) break;
            mb += cb;
        }
        inputBuffer_.insert(cursorPos_, mb);
        cursorPos_ += (int)mb.size();
        return true;
    }

    return false;
}


void Tui::sendToServer(const nlohmann::json& msg) {
    ipc::sendLine(sockFd_, msg);
}

using area::tui::parseAgentType;

void Tui::handleServerMessage(const nlohmann::json& msg) {
    std::string type = msg.value("type", "");

    if (type == "agent_msg") {
        // After local interrupt, suppress all in-flight messages from old query
        if (interruptSuppressing_) return;
        auto m = msg["msg"];
        std::string typeStr = m.value("type", "answer");
        std::string content = m.value("content", "");
        std::lock_guard lk(messagesMu_);
        messages_.push_back({Message::AGENT, parseAgentType(typeStr), content, static_cast<int>(animFrame_.load())});
        messagesDirty_ = true;
        scrollOffset_ = 0;

    } else if (type == "history") {
        std::lock_guard lk(messagesMu_);
        messages_.clear();
        for (auto& m : msg["messages"]) {
            Message dm;
            dm.who = (m.value("who", "") == "user") ? Message::USER : Message::AGENT;
            dm.agentType = parseAgentType(m.value("type", "answer"));
            dm.content = m.value("content", "");
            messages_.push_back(std::move(dm));
        }
        messagesDirty_ = true;

    } else if (type == "state") {
        bool proc = msg.value("processing", false);
        if (!proc && interruptSuppressing_) {
            interruptSuppressing_ = false;
            interruptShown_ = false;
        }
        processing_ = proc;
        if (msg.contains("dangerous")) dangerousMode_ = msg["dangerous"].get<bool>();
        if (msg.contains("context_tokens")) contextTokens_ = msg["context_tokens"].get<int>();
        if (msg.contains("context_window")) contextWindow_ = msg["context_window"].get<int>();
        messagesDirty_ = true;

    } else if (type == "confirm_req") {
        confirmReqId_ = msg.value("req_id", 0);
        confirmDescription_ = msg.value("description", "");
        confirmIsPath_ = msg.value("is_path", false);
        confirmSelection_ = 0;
        confirmCustom_.clear();
        confirmCursorPos_ = 0;
        if (confirmIsPath_) {
            auto pathStart = confirmDescription_.find(' ');
            if (pathStart != std::string::npos) {
                confirmCustom_ = confirmDescription_.substr(pathStart + 1);
                if (confirmCustom_.find(' ') != std::string::npos)
                    confirmCustom_ = confirmCustom_.substr(0, confirmCustom_.rfind(' '));
            }
            confirmCursorPos_ = (int)confirmCustom_.size();
        }
        confirmPending_ = true;
        messagesDirty_ = true;

    } else if (type == "tui_control") {
        // Reserved for future tui_control actions

    } else if (type == "chat_list") {
        // TODO: store for /attach tab completion
    }
}

void Tui::submit() {
    std::string query = inputBuffer_;

    // Handle /clear — wipe context (must work even while processing)
    if (query == "/clear") {
        sendToServer({{"type", "clear_context"}, {"chat_id", currentChatId_}});
        processing_ = false;
        interruptSuppressing_ = false;
        interruptShown_ = false;
        {
            std::lock_guard lk(messagesMu_);
            messages_.clear();
            messagesDirty_ = true;
            scrollOffset_ = 0;
        }
        inputBuffer_.clear();
        cursorPos_ = 0;
        return;
    }

    if (processing_) {
        inputFlash_ = "^C to interrupt";
        flashTime_ = std::chrono::steady_clock::now();
        return;
    }

    // Handle /dangerous toggle
    if (query == "/dangerous") {
        dangerousMode_ = !dangerousMode_.load();
        if (sockFd_ >= 0) {
            sendToServer({{"type", "set_dangerous"}, {"chat_id", currentChatId_}, {"enabled", dangerousMode_.load()}});
        }
        std::lock_guard lk(messagesMu_);
        messages_.push_back({Message::AGENT, AgentMessage::RESULT,
            dangerousMode_ ? "Dangerous mode ON — tool calls auto-approved"
                           : "Dangerous mode OFF — tool calls require confirmation",
            static_cast<int>(animFrame_.load())});
        messagesDirty_ = true;
        inputBuffer_.clear();
        cursorPos_ = 0;
        return;
    }

    // Handle /task toggle (removed — task pane is right-click only now)

    history_.push_back(query);
    historyIdx_ = -1;
    savedInput_.clear();
    inputBuffer_.clear();
    cursorPos_ = 0;
    scrollOffset_ = 0;

    {
        std::lock_guard lk(messagesMu_);
        messages_.push_back({Message::USER, AgentMessage::THINKING, query, static_cast<int>(animFrame_.load())});
    }
    render();

    interruptShown_ = false;
    interruptSuppressing_ = false;

    processing_ = true;
    sendToServer({{"type", "user_input"}, {"chat_id", currentChatId_}, {"content", query}});
}

// ── Event loop helpers ───────────────────────────────────────────────

void Tui::setupSignals() {
    struct sigaction sa;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = handleWinch;
    sigaction(SIGWINCH, &sa, nullptr);
    sa.sa_handler = handleInt;
    sigaction(SIGINT, &sa, nullptr);
}

void Tui::handleConfirmInput() {
    char c;
    while (read(STDIN_FILENO, &c, 1) > 0) {
        std::lock_guard clk(confirmMu_);
        if (!confirmPending_) break;

        if (c == 3) { denyConfirm(); break; }

        if (c == 27) {
            struct pollfd ep = {STDIN_FILENO, POLLIN, 0};
            if (poll(&ep, 1, 30) > 0 && (ep.revents & POLLIN)) {
                char seq0;
                if (read(STDIN_FILENO, &seq0, 1) <= 0) break;
                if (seq0 == '[') {
                    char seq1;
                    if (read(STDIN_FILENO, &seq1, 1) <= 0) break;
                    if (!confirmIsPath_) {
                        if (seq1 == 'C') confirmSelection_ = std::min(2, confirmSelection_ + 1);
                        else if (seq1 == 'D') confirmSelection_ = std::max(0, confirmSelection_ - 1);
                    }
                    if (seq1 == '<') readSGRMouse(); // consume
                    if (seq1 == '5' || seq1 == '6') {
                        char tilde;
                        if (read(STDIN_FILENO, &tilde, 1) < 0) break;
                    }
                }
            } else {
                denyConfirm();
                break;
            }
            continue;
        }

        if (confirmIsPath_) {
            if (c == 9) { tabCompletePath(); }
            else if (c == 13 || c == 10) { submitConfirmCustom(); break; }
            else if (c == 127 || c == 8) {
                if (!confirmCustom_.empty()) {
                    confirmCustom_.pop_back();
                    confirmCursorPos_ = (int)confirmCustom_.size();
                }
            }
            else if (c >= 32 && c < 127) {
                confirmCustom_ += c;
                confirmCursorPos_ = (int)confirmCustom_.size();
            }
        } else {
            if ((c == 'y' || c == 'Y') && confirmSelection_ != 2) { approveConfirm(); break; }
            else if ((c == 'n' || c == 'N') && confirmSelection_ != 2) { denyConfirm(); break; }
            else if (c == 9) { confirmSelection_ = 2; }
            else if (c == 13 || c == 10) {
                if (confirmSelection_ == 0) { approveConfirm(); break; }
                else if (confirmSelection_ == 1) { denyConfirm(); break; }
                else { submitConfirmCustom(); break; }
            }
            else if (c == 127 || c == 8) {
                if (confirmSelection_ == 2 && !confirmCustom_.empty())
                    confirmCustom_.pop_back();
            }
            else if (c >= 32 && c < 127 && confirmSelection_ == 2) {
                confirmCustom_ += c;
            }
        }
    }
}

bool Tui::readServerMessages() {
    while (auto msg = ipc::readLine(sockFd_)) {
        handleServerMessage(*msg);
    }
    char peek;
    if (recv(sockFd_, &peek, 1, MSG_PEEK | MSG_DONTWAIT) == 0) {
        return false; // disconnected
    }
    return true;
}

void Tui::processStdin(bool& needsRender, bool& inputChanged) {
    if (confirmPending_) {
        contextMenuOpen_ = false;
        handleConfirmInput();
        needsRender = true;
    } else {
        bool menuWasOpen = contextMenuOpen_;
        int prevScroll = scrollOffset_;
        while (handleInput()) {}
        if (scrollOffset_ != prevScroll || menuWasOpen != contextMenuOpen_) {
            needsRender = true;
        } else {
            inputChanged = true;
        }
    }
}

void Tui::renderWaveBarOnly() {
    outputBuf_ += "\033[?2026h";
    auto ts = getTermSize();
    renderWaveBar(ts.rows, ts.cols);
    if (!confirmPending_) {
        int available = ts.cols - 3;
        int scrollStart = 0;
        if (cursorPos_ > available) scrollStart = cursorPos_ - available;
        moveCursor(ts.rows - 1, 3 + (cursorPos_ - scrollStart));
        outputBuf_ += "\033[?25h";
    }
    outputBuf_ += "\033[?2026l";
    flush();
    animFrame_++;
}

void Tui::updateDisplay(bool fullRender, bool inputChanged) {
    bool fading = (animFrame_ - fadeStartFrame_) < 35;
    if (fullRender || fading || contextMenuOpen_) {
        render();
    } else if (inputChanged || processing_) {
        renderInputOnly();
    } else {
        renderWaveBarOnly();
    }
}

// ── Main event loop ──────────────────────────────────────────────────

void Tui::run() {
    setupSignals();
    enterAltScreen();
    enableRawMode();
    running_ = true;

    sendToServer({{"type", "attach"}, {"chat_id", currentChatId_}});
    render();

    bool needsRender = false;
    while (running_) {
        // Adaptive frame rate: 60fps during fade/confirm, 30fps processing, ~15fps idle
        bool fading = (animFrame_ - fadeStartFrame_) < 35;
        int pollMs = (fading || confirmPending_) ? 16 : processing_ ? 33 : 64;

        struct pollfd pfds[2];
        pfds[0] = {STDIN_FILENO, POLLIN, 0};
        pfds[1] = {sockFd_, POLLIN, 0};
        poll(pfds, 2, pollMs);

        if (g_interrupted) { g_interrupted = 0; break; }
        if (g_resized)     { g_resized = 0; needsRender = true; }

        bool inputChanged = false;
        if (pfds[0].revents & POLLIN) processStdin(needsRender, inputChanged);
        if (pfds[1].revents & POLLIN) { if (!readServerMessages()) break; }

        if (messagesDirty_.exchange(false)) {
            needsRender = true;
            fadeStartFrame_ = animFrame_;
            if (showTaskPane_) layoutNeedsRebuild_ = true;
        }

        updateDisplay(needsRender, inputChanged);
        needsRender = false;
    }

    disableRawMode();
    exitAltScreen();
}

} // namespace area
