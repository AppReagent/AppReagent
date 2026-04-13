#include "features/frontend/tui/Tui.h"

#include <bits/termios-c_cc.h>
#include <bits/termios-c_cflag.h>
#include <bits/termios-c_iflag.h>
#include <bits/types/sig_atomic_t.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <map>
#include <optional>
#include <utility>

#include <nlohmann/json.hpp>

#include "features/frontend/tui/tui_util.h"
#include "infra/ipc/IPC.h"
#include "nlohmann/detail/iterators/iter_impl.hpp"
#include "nlohmann/detail/json_ref.hpp"
#include "util/string_util.h"
#include "yoga/YGEnums.h"
#include "yoga/YGNodeLayout.h"
#include "yoga/YGNodeStyle.h"
namespace area {
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
    {62, 50, 76},
    {70, 18, 84},
    {255, 255, 255},
    {-255, -255, -255},
    {60, 50, 20},
    {140, 100, 0},
    COLOR_WHITE,
    COLOR_WHITE,
};

static const CT lightTheme = {
    {180, 170, 200},
    {60, 20, 80},
    {60, 40, 80},
    {80, 30, 90},
    {180, 160, 60},
    {80, 60, 0},
    COLOR_BLACK,
    COLOR_BLACK,
};

static RGB pulseColor(const CT& th, int x, int y, int frame, double intensity) {
    double n = noise2d(static_cast<double>(x), static_cast<double>(y), static_cast<double>(frame));
    double t = n * intensity;

    return {
        std::clamp(((th.pulseBase.r + static_cast<int>(t * th.pulseShift.r)) >> 3) << 3, 0, 255),
        std::clamp(((th.pulseBase.g + static_cast<int>(t * th.pulseShift.g)) >> 3) << 3, 0, 255),
        std::clamp(((th.pulseBase.b + static_cast<int>(t * th.pulseShift.b)) >> 3) << 3, 0, 255)
    };
}

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

void Tui::renderMarkdownLine(const std::string& text, int baseColor) {
    auto spans = area::tui::parseMarkdownSpans(text);
    for (auto& span : spans) {
        switch (span.style) {
            case tui::MarkdownSpan::BOLD:
                setBold();
                setColor(baseColor);
                break;
            case tui::MarkdownSpan::CODE:
                setColor(COLOR_YELLOW);
                break;
            case tui::MarkdownSpan::NORMAL:
                resetStyle();
                setColor(baseColor);
                break;
        }
        outputBuf_ += span.text;
    }
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
    outputBuf_ += "\033[?1000h";
    outputBuf_ += "\033[?1006h";
    mouseMode_ = true;
}

void Tui::disableMouseTracking() {
    outputBuf_ += "\033[?1006l";
    outputBuf_ += "\033[?1000l";
    mouseMode_ = false;
}

void Tui::enterAltScreen() {
    outputBuf_ += "\033[?1049h";
    outputBuf_ += "\033[?25l";
    enableMouseTracking();
    flush();
}

void Tui::exitAltScreen() {
    if (mouseMode_) disableMouseTracking();
    outputBuf_ += "\033[?25h";
    outputBuf_ += "\033[?1049l";
    flush();
}

void Tui::buildLayout() {
    freeLayout();

    auto ts = getTermSize();

    root_ = YGNodeNew();
    YGNodeStyleSetFlexDirection(root_, YGFlexDirectionColumn);
    YGNodeStyleSetWidth(root_, static_cast<float>(ts.cols));
    YGNodeStyleSetHeight(root_, static_cast<float>(ts.rows));

    int idx = 0;

    headerNode_ = YGNodeNew();
    YGNodeStyleSetHeight(headerNode_, showHeader_ ? 1.0f : 0.0f);
    YGNodeInsertChild(root_, headerNode_, idx++);

    clusterNode_ = YGNodeNew();
    YGNodeStyleSetHeight(clusterNode_, 0.0f);
    YGNodeInsertChild(root_, clusterNode_, idx++);

    int taskPaneHeight = 0;
    if (showTaskPane_) {
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
            taskPaneHeight = std::clamp(thinkingCount + 2, 4, 8);
        else
            taskPaneHeight = 4;
    }
    taskPaneNode_ = YGNodeNew();
    YGNodeStyleSetHeight(taskPaneNode_, static_cast<float>(taskPaneHeight));
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

    waveBarNode_ = YGNodeNew();
    YGNodeStyleSetHeight(waveBarNode_, 1);
    YGNodeInsertChild(root_, waveBarNode_, idx++);

    YGNodeCalculateLayout(root_, static_cast<float>(ts.cols), static_cast<float>(ts.rows), YGDirectionLTR);
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
        waveBarNode_ = nullptr;
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
    bool inCodeBlock = false;

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

        // Detect code block fences
        bool isHeading = false;
        if (line.size() >= 3 && line.substr(0, 3) == "```") {
            inCodeBlock = !inCodeBlock;
        }

        // Detect headings (only outside code blocks)
        if (!inCodeBlock && !line.empty() && line[0] == '#') {
            isHeading = true;
        }

        if (width > 0) {
            while (static_cast<int>(line.size()) > width) {
                int bp = std::min(width, static_cast<int>(line.size()) - 1);
                if (!inCodeBlock) {
                    while (bp > 0 && line[bp] != ' ') bp--;
                }
                if (bp == 0) bp = std::min(width, static_cast<int>(line.size()));
                DisplayLine dl{msg.type, line.substr(0, bp)};
                dl.isCodeBlock = inCodeBlock;
                dl.isHeading = isHeading;
                lines.push_back(dl);
                line = line.substr(bp);
                if (!line.empty() && line[0] == ' ') line.erase(0, 1);
                isHeading = false;
            }
        }
        DisplayLine dl{msg.type, line};
        dl.isCodeBlock = inCodeBlock;
        dl.isHeading = isHeading;
        lines.push_back(dl);
    }
    return lines;
}

void Tui::renderHeader(int row, int width) {
    moveCursor(row + 1, 1);
    setColor(COLOR_WHITE);
    setBold();

    outputBuf_ += "\033[7m";
    std::string title = " App Reagent (aREa) ";
    std::string header = title;

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

    int rightPad = width - static_cast<int>(header.size()) - static_cast<int>(ctxLabel.size()) - 1;
    outputBuf_ += header;
    if (rightPad > 0) {
        outputBuf_ += std::string(rightPad, ' ');
    }

    if (pct >= 90) {
        outputBuf_ += "\033[31m";
    } else if (pct >= 70) {
        outputBuf_ += "\033[33m";
    }
    outputBuf_ += ctxLabel + " ";
    outputBuf_ += "\033[7m";
    resetStyle();
}

void Tui::renderContextMenu(int screenRows, int screenCols) {
    if (!contextMenuOpen_) return;

    const int numItems = 2;
    const int menuWidth = 17;
    const int menuHeight = numItems + 2;

    int row = std::clamp(contextMenuRow_, 1, std::max(1, screenRows - menuHeight + 1));
    int col = std::clamp(contextMenuCol_, 1, std::max(1, screenCols - menuWidth + 1));

    moveCursor(row, col);
    setColor(COLOR_GRAY);
    outputBuf_ += "\xe2\x94\x8c\xe2\x94\x80 View ";
    for (int i = 0; i < menuWidth - 9; i++) outputBuf_ += "\xe2\x94\x80";
    outputBuf_ += "\xe2\x94\x90";
    resetStyle();

    struct { const char* label; bool checked; } items[] = {
        {"Header", showHeader_},
        {"Task pane", showTaskPane_.load()},
    };
    for (int i = 0; i < numItems; i++) {
        moveCursor(row + 1 + i, col);
        bool sel = (i == contextMenuSel_);
        if (sel) outputBuf_ += "\033[7m";
        setColor(sel ? COLOR_WHITE : COLOR_GRAY);
        outputBuf_ += "\xe2\x94\x82 ";
        if (items[i].checked) {
            setColor(COLOR_GREEN);
            outputBuf_ += "\xe2\x9c\x93";
            if (sel) {
                setColor(COLOR_WHITE);
            } else {
                setColor(COLOR_GRAY);
            }
        } else {
            outputBuf_ += " ";
        }
        outputBuf_ += " ";
        setColor(sel ? COLOR_WHITE : theme_.headerFg);
        std::string label = items[i].label;
        outputBuf_ += label;
        int pad = menuWidth - 6 - static_cast<int>(label.size());
        if (pad > 0) outputBuf_ += std::string(pad, ' ');
        outputBuf_ += " ";
        if (sel) {
            setColor(COLOR_WHITE);
        } else {
            setColor(COLOR_GRAY);
        }
        outputBuf_ += "\xe2\x94\x82";
        resetStyle();
    }

    moveCursor(row + menuHeight - 1, col);
    setColor(COLOR_GRAY);
    outputBuf_ += "\xe2\x94\x94";
    for (int i = 0; i < menuWidth - 2; i++) outputBuf_ += "\xe2\x94\x80";
    outputBuf_ += "\xe2\x94\x98";
    resetStyle();
}

void Tui::renderCluster(int  , int  , int  ) {
}

void Tui::renderMessages(int startRow, int height, int width) {
    std::unique_lock lk(messagesMu_, std::try_to_lock);
    if (!lk.owns_lock()) return;

    bool filterThinking = showTaskPane_.load();
    int msgCount = static_cast<int>(messages_.size());

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
                    while (static_cast<int>(line.size()) > wrapAt) {
                        cachedDisplayLines_.push_back(
                            {AgentMessage::THINKING, line.substr(0, wrapAt), msg.addedAtFrame, true});
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

    int totalLines = static_cast<int>(cachedDisplayLines_.size());
    int maxScroll = std::max(0, totalLines - height);
    scrollOffset_ = std::min(scrollOffset_, maxScroll);
    int visibleStart = std::max(0, maxScroll - scrollOffset_);

    // Scrollbar: compute thumb position and size
    bool showScrollbar = totalLines > height && height >= 3;
    int thumbStart = 0, thumbLen = 1;
    if (showScrollbar) {
        thumbLen = std::max(1, height * height / totalLines);
        int scrollRange = height - thumbLen;
        int scrollPos = maxScroll > 0 ? (maxScroll - scrollOffset_) * scrollRange / maxScroll : 0;
        thumbStart = scrollPos;
    }

    int textWidth = showScrollbar ? width - 2 : width - 1;

    for (int i = 0; i < height; i++) {
        int lineIdx = visibleStart + i;
        clearLine(startRow + i + 1, width);
        moveCursor(startRow + i + 1, 1);

        if (lineIdx >= 0 && lineIdx < totalLines) {
            auto& dl = cachedDisplayLines_[lineIdx];
            outputBuf_ += " ";

            int baseColor = COLOR_WHITE;
            if (dl.isUser) {
                setColor(COLOR_CYAN);
                setBold();
                baseColor = COLOR_CYAN;
            } else if (dl.isCodeBlock) {
                setColor(COLOR_YELLOW);
                baseColor = COLOR_YELLOW;
            } else if (dl.isHeading) {
                setColor(COLOR_MAGENTA);
                setBold();
                baseColor = COLOR_MAGENTA;
            } else {
                switch (dl.type) {
                    case AgentMessage::THINKING:
                        setColor(COLOR_GRAY);
                        baseColor = COLOR_GRAY;
                        break;
                    case AgentMessage::SQL:
                        setColor(COLOR_GREEN);
                        baseColor = COLOR_GREEN;
                        break;
                    case AgentMessage::RESULT:
                        setColor(COLOR_CYAN);
                        baseColor = COLOR_CYAN;
                        break;
                    case AgentMessage::ANSWER:
                        setColor(COLOR_WHITE);
                        setBold();
                        baseColor = COLOR_WHITE;
                        break;
                    case AgentMessage::ERROR:
                        setColor(COLOR_RED);
                        baseColor = COLOR_RED;
                        break;
                }
            }

            std::string text = dl.text;
            if (textWidth > 1 && static_cast<int>(text.size()) > textWidth)
                text = truncateUTF8(text, textWidth);

            // Use markdown rendering for answer-type agent messages
            if (!dl.isUser && dl.type == AgentMessage::ANSWER
                && !dl.isCodeBlock && !dl.isHeading) {
                renderMarkdownLine(text, baseColor);
            } else {
                outputBuf_ += text;
            }
            resetStyle();
        }

        if (showScrollbar) {
            moveCursor(startRow + i + 1, width);
            if (i >= thumbStart && i < thumbStart + thumbLen) {
                setColor(COLOR_WHITE);
                outputBuf_ += "\xe2\x94\x83";  // ┃ (thick vertical)
            } else {
                setColor(COLOR_GRAY);
                outputBuf_ += "\xe2\x94\x82";  // │ (thin vertical)
            }
            resetStyle();
        }
    }
}

void Tui::renderTaskPane(int startRow, int height, int width) {
    if (height < 3) return;

    std::unique_lock lk(messagesMu_, std::try_to_lock);
    if (!lk.owns_lock()) return;

    std::vector<std::string> taskLines;
    for (auto& msg : messages_) {
        if (msg.who == Message::AGENT && msg.agentType == AgentMessage::THINKING && !msg.content.empty()) {
            size_t pos = 0;
            int innerWidth = std::max(1, width - 4);
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
                while (static_cast<int>(line.size()) > innerWidth) {
                    taskLines.push_back(line.substr(0, innerWidth));
                    line = line.substr(innerWidth);
                }
                taskLines.push_back(line);
            }
        }
    }

    int innerHeight = height - 2;
    int totalLines = static_cast<int>(taskLines.size());
    int maxScroll = std::max(0, totalLines - innerHeight);
    taskScrollOffset_ = std::min(taskScrollOffset_, maxScroll);

    int visibleStart = std::max(0, totalLines - innerHeight);

    auto setYellow = [&]() {
        appendRGB(outputBuf_, 200, 160, 40);
    };

    int row = startRow + 1;
    clearLine(row, width);
    moveCursor(row, 1);
    setYellow();
    outputBuf_ += " \xe2\x95\xad";
    std::string title = " task ";
    int barWidth = width - 4;
    int leftBar = 2;
    int rightBar = barWidth - leftBar - static_cast<int>(title.size());
    if (rightBar < 0) rightBar = 0;
    for (int i = 0; i < leftBar; i++) outputBuf_ += "\xe2\x94\x80";
    setBold();
    outputBuf_ += title;
    resetStyle();
    setYellow();
    for (int i = 0; i < rightBar; i++) outputBuf_ += "\xe2\x94\x80";
    outputBuf_ += "\xe2\x95\xae";
    resetStyle();
    row++;

    for (int i = 0; i < innerHeight; i++) {
        clearLine(row, width);
        moveCursor(row, 1);
        setYellow();
        outputBuf_ += " \xe2\x94\x82";
        resetStyle();

        int lineIdx = visibleStart + i;
        if (lineIdx >= 0 && lineIdx < totalLines) {
            outputBuf_ += " ";
            setColor(COLOR_GRAY);
            std::string text = taskLines[lineIdx];
            int innerW = width - 5;
            if (static_cast<int>(text.size()) > innerW) text = truncateUTF8(text, innerW);
            outputBuf_ += text;
            int pad = innerW - static_cast<int>(text.size());
            if (pad > 0) outputBuf_ += std::string(pad, ' ');
            resetStyle();
        } else {
            int innerW = width - 4;
            outputBuf_ += std::string(innerW, ' ');
        }

        setYellow();
        outputBuf_ += "\xe2\x94\x82";
        resetStyle();
        row++;
    }

    clearLine(row, width);
    moveCursor(row, 1);
    setYellow();
    outputBuf_ += " \xe2\x95\xb0";
    for (int i = 0; i < barWidth; i++) outputBuf_ += "\xe2\x94\x80";
    outputBuf_ += "\xe2\x95\xaf";
    resetStyle();
}

void Tui::tabCompletePath() {
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
        std::string common = matches[0];
        for (size_t i = 1; i < matches.size(); i++) {
            size_t j = 0;
            while (j < common.size() && j < matches[i].size() &&
                   common[j] == matches[i][j]) j++;
            common.resize(j);
        }
        if (common.size() > prefix.size()) {
            path = dir + common;
        }
    }
    confirmCursorPos_ = static_cast<int>(path.size());
}

void Tui::handleCtrlC() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastCtrlC_).count();

    if (processing_) {
        if (ctrlCPending_ && elapsed < 2000) {
            running_ = false;
            return;
        }

        if (!interruptSuppressing_) {
            sendToServer({{"type", "interrupt"}, {"chat_id", currentChatId_}});

            {
                std::lock_guard lk(messagesMu_);
                messages_.push_back({Message::AGENT, AgentMessage::ANSWER, "(interrupted)"});
                messagesDirty_ = true;
            }
            interruptShown_ = true;

            interruptSuppressing_ = true;
            processing_ = false;
        }
        scrollOffset_ = 0;
        render();
    } else {
        if (ctrlCPending_ && elapsed < 2000) {
            running_ = false;
            return;
        }

        inputBuffer_.clear();
        cursorPos_ = 0;
    }

    ctrlCPending_ = true;
    lastCtrlC_ = now;
}

void Tui::approveConfirm() {
    sendToServer({{"type", "confirm_resp"}, {"chat_id", currentChatId_},
        {"req_id", confirmReqId_}, {"action", "approve"}});
    confirmPending_ = false;
    messagesDirty_ = true;
}

void Tui::denyConfirm() {
    sendToServer({{"type", "confirm_resp"}, {"chat_id", currentChatId_},
        {"req_id", confirmReqId_}, {"action", "deny"}});
    confirmPending_ = false;
    messagesDirty_ = true;
}

void Tui::submitConfirmCustom() {
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
        setColor(COLOR_YELLOW);
        setBold();
        outputBuf_ += " scan path: ";
        resetStyle();
        setColor(COLOR_WHITE);
        int labelLen = 12;
        int available = width - labelLen - 1;
        std::string vis = confirmCustom_;
        if (static_cast<int>(vis.size()) > available) {
            int start = static_cast<int>(vis.size()) - available;
            vis = vis.substr(start);
        }
        outputBuf_ += vis;
        resetStyle();

        outputBuf_ += "\033[?25h";
        int cursorCol = labelLen + 1 + std::min(static_cast<int>(confirmCustom_.size()), available);
        moveCursor(row, cursorCol);
    } else {
        setColor(COLOR_YELLOW);
        setBold();
        outputBuf_ += " \xe2\x96\xb6 ";
        resetStyle();
        setColor(COLOR_WHITE);
        std::string desc = confirmDescription_;
        if (static_cast<int>(desc.size()) > width - 20) desc = truncateUTF8(desc, width - 20) + "...";
        outputBuf_ += desc;
        resetStyle();

        int cursorCol = 3 + static_cast<int>(desc.size()) + 2;
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

void Tui::renderSeparator(int row, int width) {
    moveCursor(row + 1, 1);
    outputBuf_ += "\033[2K";
    setColor(COLOR_GRAY);

    // Left side: session name
    std::string left = " " + currentChatId_;
    if (dangerousMode_) {
        left += " ";
        resetStyle();
        setColor(COLOR_RED);
        setBold();
        left += "\xe2\x9a\xa0 dangerous";  // ⚠ dangerous
    }

    outputBuf_ += left;
    resetStyle();

    // Right side: status
    setColor(COLOR_GRAY);
    std::string right;
    if (processing_) {
        right = "processing ";
    }

    int pad = width - static_cast<int>(left.size()) - static_cast<int>(right.size());
    if (pad > 0) outputBuf_ += std::string(pad, ' ');
    outputBuf_ += right;
    resetStyle();
}

void Tui::renderInput(int row, int width) {
    moveCursor(row, 1);
    outputBuf_ += "\033[2K";
    outputBuf_ += "  ";
    setColor(confirmPending_ ? COLOR_GRAY : COLOR_WHITE);

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
    if (!rightHint.empty()) rightWidth = static_cast<int>(rightHint.size()) + 1;
    else if (processing_) rightWidth = 8;

    int available = width - 3;
    int scrollStart = 0;
    if (cursorPos_ > available - rightWidth) {
        scrollStart = cursorPos_ - (available - rightWidth);
    }
    std::string visible = inputBuffer_.substr(scrollStart,
        std::min(available - rightWidth, static_cast<int>(inputBuffer_.size()) - scrollStart));
    outputBuf_ += visible;

    if (!rightHint.empty()) {
        int textEnd = 3 + static_cast<int>(visible.size());
        int hintStart = width - static_cast<int>(rightHint.size()) - 1;
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

    animFrame_++;

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
    int prevR = -1, prevG = -1, prevB = -1;
    for (int i = 0; i < width; i++) {
        double pos = static_cast<double>(i) / static_cast<double>(std::max(1, width));
        double env = 1.0 - pos;
        env = env * env * (3.0 - 2.0 * env);
        double n = flowNoise(static_cast<double>(i) * 0.8, static_cast<double>(animFrame_));
        double wave = (n + 1.0) * 0.5 * env;
        int r = wBase.r + static_cast<int>(wave * wAccent.r);
        int g = wBase.g + static_cast<int>(wave * wAccent.g);
        int b = wBase.b + static_cast<int>(wave * wAccent.b);
        if (r != prevR || g != prevG || b != prevB) {
            appendRGB(outputBuf_, r, g, b);
            prevR = r; prevG = g; prevB = b;
        }
        outputBuf_ += (i == 0) ? "\xe2\x94\x97" : "\xe2\x94\x81";
    }
    resetStyle();
}

void Tui::render() {
    outputBuf_ += "\033[?2026h";
    outputBuf_ += "\033[?25l";
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

    int headerRow = static_cast<int>(YGNodeLayoutGetTop(headerNode_));
    int headerWidth = static_cast<int>(YGNodeLayoutGetWidth(headerNode_));

    int taskPaneRow = static_cast<int>(YGNodeLayoutGetTop(taskPaneNode_));
    int taskPaneHeight = static_cast<int>(YGNodeLayoutGetHeight(taskPaneNode_));
    int taskPaneWidth = static_cast<int>(YGNodeLayoutGetWidth(taskPaneNode_));

    int contentRow = static_cast<int>(YGNodeLayoutGetTop(contentNode_));
    int contentHeight = static_cast<int>(YGNodeLayoutGetHeight(contentNode_));
    int contentWidth = static_cast<int>(YGNodeLayoutGetWidth(contentNode_));

    int sepRow = static_cast<int>(YGNodeLayoutGetTop(separatorNode_));
    int inputRow = static_cast<int>(YGNodeLayoutGetTop(inputNode_));
    int inputWidth = static_cast<int>(YGNodeLayoutGetWidth(inputNode_));

    int clusterRow = static_cast<int>(YGNodeLayoutGetTop(clusterNode_));
    int clusterHeight = static_cast<int>(YGNodeLayoutGetHeight(clusterNode_));
    int clusterWidth = static_cast<int>(YGNodeLayoutGetWidth(clusterNode_));

    if (showHeader_) renderHeader(headerRow, headerWidth);
    if (taskPaneHeight > 0) {
        renderTaskPane(taskPaneRow, taskPaneHeight, taskPaneWidth);
    }
    renderMessages(contentRow, confirmPending_ ? contentHeight - 1 : contentHeight, contentWidth);
    if (confirmPending_) {
        renderConfirm(contentRow + contentHeight, contentWidth);
    }
    int sepWidth = static_cast<int>(YGNodeLayoutGetWidth(separatorNode_));
    renderSeparator(sepRow, sepWidth);
    renderInput(inputRow + 1, inputWidth);
    int waveBarRow = static_cast<int>(YGNodeLayoutGetTop(waveBarNode_));
    int waveBarWidth = static_cast<int>(YGNodeLayoutGetWidth(waveBarNode_));
    renderWaveBar(waveBarRow + 1, waveBarWidth);
    renderContextMenu(ts.rows, ts.cols);

    outputBuf_ += "\033[?2026l";
    flush();
}

void Tui::renderInputOnly() {
    outputBuf_ += "\033[?2026h";
    auto ts = getTermSize();
    if (!root_ || ts.rows != layoutRows_ || ts.cols != layoutCols_) {
        render();
        return;
    }
    int inputRow = static_cast<int>(YGNodeLayoutGetTop(inputNode_));
    int inputWidth = static_cast<int>(YGNodeLayoutGetWidth(inputNode_));
    renderInput(inputRow + 1, inputWidth);
    outputBuf_ += "\033[?2026l";
    flush();
}

Tui::MouseEvent Tui::readSGRMouse() {
    char buf[32];
    int bi = 0;
    while (bi < 31) {
        if (read(STDIN_FILENO, &buf[bi], 1) <= 0) break;
        if (buf[bi] == 'M' || buf[bi] == 'm') {
            bi++; break;
        }
        bi++;
    }
    buf[bi] = 0;
    MouseEvent ev{};
    ev.press = (bi > 0 && buf[bi - 1] == 'M');
    sscanf(buf, "%d;%d;%d", &ev.button, &ev.x, &ev.y);
    return ev;
}

void Tui::toggleContextMenuItem(int item) {
    if (item == 0) {
        showHeader_ = !showHeader_;
        layoutNeedsRebuild_ = true;
    } else if (item == 1) {
        showTaskPane_.store(!showTaskPane_.load());
        layoutNeedsRebuild_ = true;
    }
}

bool Tui::handleContextMenuInput(char c) {
    const int numItems = 2;

    if (c == 27) {
        struct pollfd ep = {STDIN_FILENO, POLLIN, 0};
        if (poll(&ep, 1, 30) > 0 && (ep.revents & POLLIN)) {
            char seq0;
            if (read(STDIN_FILENO, &seq0, 1) <= 0) {
                contextMenuOpen_ = false;
                return false;
            }
            if (seq0 == '[') {
                char seq1;
                if (read(STDIN_FILENO, &seq1, 1) <= 0) {
                    contextMenuOpen_ = false;
                    return false;
                }
                if (seq1 == 'A') {
                    if (contextMenuSel_ > 0) {
                        contextMenuSel_--;
                    }
                    return true;
                }
                if (seq1 == 'B') {
                    if (contextMenuSel_ < numItems - 1) {
                        contextMenuSel_++;
                    }
                    return true;
                }
                if (seq1 == '<') {
                    auto mouse = readSGRMouse();
                    if (mouse.button == 2 && mouse.press) {
                        contextMenuRow_ = mouse.y;
                        contextMenuCol_ = mouse.x;
                        contextMenuSel_ = 0;
                        return true;
                    }
                    if (mouse.button == 0 && mouse.press) {
                        auto ts = getTermSize();
                        const int menuWidth = 17, menuHeight = numItems + 2;
                        int mr = std::clamp(contextMenuRow_, 1, std::max(1, ts.rows - menuHeight + 1));
                        int mc = std::clamp(contextMenuCol_, 1, std::max(1, ts.cols - menuWidth + 1));
                        if (mouse.y >= mr + 1 && mouse.y <= mr + numItems
                            && mouse.x >= mc && mouse.x < mc + menuWidth) {
                            toggleContextMenuItem(mouse.y - mr - 1);
                        }
                        contextMenuOpen_ = false;
                        return true;
                    }
                    if (mouse.button == 64) {
                        scrollOffset_ += 3; contextMenuOpen_ = false; return true;
                    }
                    if (mouse.button == 65) {
                        scrollOffset_ = std::max(0, scrollOffset_ - 3); contextMenuOpen_ = false; return true;
                    }
                    return true;
                }
                if (seq1 == '5' || seq1 == '6') {
                    char t; if (read(STDIN_FILENO, &t, 1)) {}
                }
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

bool Tui::handleEscapeSequence() {
    char seq[2];
    if (read(STDIN_FILENO, &seq[0], 1) <= 0) return false;

    // Alt+Backspace: \033 \x7f
    if (seq[0] == 127) {
        // Delete previous word (same as Ctrl+W)
        if (cursorPos_ > 0) {
            int end = cursorPos_;
            while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] == ' ') cursorPos_--;
            while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] != ' ') cursorPos_--;
            inputBuffer_.erase(cursorPos_, end - cursorPos_);
        }
        return true;
    }

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
        if (mouse.button == 64) {
            scrollOffset_ += 3;
            return true;
        }
        if (mouse.button == 65) {
            scrollOffset_ = std::max(0, scrollOffset_ - 3);
            return true;
        }
        return true;
    }

    if (seq[1] == '5') {
        char tilde;
        if (read(STDIN_FILENO, &tilde, 1) < 0) {
            return true;
        }
        scrollOffset_ += 15;
        return true;
    }
    if (seq[1] == '6') {
        char tilde;
        if (read(STDIN_FILENO, &tilde, 1) < 0) {
            return true;
        }
        scrollOffset_ = std::max(0, scrollOffset_ - 15);
        return true;
    }

    // Modified keys: \033[1;3C (Alt+Right), \033[1;3D (Alt+Left)
    if (seq[1] == '1') {
        char mod[2];
        if (read(STDIN_FILENO, &mod[0], 1) <= 0) return true;
        if (read(STDIN_FILENO, &mod[1], 1) <= 0) return true;
        if (mod[0] == ';' && mod[1] == '3') {
            char dir;
            if (read(STDIN_FILENO, &dir, 1) <= 0) return true;
            if (dir == 'C') {
                // Alt+Right: move to end of next word
                int len = static_cast<int>(inputBuffer_.size());
                while (cursorPos_ < len && inputBuffer_[cursorPos_] == ' ') cursorPos_++;
                while (cursorPos_ < len && inputBuffer_[cursorPos_] != ' ') cursorPos_++;
            } else if (dir == 'D') {
                // Alt+Left: move to start of previous word
                while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] == ' ') cursorPos_--;
                while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] != ' ') cursorPos_--;
            }
        }
        return true;
    }

    if (seq[1] == 'A') {
        if (!history_.empty()) {
            if (historyIdx_ == -1) {
                savedInput_ = inputBuffer_;
                historyIdx_ = static_cast<int>(history_.size()) - 1;
            } else if (historyIdx_ > 0) {
                historyIdx_--;
            }
            inputBuffer_ = history_[historyIdx_];
            cursorPos_ = static_cast<int>(inputBuffer_.size());
        }
    } else if (seq[1] == 'B') {
        if (historyIdx_ != -1) {
            if (historyIdx_ < static_cast<int>(history_.size()) - 1) {
                historyIdx_++;
                inputBuffer_ = history_[historyIdx_];
            } else {
                historyIdx_ = -1;
                inputBuffer_ = savedInput_;
                savedInput_.clear();
            }
            cursorPos_ = static_cast<int>(inputBuffer_.size());
        }
    } else if (seq[1] == 'C') {
        if (cursorPos_ < static_cast<int>(inputBuffer_.size())) cursorPos_++;
    } else if (seq[1] == 'D') {
        if (cursorPos_ > 0) cursorPos_--;
    }

    return true;
}

bool Tui::handleInput() {
    char c;
    if (read(STDIN_FILENO, &c, 1) <= 0) return false;

    if (contextMenuOpen_) return handleContextMenuInput(c);

    if (c == 3) {
        handleCtrlC(); return true;
    }

    ctrlCPending_ = false;

    if (c == 13 || c == 10) {
        if (!inputBuffer_.empty()) submit();
        return true;
    }
    if (c == 127 || c == 8) {
        if (cursorPos_ > 0) {
            inputBuffer_.erase(cursorPos_ - 1, 1); cursorPos_--;
        }
        return true;
    }
    if (c == 1)  {
        cursorPos_ = 0; return true;
    }
    if (c == 5)  {
        cursorPos_ = static_cast<int>(inputBuffer_.size()); return true;
    }
    if (c == 21) {
        inputBuffer_.erase(0, cursorPos_); cursorPos_ = 0; return true;
    }
    if (c == 11) {
        inputBuffer_.erase(cursorPos_); return true;
    }
    if (c == 23) {
        if (cursorPos_ > 0) {
            int end = cursorPos_;
            while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] == ' ') cursorPos_--;
            while (cursorPos_ > 0 && inputBuffer_[cursorPos_ - 1] != ' ') cursorPos_--;
            inputBuffer_.erase(cursorPos_, end - cursorPos_);
        }
        return true;
    }
    if (c == 12) {
        outputBuf_ += "\033[2J"; return true;
    }
    if (c == 2) {
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

    if ((unsigned char)c >= 0xC0) {
        std::string mb(1, c);
        int expect = ((unsigned char)c >= 0xF0) ? 3 : ((unsigned char)c >= 0xE0) ? 2 : 1;
        for (int i = 0; i < expect; i++) {
            char cb;
            if (read(STDIN_FILENO, &cb, 1) <= 0) break;
            mb += cb;
        }
        inputBuffer_.insert(cursorPos_, mb);
        cursorPos_ += static_cast<int>(mb.size());
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
                    confirmCustom_.erase(confirmCustom_.rfind(' '));
            }
            confirmCursorPos_ = static_cast<int>(confirmCustom_.size());
        }
        confirmPending_ = true;
        messagesDirty_ = true;
    } else if (type == "tui_control") {
    } else if (type == "chat_list") {
    }
}

void Tui::submit() {
    std::string query = inputBuffer_;

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

        if (c == 3) {
            denyConfirm(); break;
        }

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
                    if (seq1 == '<') readSGRMouse();
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
            if (c == 9) {
                tabCompletePath();
            } else if (c == 13 || c == 10) {
                submitConfirmCustom();
                break;
            } else if (c == 127 || c == 8) {
                if (!confirmCustom_.empty()) {
                    confirmCustom_.pop_back();
                    confirmCursorPos_ = static_cast<int>(confirmCustom_.size());
                }
            } else if (c >= 32 && c < 127) {
                confirmCustom_ += c;
                confirmCursorPos_ = static_cast<int>(confirmCustom_.size());
            }
        } else {
            if ((c == 'y' || c == 'Y') && confirmSelection_ != 2) {
                approveConfirm();
                break;
            } else if ((c == 'n' || c == 'N') && confirmSelection_ != 2) {
                denyConfirm();
                break;
            } else if (c == 9) {
                confirmSelection_ = 2;
            } else if (c == 13 || c == 10) {
                if (confirmSelection_ == 0) {
                    approveConfirm();
                    break;
                } else if (confirmSelection_ == 1) {
                    denyConfirm();
                    break;
                } else {
                    submitConfirmCustom();
                    break;
                }
            } else if (c == 127 || c == 8) {
                if (confirmSelection_ == 2 && !confirmCustom_.empty())
                    confirmCustom_.pop_back();
            } else if (c >= 32 && c < 127 && confirmSelection_ == 2) {
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
        return false;
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

void Tui::run() {
    setupSignals();
    enterAltScreen();
    enableRawMode();
    running_ = true;

    sendToServer({{"type", "attach"}, {"chat_id", currentChatId_}});
    render();

    bool needsRender = false;
    while (running_) {
        bool fading = (animFrame_ - fadeStartFrame_) < 35;
        int pollMs = (fading || confirmPending_) ? 16 : processing_ ? 33 : 64;

        struct pollfd pfds[2];
        pfds[0] = {STDIN_FILENO, POLLIN, 0};
        pfds[1] = {sockFd_, POLLIN, 0};
        poll(pfds, 2, pollMs);

        if (g_interrupted) {
            g_interrupted = 0; break;
        }
        if (g_resized)     {
            g_resized = 0; needsRender = true;
        }

        bool inputChanged = false;
        if (pfds[0].revents & POLLIN) processStdin(needsRender, inputChanged);
        if (pfds[1].revents & POLLIN) {
            if (!readServerMessages()) break;
        }

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
}  // namespace area
