#pragma once

#include <termios.h>
#include <bits/chrono.h>
#include <stdint.h>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>

#include "infra/agent/Agent.h"
#include <nlohmann/json.hpp>
#include "yoga/YGNode.h"

namespace area {

class Tui {
 public:
    explicit Tui(int sockFd, const std::string& theme = "dark");
    ~Tui();

    Tui(const Tui&) = delete;
    Tui& operator=(const Tui&) = delete;

    void run();

    struct ColorTheme {
        struct RGB { int r, g, b; };
        RGB waveBase, waveAccent, pulseBase, pulseShift;
        RGB procBase, procAccent;
        int textFg, headerFg;
    };

 private:
    struct TermSize { int rows, cols; };
    TermSize getTermSize();

    void enableRawMode();
    void disableRawMode();
    void enterAltScreen();
    void exitAltScreen();

    void buildLayout();
    void freeLayout();
    void render();
    void renderInputOnly();
    void renderHeader(int row, int width);
    void renderCluster(int startRow, int height, int width);
    void renderMessages(int startRow, int height, int width);
    void renderTaskPane(int startRow, int height, int width);
    void renderInput(int row, int width);
    void renderWaveBar(int row, int width);

    void moveCursor(int row, int col);
    void clearLine(int row, int width);
    void setColor(int fg);
    void setBold();
    void resetStyle();
    void flush();

    bool handleInput();
    bool handleContextMenuInput(char c);
    bool handleEscapeSequence();
    void handleConfirmInput();
    void submit();

    void setupSignals();
    bool readServerMessages();
    void processStdin(bool& needsRender, bool& inputChanged);
    void updateDisplay(bool fullRender, bool inputChanged);
    void renderWaveBarOnly();

    struct MouseEvent { int button = 0, x = 0, y = 0; bool press = false; };
    MouseEvent readSGRMouse();
    void toggleContextMenuItem(int item);

    struct DisplayLine {
        AgentMessage::Type type;
        std::string text;
        int addedAtFrame = 0;
        bool isUser = false;
    };

    std::vector<DisplayLine> wrapMessage(const AgentMessage& msg, int width);

    int sockFd_;
    std::string currentChatId_ = "default";
    int confirmReqId_ = 0;

    void handleServerMessage(const nlohmann::json& msg);
    void sendToServer(const nlohmann::json& msg);
    bool running_ = false;
    std::atomic<bool> processing_{false};
    std::atomic<bool> showTaskPane_{false};
    std::atomic<bool> messagesDirty_{false};
    std::mutex messagesMu_;

    int scrollOffset_ = 0;
    int taskScrollOffset_ = 0;
    std::atomic<uint64_t> animFrame_{0};
    int noiseFrame_ = 0;
    uint64_t fadeStartFrame_ = 0;
    int layoutRows_ = 0, layoutCols_ = 0;
    bool layoutShowTaskPane_ = false;
    bool layoutNeedsRebuild_ = false;

    std::vector<DisplayLine> cachedDisplayLines_;
    int cachedDisplayWidth_ = 0;
    int cachedDisplayCount_ = 0;
    bool cachedDisplayFilter_ = false;

    std::string inputBuffer_;
    int cursorPos_ = 0;

    std::vector<std::string> history_;
    int historyIdx_ = -1;
    std::string savedInput_;

    struct Message {
        enum Type { USER, AGENT };
        Type who;
        AgentMessage::Type agentType;
        std::string content;
        int addedAtFrame = 0;
    };
    std::vector<Message> messages_;

    ColorTheme theme_;
    std::atomic<bool> dangerousMode_{false};

    std::mutex confirmMu_;
    std::atomic<bool> confirmPending_{false};
    bool confirmIsPath_ = false;
    std::string confirmDescription_;
    int confirmSelection_ = 0;
    std::string confirmCustom_;
    int confirmCursorPos_ = 0;

    void renderConfirm(int row, int width);
    void tabCompletePath();
    void handleCtrlC();
    void approveConfirm();
    void denyConfirm();
    void submitConfirmCustom();

    std::string outputBuf_;

    struct termios origTermios_{};
    bool rawMode_ = false;
    std::chrono::steady_clock::time_point lastCtrlC_{};
    bool ctrlCPending_ = false;
    std::atomic<bool> interruptShown_{false};
    std::atomic<bool> interruptSuppressing_{false};
    std::string inputFlash_;
    std::chrono::steady_clock::time_point flashTime_{};

    bool showHeader_ = false;
    int contextTokens_ = 0;
    int contextWindow_ = 0;
    bool mouseMode_ = false;

    void enableMouseTracking();
    void disableMouseTracking();

    bool contextMenuOpen_ = false;
    int contextMenuRow_ = 0;
    int contextMenuCol_ = 0;
    int contextMenuSel_ = 0;
    void renderContextMenu(int screenRows, int screenCols);

    YGNodeRef root_ = nullptr;
    YGNodeRef headerNode_ = nullptr;
    YGNodeRef clusterNode_ = nullptr;
    YGNodeRef taskPaneNode_ = nullptr;
    YGNodeRef contentNode_ = nullptr;
    YGNodeRef separatorNode_ = nullptr;
    YGNodeRef inputNode_ = nullptr;
};

}  // namespace area
