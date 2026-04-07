#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>
#include <termios.h>
#include <nlohmann/json.hpp>
#include <yoga/Yoga.h>

#include "Agent.h"

namespace area {

class Tui {
public:
    Tui(int sockFd, const std::string& theme = "dark");
    ~Tui();

    Tui(const Tui&) = delete;
    Tui& operator=(const Tui&) = delete;

    void run();

    struct ColorTheme {
        struct RGB { int r, g, b; };
        RGB waveBase, waveAccent, pulseBase, pulseShift;
        RGB procBase, procAccent; // wave bar colors during processing
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
    void submit();

    struct DisplayLine {
        AgentMessage::Type type;
        std::string text;
        int addedAtFrame = 0;
        bool isUser = false;
    };

    std::vector<DisplayLine> wrapMessage(const AgentMessage& msg, int width);

    int sockFd_;
    std::string currentChatId_ = "default";
    int confirmReqId_ = 0;   // for socket confirm matching

    void handleServerMessage(const nlohmann::json& msg);
    void sendToServer(const nlohmann::json& msg);
    bool running_ = false;
    std::atomic<bool> processing_{false};
    std::atomic<bool> showTaskPane_{false};  // controlled by agent (TUI: tool) and user (/task)
    std::atomic<bool> messagesDirty_{false}; // set by server messages
    std::mutex messagesMu_;

    int scrollOffset_ = 0;
    int taskScrollOffset_ = 0;
    std::atomic<uint64_t> animFrame_{0};   // 60fps counter for wave bar
    int noiseFrame_ = 0;  // slow counter for text noise, increments on full renders
    uint64_t fadeStartFrame_ = 0; // animFrame_ when last new message arrived
    int layoutRows_ = 0, layoutCols_ = 0;
    bool layoutShowTaskPane_ = false;
    bool layoutNeedsRebuild_ = false;

    // Cached wrapped display lines (rebuilt only when messages or width change)
    std::vector<DisplayLine> cachedDisplayLines_;
    int cachedDisplayWidth_ = 0;
    int cachedDisplayCount_ = 0;
    bool cachedDisplayFilter_ = false;

    std::string inputBuffer_;
    int cursorPos_ = 0;

    std::vector<std::string> history_;
    int historyIdx_ = -1;
    std::string savedInput_; // stash current input when browsing history

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

    // Confirm UI state
    std::mutex confirmMu_;
    std::atomic<bool> confirmPending_{false};
    bool confirmIsPath_ = false; // SCAN mode: path input with tab completion
    std::string confirmDescription_;
    int confirmSelection_ = 0; // 0=Yes, 1=No, 2=Custom
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
    std::atomic<bool> interruptShown_{false};  // suppress duplicate (interrupted) from server
    std::atomic<bool> interruptSuppressing_{false};  // suppress all agent_msg until server confirms done
    std::string inputFlash_;
    std::chrono::steady_clock::time_point flashTime_{};

    bool showHeader_ = false;
    bool mouseMode_ = false;  // false = text selection, true = scroll wheel + right-click

    void enableMouseTracking();
    void disableMouseTracking();

    // Right-click context menu
    bool contextMenuOpen_ = false;
    int contextMenuRow_ = 0;   // 1-based screen row (mouse click position)
    int contextMenuCol_ = 0;   // 1-based screen col
    int contextMenuSel_ = 0;   // selected item (0-based)
    void renderContextMenu(int screenRows, int screenCols);

    YGNodeRef root_ = nullptr;
    YGNodeRef headerNode_ = nullptr;
    YGNodeRef clusterNode_ = nullptr;
    YGNodeRef taskPaneNode_ = nullptr;
    YGNodeRef contentNode_ = nullptr;
    YGNodeRef separatorNode_ = nullptr;
    YGNodeRef inputNode_ = nullptr;
};

} // namespace area
