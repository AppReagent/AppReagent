#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace area {

struct VtCell {
    char32_t ch = ' ';
    bool bold = false;
    bool inverse = false;
};

/// Minimal VT100/xterm escape sequence parser that maintains a screen buffer.
/// Handles the subset of sequences used by the area TUI.
class VtScreen {
public:
    VtScreen(int rows = 24, int cols = 80);

    void resize(int rows, int cols);
    void feed(const char* data, size_t len);
    void feed(const std::string& data) { feed(data.data(), data.size()); }

    /// Dump screen as plain text (rows joined by newlines, trailing spaces trimmed).
    std::string text() const;

    int rows() const { return rows_; }
    int cols() const { return cols_; }
    int cursorRow() const { return curRow_; }
    int cursorCol() const { return curCol_; }
    bool mouseTracking() const { return mouseTracking_; }

private:
    enum class State { Ground, Escape, CsiParam, OscString, EscHash };

    void processChar(char32_t ch);
    void executeControl(char32_t ch);
    void executeCsi(char final_ch);
    void executeDecPrivate(char final_ch);
    void executeSgr();

    void putChar(char32_t ch);
    void scrollUp();
    void clearCells(int row, int colStart, int colEnd);

    int rows_, cols_;
    int curRow_ = 0, curCol_ = 0;
    std::vector<std::vector<VtCell>> grid_;

    // Parser state
    State state_ = State::Ground;
    std::string paramBuf_;
    bool decPrivate_ = false; // CSI ? prefix

    // Current attributes
    VtCell curAttr_;

    // Alt screen
    bool altScreen_ = false;
    std::vector<std::vector<VtCell>> savedGrid_;
    int savedRow_ = 0, savedCol_ = 0;

    // Tracked flags
    bool mouseTracking_ = false;

    // UTF-8 decoder
    char32_t utf8Acc_ = 0;
    int utf8Remaining_ = 0;

    // Helpers
    std::vector<int> parseParams(int defaultVal = 0) const;
};

} // namespace area
