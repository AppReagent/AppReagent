#pragma once

#include <stddef.h>
#include <string>
#include <vector>

namespace area {

struct VtCell {
    char32_t ch = ' ';
    bool bold = false;
    bool inverse = false;
};

class VtScreen {
 public:
    explicit VtScreen(int rows = 24, int cols = 80);

    void resize(int rows, int cols);
    void feed(const char* data, size_t len);
    void feed(const std::string& data) { feed(data.data(), data.size()); }

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

    State state_ = State::Ground;
    std::string paramBuf_;
    bool decPrivate_ = false;

    VtCell curAttr_;

    bool altScreen_ = false;
    std::vector<std::vector<VtCell>> savedGrid_;
    int savedRow_ = 0, savedCol_ = 0;

    bool mouseTracking_ = false;

    char32_t utf8Acc_ = 0;
    int utf8Remaining_ = 0;

    std::vector<int> parseParams(int defaultVal = 0) const;
};

}  // namespace area
