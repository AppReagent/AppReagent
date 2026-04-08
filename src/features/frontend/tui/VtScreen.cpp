#include "features/frontend/tui/VtScreen.h"

#include <algorithm>
#include <sstream>
#include <cstdint>

namespace area {
VtScreen::VtScreen(int rows, int cols) : rows_(rows), cols_(cols) {
    grid_.assign(rows_, std::vector<VtCell>(cols_));
}

void VtScreen::resize(int rows, int cols) {
    rows_ = rows;
    cols_ = cols;
    grid_.assign(rows_, std::vector<VtCell>(cols_));
    curRow_ = std::min(curRow_, rows_ - 1);
    curCol_ = std::min(curCol_, cols_ - 1);
}

void VtScreen::feed(const char* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        auto b = static_cast<uint8_t>(data[i]);

        if (utf8Remaining_ > 0) {
            if ((b & 0xC0) == 0x80) {
                utf8Acc_ = (utf8Acc_ << 6) | (b & 0x3F);
                if (--utf8Remaining_ == 0) processChar(utf8Acc_);
            } else {
                utf8Remaining_ = 0;
                --i;
            }
            continue;
        }

        if (b < 0x80) {
            processChar(b);
        } else if ((b & 0xE0) == 0xC0) {
            utf8Acc_ = b & 0x1F;
            utf8Remaining_ = 1;
        } else if ((b & 0xF0) == 0xE0) {
            utf8Acc_ = b & 0x0F;
            utf8Remaining_ = 2;
        } else if ((b & 0xF8) == 0xF0) {
            utf8Acc_ = b & 0x07;
            utf8Remaining_ = 3;
        }
    }
}

void VtScreen::processChar(char32_t ch) {
    switch (state_) {
    case State::Ground:
        if (ch == 0x1B) {
            state_ = State::Escape;
            paramBuf_.clear();
            decPrivate_ = false;
        } else if (ch < 0x20 || ch == 0x7F) {
            executeControl(ch);
        } else {
            putChar(ch);
        }
        break;

    case State::Escape:
        if (ch == '[') {
            state_ = State::CsiParam;
            paramBuf_.clear();
            decPrivate_ = false;
        } else if (ch == ']') {
            state_ = State::OscString;
            paramBuf_.clear();
        } else if (ch == '#') {
            state_ = State::EscHash;
        } else {
            state_ = State::Ground;
        }
        break;

    case State::CsiParam:
        if (ch == '?') {
            decPrivate_ = true;
        } else if ((ch >= '0' && ch <= '9') || ch == ';') {
            paramBuf_ += static_cast<char>(ch);
        } else if (ch >= 0x40 && ch <= 0x7E) {
            if (decPrivate_) {
                executeDecPrivate(static_cast<char>(ch));
            } else {
                executeCsi(static_cast<char>(ch));
            }
            state_ = State::Ground;
        } else {
        }
        break;

    case State::OscString:

        if (ch == 0x07) {
            state_ = State::Ground;
        } else if (ch == 0x1B) {
            state_ = State::Ground;
        }
        break;

    case State::EscHash:

        state_ = State::Ground;
        break;
    }
}

void VtScreen::executeControl(char32_t ch) {
    switch (ch) {
    case '\n':
        if (curRow_ < rows_ - 1) {
            ++curRow_;
        } else {
            scrollUp();
        }
        break;
    case '\r':
        curCol_ = 0;
        break;
    case '\t': {
        int next = ((curCol_ / 8) + 1) * 8;
        curCol_ = std::min(next, cols_ - 1);
        break;
    }
    case '\b':
        if (curCol_ > 0) --curCol_;
        break;
    default:
        break;
    }
}

std::vector<int> VtScreen::parseParams(int defaultVal) const {
    std::vector<int> params;
    if (paramBuf_.empty()) {
        params.push_back(defaultVal);
        return params;
    }
    std::istringstream ss(paramBuf_);
    std::string token;
    while (std::getline(ss, token, ';')) {
        if (token.empty()) {
            params.push_back(defaultVal);
        } else {
            params.push_back(std::stoi(token));
        }
    }
    if (params.empty()) params.push_back(defaultVal);
    return params;
}

void VtScreen::executeCsi(char f) {
    auto p = parseParams(f == 'm' ? 0 : 1);

    switch (f) {
    case 'H':
    case 'f': {
        int row = (p.size() > 0 ? p[0] : 1) - 1;
        int col = (p.size() > 1 ? p[1] : 1) - 1;
        curRow_ = std::clamp(row, 0, rows_ - 1);
        curCol_ = std::clamp(col, 0, cols_ - 1);
        break;
    }
    case 'A':
        curRow_ = std::max(0, curRow_ - p[0]);
        break;
    case 'B':
        curRow_ = std::min(rows_ - 1, curRow_ + p[0]);
        break;
    case 'C':
        curCol_ = std::min(cols_ - 1, curCol_ + p[0]);
        break;
    case 'D':
        curCol_ = std::max(0, curCol_ - p[0]);
        break;
    case 'G':
        curCol_ = std::clamp(p[0] - 1, 0, cols_ - 1);
        break;
    case 'd':
        curRow_ = std::clamp(p[0] - 1, 0, rows_ - 1);
        break;
    case 'J': {
        int mode = p[0];
        if (mode == 0) {
            clearCells(curRow_, curCol_, cols_);
            for (int r = curRow_ + 1; r < rows_; ++r)
                clearCells(r, 0, cols_);
        } else if (mode == 1) {
            for (int r = 0; r < curRow_; ++r)
                clearCells(r, 0, cols_);
            clearCells(curRow_, 0, curCol_ + 1);
        } else if (mode == 2 || mode == 3) {
            for (int r = 0; r < rows_; ++r)
                clearCells(r, 0, cols_);
        }
        break;
    }
    case 'K': {
        int mode = p[0];
        if (mode == 0) {
            clearCells(curRow_, curCol_, cols_);
        } else if (mode == 1) {
            clearCells(curRow_, 0, curCol_ + 1);
        } else if (mode == 2) {
            clearCells(curRow_, 0, cols_);
        }
        break;
    }
    case 'L': {
        int n = p[0];
        for (int i = 0; i < n && curRow_ + i < rows_; ++i) {
            grid_.insert(grid_.begin() + curRow_, std::vector<VtCell>(cols_));
            grid_.resize(rows_);
        }
        break;
    }
    case 'M': {
        int n = p[0];
        for (int i = 0; i < n && curRow_ < static_cast<int>(grid_.size()); ++i) {
            grid_.erase(grid_.begin() + curRow_);
            grid_.push_back(std::vector<VtCell>(cols_));
        }
        break;
    }
    case 'm':
        executeSgr();
        break;
    case 'S':
        for (int i = 0; i < p[0]; ++i) scrollUp();
        break;
    case 'T':
        for (int i = 0; i < p[0]; ++i) {
            grid_.insert(grid_.begin(), std::vector<VtCell>(cols_));
            grid_.resize(rows_);
        }
        break;
    default:
        break;
    }
}

void VtScreen::executeDecPrivate(char f) {
    auto p = parseParams(0);
    bool set = (f == 'h');

    for (int code : p) {
        switch (code) {
        case 1049:
            if (set && !altScreen_) {
                savedGrid_ = grid_;
                savedRow_ = curRow_;
                savedCol_ = curCol_;
                altScreen_ = true;
                for (int r = 0; r < rows_; ++r)
                    clearCells(r, 0, cols_);
                curRow_ = 0;
                curCol_ = 0;
            } else if (!set && altScreen_) {
                grid_ = savedGrid_;
                curRow_ = savedRow_;
                curCol_ = savedCol_;
                altScreen_ = false;
            }
            break;
        case 1000:
        case 1006:
            mouseTracking_ = set;
            break;
        default:
            break;
        }
    }
}

void VtScreen::executeSgr() {
    auto p = parseParams(0);
    for (size_t i = 0; i < p.size(); ++i) {
        int code = p[i];
        switch (code) {
        case 0:
            curAttr_ = VtCell{};
            break;
        case 1:
            curAttr_.bold = true;
            break;
        case 7:
            curAttr_.inverse = true;
            break;
        case 22:
            curAttr_.bold = false;
            break;
        case 27:
            curAttr_.inverse = false;
            break;
        case 38:
            if (i + 1 < p.size() && p[i + 1] == 2) {
                i += 4;
            } else if (i + 1 < p.size() && p[i + 1] == 5) {
                i += 2;
            }
            break;
        case 48:
            if (i + 1 < p.size() && p[i + 1] == 2) {
                i += 4;
            } else if (i + 1 < p.size() && p[i + 1] == 5) {
                i += 2;
            }
            break;
        default:

            break;
        }
    }
}

void VtScreen::putChar(char32_t ch) {
    if (curCol_ >= cols_) {
        curCol_ = 0;
        if (curRow_ < rows_ - 1) {
            ++curRow_;
        } else {
            scrollUp();
        }
    }
    auto& cell = grid_[curRow_][curCol_];
    cell.ch = ch;
    cell.bold = curAttr_.bold;
    cell.inverse = curAttr_.inverse;
    ++curCol_;
}

void VtScreen::scrollUp() {
    grid_.erase(grid_.begin());
    grid_.push_back(std::vector<VtCell>(cols_));
}

void VtScreen::clearCells(int row, int colStart, int colEnd) {
    if (row < 0 || row >= rows_) return;
    colStart = std::max(0, colStart);
    colEnd = std::min(cols_, colEnd);
    for (int c = colStart; c < colEnd; ++c) {
        grid_[row][c] = VtCell{};
    }
}

static void appendUtf8(std::string& out, char32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

std::string VtScreen::text() const {
    std::string out;
    out.reserve(rows_ * (cols_ + 1));
    for (int r = 0; r < rows_; ++r) {
        std::string row;
        row.reserve(cols_ * 2);
        for (int c = 0; c < cols_; ++c) {
            appendUtf8(row, grid_[r][c].ch);
        }

        auto end = row.find_last_not_of(' ');
        if (end != std::string::npos) {
            row.resize(end + 1);
        } else {
            row.clear();
        }
        out += row;
        if (r < rows_ - 1) out += '\n';
    }
    return out;
}
}  // namespace area
