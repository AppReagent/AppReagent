#include <gtest/gtest.h>
#include "VtScreen.h"

using area::VtScreen;

// ── basic text ──────────────────────────────────────────────────────

TEST(VtScreen, DefaultBlank) {
    VtScreen s(3, 5);
    // All spaces, trimmed → empty lines
    EXPECT_EQ(s.text(), "\n\n");
}

TEST(VtScreen, PutChars) {
    VtScreen s(2, 10);
    s.feed("hello");
    EXPECT_EQ(s.cursorCol(), 5);
    EXPECT_EQ(s.cursorRow(), 0);
    auto t = s.text();
    EXPECT_EQ(t.substr(0, 5), "hello");
}

TEST(VtScreen, LineWrap) {
    VtScreen s(2, 5);
    s.feed("abcdefgh");
    // "abcde" on row 0, "fgh" on row 1
    auto t = s.text();
    EXPECT_NE(t.find("abcde"), std::string::npos);
    EXPECT_NE(t.find("fgh"), std::string::npos);
    EXPECT_EQ(s.cursorRow(), 1);
    EXPECT_EQ(s.cursorCol(), 3);
}

// ── cursor positioning ──────────────────────────────────────────────

TEST(VtScreen, CursorHome) {
    VtScreen s(3, 10);
    s.feed("hello");
    s.feed("\033[H"); // cursor home (1,1)
    EXPECT_EQ(s.cursorRow(), 0);
    EXPECT_EQ(s.cursorCol(), 0);
}

TEST(VtScreen, CursorPosition) {
    VtScreen s(5, 10);
    s.feed("\033[3;7H"); // row 3, col 7 (1-based)
    EXPECT_EQ(s.cursorRow(), 2);
    EXPECT_EQ(s.cursorCol(), 6);
}

TEST(VtScreen, CursorMovement) {
    VtScreen s(5, 10);
    s.feed("\033[3;5H"); // row 3, col 5
    s.feed("\033[2A");   // up 2
    EXPECT_EQ(s.cursorRow(), 0);
    s.feed("\033[3B");   // down 3
    EXPECT_EQ(s.cursorRow(), 3);
    s.feed("\033[2C");   // right 2
    EXPECT_EQ(s.cursorCol(), 6);
    s.feed("\033[3D");   // left 3
    EXPECT_EQ(s.cursorCol(), 3);
}

// ── erase ───────────────────────────────────────────────────────────

TEST(VtScreen, EraseLine) {
    VtScreen s(2, 10);
    s.feed("0123456789");
    s.feed("\033[1;1H"); // back to start
    s.feed("\033[2K");   // erase entire line
    auto t = s.text();
    // First line should be empty (trimmed)
    auto nl = t.find('\n');
    EXPECT_EQ(t.substr(0, nl), "");
}

TEST(VtScreen, EraseScreen) {
    VtScreen s(3, 5);
    s.feed("hello");
    s.feed("\033[2J"); // erase entire screen
    EXPECT_EQ(s.text(), "\n\n");
}

// ── scroll ──────────────────────────────────────────────────────────

TEST(VtScreen, ScrollUp) {
    VtScreen s(2, 10);
    s.feed("line1\r\n");
    s.feed("line2\r\n"); // should scroll: line1 gone, line2 on row 0
    s.feed("line3");
    auto t = s.text();
    EXPECT_EQ(t.find("line1"), std::string::npos);
    EXPECT_NE(t.find("line2"), std::string::npos);
    EXPECT_NE(t.find("line3"), std::string::npos);
}

// ── alt screen ──────────────────────────────────────────────────────

TEST(VtScreen, AltScreen) {
    VtScreen s(3, 10);
    s.feed("main");
    s.feed("\033[?1049h"); // enter alt screen
    EXPECT_EQ(s.cursorRow(), 0);
    EXPECT_EQ(s.cursorCol(), 0);
    s.feed("alt");
    auto t = s.text();
    EXPECT_NE(t.find("alt"), std::string::npos);
    EXPECT_EQ(t.find("main"), std::string::npos);

    s.feed("\033[?1049l"); // exit alt screen
    t = s.text();
    EXPECT_NE(t.find("main"), std::string::npos);
}

// ── SGR ─────────────────────────────────────────────────────────────

TEST(VtScreen, SgrReset) {
    VtScreen s(2, 10);
    s.feed("\033[1m");         // bold
    s.feed("\033[38;2;255;0;0m"); // RGB red (ignored in text, but shouldn't crash)
    s.feed("hi");
    s.feed("\033[0m");         // reset
    s.feed("lo");
    auto t = s.text();
    EXPECT_NE(t.find("hilo"), std::string::npos);
}

// ── UTF-8 ───────────────────────────────────────────────────────────

TEST(VtScreen, Utf8TwoByte) {
    VtScreen s(1, 10);
    s.feed("caf\xc3\xa9"); // café
    auto t = s.text();
    EXPECT_NE(t.find("caf\xc3\xa9"), std::string::npos);
}

TEST(VtScreen, Utf8ThreeByte) {
    VtScreen s(1, 10);
    s.feed("\xe2\x9c\x93"); // ✓
    auto t = s.text();
    EXPECT_NE(t.find("\xe2\x9c\x93"), std::string::npos);
}

// ── control chars ───────────────────────────────────────────────────

TEST(VtScreen, CarriageReturn) {
    VtScreen s(1, 10);
    s.feed("hello");
    s.feed("\rworld");
    auto t = s.text();
    EXPECT_NE(t.find("world"), std::string::npos);
    EXPECT_EQ(t.find("hello"), std::string::npos); // overwritten
}

TEST(VtScreen, Tab) {
    VtScreen s(1, 20);
    s.feed("a\tb");
    EXPECT_EQ(s.cursorCol(), 9); // 'a' at 0, tab to 8, 'b' at 8, cursor at 9
}

TEST(VtScreen, Backspace) {
    VtScreen s(1, 10);
    s.feed("abc\b");
    EXPECT_EQ(s.cursorCol(), 2);
}

// ── mouse tracking flag ─────────────────────────────────────────────

TEST(VtScreen, MouseTrackingFlag) {
    VtScreen s(3, 10);
    EXPECT_FALSE(s.mouseTracking());
    s.feed("\033[?1000h");
    EXPECT_TRUE(s.mouseTracking());
    s.feed("\033[?1000l");
    EXPECT_FALSE(s.mouseTracking());
}

// ── resize ──────────────────────────────────────────────────────────

TEST(VtScreen, Resize) {
    VtScreen s(3, 10);
    s.feed("hello");
    s.resize(5, 20);
    EXPECT_EQ(s.rows(), 5);
    EXPECT_EQ(s.cols(), 20);
    // Content cleared on resize
    EXPECT_EQ(s.text(), "\n\n\n\n");
}

// ── DEC private modes (no crash) ────────────────────────────────────

TEST(VtScreen, DecPrivateModesNoCrash) {
    VtScreen s(3, 10);
    s.feed("\033[?25l");   // hide cursor
    s.feed("\033[?25h");   // show cursor
    s.feed("\033[?2026h"); // sync output begin
    s.feed("\033[?2026l"); // sync output end
    s.feed("\033[?1006h"); // SGR mouse
    // Should not crash
    EXPECT_TRUE(true);
}
