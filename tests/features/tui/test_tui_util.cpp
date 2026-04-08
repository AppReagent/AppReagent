#include <gtest/gtest.h>
#include "features/frontend/tui/tui_util.h"
#include "util/string_util.h"

using namespace area::tui;
using area::util::truncateUTF8;

// ── truncateUTF8 ─────────────────────────────────────────────────────

TEST(TuiUtil, TruncateUTF8_EmptyString) {
    EXPECT_EQ(truncateUTF8("", 10), "");
}

TEST(TuiUtil, TruncateUTF8_FitsExactly) {
    EXPECT_EQ(truncateUTF8("abcde", 5), "abcde");
}

TEST(TuiUtil, TruncateUTF8_ShorterThanLimit) {
    EXPECT_EQ(truncateUTF8("abc", 10), "abc");
}

TEST(TuiUtil, TruncateUTF8_TruncatesASCII) {
    EXPECT_EQ(truncateUTF8("hello world", 5), "hello");
}

TEST(TuiUtil, TruncateUTF8_ZeroMax) {
    EXPECT_EQ(truncateUTF8("abc", 0), "");
}

TEST(TuiUtil, TruncateUTF8_NegativeMax) {
    EXPECT_EQ(truncateUTF8("abc", -1), "");
}

TEST(TuiUtil, TruncateUTF8_DoesNotSplitTwoByte) {
    // "ñ" is 0xC3 0xB1 (2 bytes)
    std::string s = "a\xc3\xb1" "b"; // "añb" = 4 bytes
    // Truncating at 2 bytes would land in the middle of ñ — should back up
    EXPECT_EQ(truncateUTF8(s, 2), "a");
    // Truncating at 3 bytes fits the full ñ
    EXPECT_EQ(truncateUTF8(s, 3), "a\xc3\xb1");
}

TEST(TuiUtil, TruncateUTF8_DoesNotSplitThreeByte) {
    // "€" is 0xE2 0x82 0xAC (3 bytes)
    std::string s = "x\xe2\x82\xac" "y"; // "x€y" = 5 bytes
    EXPECT_EQ(truncateUTF8(s, 2), "x");   // can't fit first byte of €
    EXPECT_EQ(truncateUTF8(s, 3), "x");   // can't fit second byte of €
    EXPECT_EQ(truncateUTF8(s, 4), "x\xe2\x82\xac");
}

TEST(TuiUtil, TruncateUTF8_DoesNotSplitFourByte) {
    // U+1F600 (😀) is 0xF0 0x9F 0x98 0x80 (4 bytes)
    std::string s = "\xf0\x9f\x98\x80" "!"; // "😀!" = 5 bytes
    EXPECT_EQ(truncateUTF8(s, 1), "");
    EXPECT_EQ(truncateUTF8(s, 3), "");
    EXPECT_EQ(truncateUTF8(s, 4), "\xf0\x9f\x98\x80");
}

// ── flowNoise ────────────────────────────────────────────────────────

TEST(TuiUtil, FlowNoise_BoundedOutput) {
    // Sum of amplitudes: 0.5 + 0.3 + 0.2 = 1.0, so output ∈ [-1, 1]
    for (int i = 0; i < 1000; i++) {
        double x = static_cast<double>(i) * 0.1;
        double t = static_cast<double>(i) * 7.0;
        double v = flowNoise(x, t);
        EXPECT_GE(v, -1.0001);
        EXPECT_LE(v, 1.0001);
    }
}

TEST(TuiUtil, FlowNoise_VariesWithPosition) {
    double a = flowNoise(0, 100);
    double b = flowNoise(10, 100);
    EXPECT_NE(a, b);
}

TEST(TuiUtil, FlowNoise_VariesWithTime) {
    double a = flowNoise(5, 0);
    double b = flowNoise(5, 1000);
    EXPECT_NE(a, b);
}

// ── noise2d ──────────────────────────────────────────────────────────

TEST(TuiUtil, Noise2d_OutputRange) {
    // Should return values in [0, 1] (approximately)
    for (int i = 0; i < 500; i++) {
        double x = static_cast<double>(i) * 0.3;
        double y = static_cast<double>(i) * 0.7;
        double t = static_cast<double>(i) * 2.0;
        double v = noise2d(x, y, t);
        EXPECT_GE(v, -0.01);
        EXPECT_LE(v, 1.01);
    }
}

TEST(TuiUtil, Noise2d_VariesSpatially) {
    double a = noise2d(0, 0, 50);
    double b = noise2d(10, 10, 50);
    EXPECT_NE(a, b);
}

// ── parseAgentType ───────────────────────────────────────────────────

TEST(TuiUtil, ParseAgentType_AllKnownTypes) {
    EXPECT_EQ(parseAgentType("thinking"), area::AgentMessage::THINKING);
    EXPECT_EQ(parseAgentType("sql"),      area::AgentMessage::SQL);
    EXPECT_EQ(parseAgentType("result"),   area::AgentMessage::RESULT);
    EXPECT_EQ(parseAgentType("answer"),   area::AgentMessage::ANSWER);
    EXPECT_EQ(parseAgentType("error"),    area::AgentMessage::ERROR);
}

TEST(TuiUtil, ParseAgentType_UnknownDefaultsToAnswer) {
    EXPECT_EQ(parseAgentType(""), area::AgentMessage::ANSWER);
    EXPECT_EQ(parseAgentType("unknown"), area::AgentMessage::ANSWER);
    EXPECT_EQ(parseAgentType("ANSWER"), area::AgentMessage::ANSWER); // case sensitive
}
