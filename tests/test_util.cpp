#include <gtest/gtest.h>
#include "util/convo_io.h"
#include "util/file_io.h"
#include "util/string_util.h"

#include <fstream>
#include <cstdio>

// ==================== escapeNewlines / unescapeNewlines ====================

TEST(ConvoIO, EscapeNewlines) {
    EXPECT_EQ(area::util::escapeNewlines("hello\nworld"), "hello\\nworld");
}

TEST(ConvoIO, EscapeBackslash) {
    EXPECT_EQ(area::util::escapeNewlines("back\\slash"), "back\\\\slash");
}

TEST(ConvoIO, EscapeEmpty) {
    EXPECT_EQ(area::util::escapeNewlines(""), "");
}

TEST(ConvoIO, EscapeNoSpecialChars) {
    EXPECT_EQ(area::util::escapeNewlines("plain text"), "plain text");
}

TEST(ConvoIO, EscapeMultipleNewlines) {
    EXPECT_EQ(area::util::escapeNewlines("\n\n\n"), "\\n\\n\\n");
}

TEST(ConvoIO, EscapeMixed) {
    EXPECT_EQ(area::util::escapeNewlines("a\\b\nc"), "a\\\\b\\nc");
}

TEST(ConvoIO, UnescapeNewlines) {
    EXPECT_EQ(area::util::unescapeNewlines("hello\\nworld"), "hello\nworld");
}

TEST(ConvoIO, UnescapeBackslash) {
    EXPECT_EQ(area::util::unescapeNewlines("back\\\\slash"), "back\\slash");
}

TEST(ConvoIO, UnescapeEmpty) {
    EXPECT_EQ(area::util::unescapeNewlines(""), "");
}

TEST(ConvoIO, UnescapeNoSpecialChars) {
    EXPECT_EQ(area::util::unescapeNewlines("plain text"), "plain text");
}

TEST(ConvoIO, UnescapeTrailingBackslash) {
    EXPECT_EQ(area::util::unescapeNewlines("end\\"), "end\\");
}

TEST(ConvoIO, RoundTrip) {
    std::string original = "line1\nline2\\path\nline3";
    EXPECT_EQ(area::util::unescapeNewlines(area::util::escapeNewlines(original)), original);
}

// ==================== readFile / readFileOrThrow ====================

TEST(FileIO, ReadFileMissing) {
    EXPECT_EQ(area::util::readFile("/tmp/area_test_nonexistent_file_xyz"), "");
}

TEST(FileIO, ReadFileContent) {
    std::string path = "/tmp/area_test_readfile.txt";
    { std::ofstream f(path); f << "hello world"; }
    EXPECT_EQ(area::util::readFile(path), "hello world");
    std::remove(path.c_str());
}

TEST(FileIO, ReadFileEmpty) {
    std::string path = "/tmp/area_test_readfile_empty.txt";
    { std::ofstream f(path); }
    EXPECT_EQ(area::util::readFile(path), "");
    std::remove(path.c_str());
}

TEST(FileIO, ReadFileOrThrowMissing) {
    EXPECT_THROW(area::util::readFileOrThrow("/tmp/area_test_nonexistent_xyz"), std::runtime_error);
}

TEST(FileIO, ReadFileOrThrowContent) {
    std::string path = "/tmp/area_test_readorthrow.txt";
    { std::ofstream f(path); f << "content"; }
    EXPECT_EQ(area::util::readFileOrThrow(path), "content");
    std::remove(path.c_str());
}

// ==================== trim / trimInPlace / ltrimInPlace / rtrimInPlace ====================

TEST(StringUtil, TrimBothSides) {
    EXPECT_EQ(area::util::trim("  hello  "), "hello");
}

TEST(StringUtil, TrimNewlines) {
    EXPECT_EQ(area::util::trim("\n\nhello\n\n"), "hello");
}

TEST(StringUtil, TrimMixed) {
    EXPECT_EQ(area::util::trim(" \n hello \n "), "hello");
}

TEST(StringUtil, TrimEmpty) {
    EXPECT_EQ(area::util::trim(""), "");
}

TEST(StringUtil, TrimAllWhitespace) {
    EXPECT_EQ(area::util::trim("   \n\n  "), "");
}

TEST(StringUtil, TrimNoChange) {
    EXPECT_EQ(area::util::trim("hello"), "hello");
}

TEST(StringUtil, TrimInPlace) {
    std::string s = " \nhello\n ";
    area::util::trimInPlace(s);
    EXPECT_EQ(s, "hello");
}

TEST(StringUtil, TrimInPlaceEmpty) {
    std::string s = "";
    area::util::trimInPlace(s);
    EXPECT_EQ(s, "");
}

TEST(StringUtil, LtrimInPlace) {
    std::string s = " \nhello ";
    area::util::ltrimInPlace(s);
    EXPECT_EQ(s, "hello ");
}

TEST(StringUtil, LtrimInPlaceNoLeft) {
    std::string s = "hello ";
    area::util::ltrimInPlace(s);
    EXPECT_EQ(s, "hello ");
}

TEST(StringUtil, RtrimInPlace) {
    std::string s = " hello\n ";
    area::util::rtrimInPlace(s);
    EXPECT_EQ(s, " hello");
}

TEST(StringUtil, RtrimInPlaceNoRight) {
    std::string s = " hello";
    area::util::rtrimInPlace(s);
    EXPECT_EQ(s, " hello");
}
