#include <gtest/gtest.h>
#include "infra/config/ArgParse.h"
#include "infra/config/Error.h"

// Helper to build argv from strings
struct ArgHelper {
    std::vector<std::string> strs;
    std::vector<char*> ptrs;

    ArgHelper(std::initializer_list<std::string> args) : strs(args) {
        for (auto& s : strs) ptrs.push_back(s.data());
    }
    int argc() const { return (int)ptrs.size(); }
    char** argv() { return ptrs.data(); }
};

// ==================== ArgParse Tests ====================

TEST(ArgParse, PositionalArgsOnly) {
    ArgHelper args{"area", "scan", "/path/to/file"};
    area::ArgParse parser(args.argc(), args.argv());
    auto err = parser.parse();
    EXPECT_FALSE(err.has_value());
    EXPECT_EQ(parser.getPositionalArg(0).value(), "area");
    EXPECT_EQ(parser.getPositionalArg(1).value(), "scan");
    EXPECT_EQ(parser.getPositionalArg(2).value(), "/path/to/file");
}

TEST(ArgParse, NamedArgs) {
    ArgHelper args{"area", "--config", "/etc/area.json", "--tier", "2"};
    area::ArgParse parser(args.argc(), args.argv());
    auto err = parser.parse();
    EXPECT_FALSE(err.has_value());
    // "area" is positional (before first --)
    EXPECT_EQ(parser.getPositionalArg(0).value(), "area");
    EXPECT_EQ(parser.getNamedArg("config").value(), "/etc/area.json");
    EXPECT_EQ(parser.getNamedArg("tier").value(), "2");
}

TEST(ArgParse, MixedPositionalAndNamed) {
    ArgHelper args{"area", "scan", "--output", "results.json"};
    area::ArgParse parser(args.argc(), args.argv());
    auto err = parser.parse();
    EXPECT_FALSE(err.has_value());
    EXPECT_EQ(parser.getPositionalArg(0).value(), "area");
    EXPECT_EQ(parser.getPositionalArg(1).value(), "scan");
    EXPECT_EQ(parser.getNamedArg("output").value(), "results.json");
}

TEST(ArgParse, MissingNamedArgValue) {
    ArgHelper args{"area", "--config"};
    area::ArgParse parser(args.argc(), args.argv());
    auto err = parser.parse();
    ASSERT_TRUE(err.has_value());
    EXPECT_EQ(err.value(), area::Error::ExpectedNamedArgValue);
}

TEST(ArgParse, OutOfBoundsPositionalArg) {
    ArgHelper args{"area"};
    area::ArgParse parser(args.argc(), args.argv());
    parser.parse();
    EXPECT_TRUE(parser.getPositionalArg(0).has_value());
    EXPECT_FALSE(parser.getPositionalArg(1).has_value());
    EXPECT_FALSE(parser.getPositionalArg(99).has_value());
}

TEST(ArgParse, MissingNamedArg) {
    ArgHelper args{"area", "--foo", "bar"};
    area::ArgParse parser(args.argc(), args.argv());
    parser.parse();
    EXPECT_FALSE(parser.getNamedArg("nonexistent").has_value());
}

TEST(ArgParse, EmptyArgs) {
    std::vector<char*> ptrs;
    area::ArgParse parser(0, ptrs.data());
    auto err = parser.parse();
    EXPECT_FALSE(err.has_value());
    EXPECT_FALSE(parser.getPositionalArg(0).has_value());
}

TEST(ArgParse, DoubleParseSafe) {
    ArgHelper args{"area", "scan"};
    area::ArgParse parser(args.argc(), args.argv());
    parser.parse();
    auto err2 = parser.parse(); // second parse should be no-op
    EXPECT_FALSE(err2.has_value());
    EXPECT_EQ(parser.getPositionalArg(0).value(), "area");
}

// ==================== Error Tests ====================

TEST(Error, ToStrKnownErrors) {
    EXPECT_EQ(area::toStr(area::Error::ExpectedNamedArgValue), "ExpectedNamedArgValue");
    EXPECT_EQ(area::toStr(area::Error::NotYetParsed), "NotYetParsed");
    EXPECT_EQ(area::toStr(area::Error::NoSuchPositionalArg), "NoSuchPositionalArg");
    EXPECT_EQ(area::toStr(area::Error::UnknownCommand), "UnknownCommand");
    EXPECT_EQ(area::toStr(area::Error::UnknownDirectory), "UnknownDirectory");
}

TEST(Error, ToStrUnknownError) {
    // Cast an out-of-range value to Error
    auto unknown = static_cast<area::Error>(9999);
    EXPECT_EQ(area::toStr(unknown), "(UnknownError!)");
}
