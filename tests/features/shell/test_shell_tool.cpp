#include <gtest/gtest.h>

#include <optional>
#include <vector>

#include "features/shell/ShellTool.h"
#include "infra/agent/Agent.h"
#include "infra/agent/Harness.h"
#include "infra/tools/ToolContext.h"

namespace {
area::ToolContext makeToolContext(std::vector<area::AgentMessage>& messages) {
    static area::Harness harness = area::Harness::createDefault();
    return area::ToolContext{
        [&](const area::AgentMessage& msg) { messages.push_back(msg); },
        nullptr,
        harness
    };
}
}  // namespace

TEST(ShellTool, IgnoresNonShellAction) {
    area::ShellTool tool;
    std::vector<area::AgentMessage> messages;
    auto ctx = makeToolContext(messages);

    auto result = tool.tryExecute("READ: /tmp/file", ctx);

    EXPECT_FALSE(result.has_value());
    EXPECT_TRUE(messages.empty());
}

TEST(ShellTool, ExecutesCommandOnHost) {
    area::ShellTool tool;
    std::vector<area::AgentMessage> messages;
    auto ctx = makeToolContext(messages);

    auto result = tool.tryExecute("SHELL: printf hello", ctx);

    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("exit code: 0"), std::string::npos);
    EXPECT_NE(result->observation.find("hello"), std::string::npos);
    ASSERT_GE(messages.size(), 2u);
    EXPECT_EQ(messages.front().type, area::AgentMessage::THINKING);
    EXPECT_EQ(messages.back().type, area::AgentMessage::RESULT);
}
