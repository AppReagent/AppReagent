#pragma once

#include <functional>
#include <optional>
#include <string>

namespace area {

struct AgentMessage;
using MessageCallback = std::function<void(const AgentMessage&)>;
struct ConfirmResult;
using ConfirmCallback = std::function<ConfirmResult(const std::string& description)>;

struct ToolResult {
    std::string observation; // pushed to agent history as user message
};

class ToolContext;

class Tool {
public:
    virtual ~Tool() = default;

    // Short name used as prefix, e.g. "SQL", "SCAN", "SHELL"
    virtual std::string name() const = 0;

    // One-line description for the LLM system prompt
    virtual std::string description() const = 0;

    // Try to match and execute. Returns nullopt if this tool doesn't match the action.
    virtual std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) = 0;
};

} // namespace area
