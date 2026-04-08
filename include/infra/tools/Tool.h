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
    std::string observation;
};

class ToolContext;

class Tool {
 public:
    virtual ~Tool() = default;

    virtual std::string name() const = 0;

    virtual std::string description() const = 0;

    virtual std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) = 0;
};

}  // namespace area
