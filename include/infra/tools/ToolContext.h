#pragma once

#include <functional>
#include <string>

namespace area {

struct AgentMessage;
struct ConfirmResult;
class Harness;

struct ToolContext {
    std::function<void(const AgentMessage&)> cb;
    std::function<ConfirmResult(const std::string&)> confirm;
    Harness& harness;
};

} // namespace area
