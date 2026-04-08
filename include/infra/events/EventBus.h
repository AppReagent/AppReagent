#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>
#include <utility>

namespace area {

enum class EventType {
    TOOL_START,
    TOOL_END,
    LLM_CALL,
    NODE_START,
    NODE_END,
    SCAN_FILE_START,
    SCAN_FILE_END,
    SCAN_PROGRESS,
    AGENT_THOUGHT,
    AGENT_ANSWER,
    AGENT_MSG_SQL,
    AGENT_MSG_RESULT,
    AGENT_MSG_ERROR,
    AGENT_MSG_TUI_CONTROL,
    AGENT_MSG_STATE,
};

struct Event {
    EventType type;
    std::string source;
    std::string detail;
    std::string chatId;
    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
};

using SubscriptionId = uint64_t;

class EventBus {
 public:
    using Callback = std::function<void(const Event&)>;

    SubscriptionId subscribe(EventType type, Callback cb);

    SubscriptionId subscribe(Callback cb);

    void unsubscribe(SubscriptionId id);

    void emit(Event event);

 private:
    std::mutex mu_;
    uint64_t nextId_ = 1;

    struct TypedSub {
        SubscriptionId id;
        EventType type;
        Callback cb;
    };
    struct GlobalSub {
        SubscriptionId id;
        Callback cb;
    };

    std::vector<TypedSub> typed_;
    std::vector<GlobalSub> global_;
};

}  // namespace area
