#pragma once

#include <bits/chrono.h>
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
};

struct Event {
    EventType type;
    std::string source;
    std::string detail;
    std::chrono::steady_clock::time_point timestamp = std::chrono::steady_clock::now();
};

class EventBus {
 public:
    using Callback = std::function<void(const Event&)>;

    void subscribe(EventType type, Callback cb);

    void subscribe(Callback cb);

    void emit(Event event);

 private:
    std::mutex mu_;
    std::vector<std::pair<EventType, Callback>> typed_;
    std::vector<Callback> global_;
};

}  // namespace area
