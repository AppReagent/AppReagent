#pragma once

#include <chrono>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

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

    // Subscribe to a specific event type
    void subscribe(EventType type, Callback cb);

    // Subscribe to all events
    void subscribe(Callback cb);

    void emit(Event event);

private:
    std::mutex mu_;
    std::vector<std::pair<EventType, Callback>> typed_;
    std::vector<Callback> global_;
};

} // namespace area
