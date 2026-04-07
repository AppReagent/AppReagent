#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "infra/agent/Harness.h"
#include "infra/llm/LLMBackend.h"
#include "infra/tools/ToolRegistry.h"

namespace area {

struct AgentMessage {
    enum Type { THINKING, SQL, RESULT, ANSWER, ERROR, TUI_CONTROL };
    Type type;
    std::string content;
};

using MessageCallback = std::function<void(const AgentMessage&)>;

struct ConfirmResult {
    enum Action { APPROVE, DENY, CUSTOM };
    Action action = APPROVE;
    std::string customText;
};

using ConfirmCallback = std::function<ConfirmResult(const std::string& description)>;

class Agent {
public:
    Agent(std::unique_ptr<LLMBackend> backend, ToolRegistry& tools,
          Harness harness = Harness::createDefault());
    Agent(LLMBackend* sharedBackend, ToolRegistry& tools,
          Harness harness = Harness::createDefault());

    void process(const std::string& userInput, MessageCallback cb,
                 ConfirmCallback confirm = nullptr);

    void interrupt();
    void clearHistory();

    LLMBackend& backend() const { return *backend_; }

    int contextPercent() const;
    int estimateTokens() const;
    void setSystemContext(const std::string& ctx) { systemContext_ = ctx; }
    void setPromptsDir(const std::string& dir) { promptsDir_ = dir; }

private:
    std::string buildSystemPrompt() const;
    std::string extractThought(const std::string& response, std::string& thought);
    void compressHistory(MessageCallback cb);

    std::unique_ptr<LLMBackend> ownedBackend_;
    LLMBackend* backend_ = nullptr;
    ToolRegistry& tools_;
    Harness harness_;
    std::string systemContext_;
    std::string promptsDir_;
    std::vector<ChatMessage> history_;
    std::atomic<bool> interrupted_{false};

    static constexpr int MAX_ITERATIONS = 25;
    static constexpr int ITERATION_WARNING = 20;
    static constexpr double COMPRESS_THRESHOLD = 0.9;
};

} // namespace area
