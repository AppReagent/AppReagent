#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "infra/config/Config.h"

namespace area {

struct ChatMessage {
    std::string role;
    std::string content;
};

struct TokenUsage {
    int prompt_tokens = 0;
    int completion_tokens = 0;
    int total_tokens = 0;
};

struct ChatResult {
    std::string content;
    TokenUsage usage;
};

class LLMBackend {
public:
    virtual ~LLMBackend() = default;

    virtual std::string chat(const std::string& system,
                             const std::vector<ChatMessage>& messages) = 0;

    virtual ChatResult chatWithUsage(const std::string& system,
                                     const std::vector<ChatMessage>& messages,
                                     int max_tokens = 0) {
        ChatResult r;
        r.content = chat(system, messages);
        return r;
    }

    std::atomic<int> totalPromptTokens{0};
    std::atomic<int> totalCompletionTokens{0};

    const AiEndpoint& endpoint() const { return endpoint_; }

    // Set a flag that, when true, aborts in-flight HTTP requests
    void setCancelFlag(std::atomic<bool>* flag) { cancelFlag_ = flag; }

    static std::unique_ptr<LLMBackend> create(const AiEndpoint& ep);

protected:
    explicit LLMBackend(const AiEndpoint& ep) : endpoint_(ep) {}
    AiEndpoint endpoint_;
    std::atomic<bool>* cancelFlag_ = nullptr;
};


class OllamaBackend : public LLMBackend {
public:
    explicit OllamaBackend(const AiEndpoint& ep) : LLMBackend(ep) {}

    std::string chat(const std::string& system,
                     const std::vector<ChatMessage>& messages) override;
};


class OpenAIBackend : public LLMBackend {
public:
    explicit OpenAIBackend(const AiEndpoint& ep) : LLMBackend(ep) {}

    std::string chat(const std::string& system,
                     const std::vector<ChatMessage>& messages) override;
    ChatResult chatWithUsage(const std::string& system,
                             const std::vector<ChatMessage>& messages,
                             int max_tokens = 0) override;
};


/// Structured mock prompt entry for MockBackend.
/// Structured mock prompt entry for MockBackend.
/// `match` checks system+all messages. `user_match` checks only the last user message.
struct MockPromptEntry {
    std::string id;                                     // e.g. "triage", "agent_scan"
    std::vector<std::string> match;                     // ALL must appear in system+messages
    std::vector<std::string> user_match;                // ALL must appear in last user message only
    std::string response;                               // response template with {{key}} placeholders
    std::unordered_map<std::string, std::string> data;  // interpolation values
};

class MockBackend : public LLMBackend {
public:
    explicit MockBackend(const AiEndpoint& ep);

    std::string chat(const std::string& system,
                     const std::vector<ChatMessage>& messages) override;

    void setResponse(const std::string& response) { std::lock_guard lk(mu_); canned_ = response; }
    void setResponses(std::vector<std::string> responses) { std::lock_guard lk(mu_); sequence_ = std::move(responses); seqIdx_ = 0; }
    void setPromptEntries(std::vector<MockPromptEntry> entries) { std::lock_guard lk(mu_); promptEntries_ = std::move(entries); }
    void setFailAfter(int n) { failAfter_.store(n); callCount_.store(0); }
    void setLatencyMs(int ms) { latencyMs_.store(ms); }

    int callCount() const { return callCount_.load(); }
    int peakConcurrent() const { return peakConcurrent_.load(); }
    int currentConcurrent() const { return concurrent_.load(); }
    ChatMessage lastUserMessage() const { std::lock_guard lk(mu_); return lastUser_; }
    std::string lastSystem() const { std::lock_guard lk(mu_); return lastSystem_; }
    std::string lastMatchedId() const { std::lock_guard lk(mu_); return lastMatchedId_; }

private:
    void loadResponseFile(const std::string& path);
    static std::string interpolate(const std::string& tmpl,
                                   const std::unordered_map<std::string, std::string>& data);

    mutable std::mutex mu_;
    std::string canned_ = "ANSWER: mock response";
    std::vector<std::string> sequence_;
    std::vector<std::pair<std::string, std::string>> routedResponses_;
    std::vector<MockPromptEntry> promptEntries_;
    std::string defaultResponse_;
    std::string lastMatchedId_;
    std::atomic<size_t> seqIdx_ = 0;
    std::atomic<int> failAfter_{-1};
    std::atomic<int> callCount_{0};
    std::atomic<int> latencyMs_{0};
    ChatMessage lastUser_;
    std::string lastSystem_;

    std::atomic<int> concurrent_{0};
    std::atomic<int> peakConcurrent_{0};
};

} // namespace area
