#pragma once

#include <stddef.h>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>
#include <string>
#include <utility>

#include "infra/llm/LLMBackend.h"
#include "infra/config/Config.h"

namespace area {

class BackendPool : public LLMBackend {
 public:
    explicit BackendPool(const std::vector<AiEndpoint>& endpoints);
    BackendPool(const std::vector<AiEndpoint>& endpoints, int tier);

    std::string chat(const std::string& system,
                     const std::vector<ChatMessage>& messages) override;

    ChatResult chatWithUsage(const std::string& system,
                             const std::vector<ChatMessage>& messages,
                             int max_tokens = 0) override;

    size_t size() const { return backends_.size(); }
    int totalConcurrency() const;

 private:
    struct Slot {
        std::unique_ptr<LLMBackend> backend;
        int maxConcurrent;
        std::atomic<int> active{0};
    };

    Slot& acquire();
    void release(Slot& slot);

    template <typename Fn>
    auto withRetry(Fn&& fn) -> decltype(fn(std::declval<Slot&>()));

    static constexpr int MAX_RETRIES = 3;

    std::vector<std::unique_ptr<Slot>> backends_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::atomic<size_t> roundRobin_{0};
};

}  // namespace area
