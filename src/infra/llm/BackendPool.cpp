#include "infra/llm/BackendPool.h"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <algorithm>
#include <exception>

namespace area {
static AiEndpoint poolEndpoint(const std::vector<AiEndpoint>& endpoints) {
    if (endpoints.empty()) {
        return AiEndpoint{"pool", "pool", "", "auto", "", 0, 1, 8192};
    }
    AiEndpoint ep = endpoints[0];
    ep.id = "pool";
    for (auto& e : endpoints) {
        ep.context_window = std::max(ep.context_window, e.context_window);
    }
    return ep;
}

static bool isTransient(const std::string& err) {
    return err.find("Timeout") != std::string::npos ||
           err.find("timeout") != std::string::npos ||
           err.find("504") != std::string::npos ||
           err.find("502") != std::string::npos ||
           err.find("503") != std::string::npos ||
           err.find("429") != std::string::npos ||
           err.find("rate limit") != std::string::npos ||
           err.find("Connection refused") != std::string::npos ||
           err.find("connection") != std::string::npos ||
           err.find("Could not resolve") != std::string::npos ||
           err.find("context length") != std::string::npos ||
           err.find("context_length") != std::string::npos ||
           err.find("maximum input length") != std::string::npos ||
           err.find("input tokens") != std::string::npos ||
           err.find("response content is null") != std::string::npos ||
           err.find("response content is \"None\"") != std::string::npos;
}

BackendPool::BackendPool(const std::vector<AiEndpoint>& endpoints)
    : LLMBackend(poolEndpoint(endpoints)) {
    for (auto& ep : endpoints) {
        auto slot = std::make_unique<Slot>();
        slot->maxConcurrent = ep.max_concurrent;
        slot->backend = LLMBackend::create(ep);
        backends_.push_back(std::move(slot));
    }
}

BackendPool::BackendPool(const std::vector<AiEndpoint>& endpoints, int tier)
    : LLMBackend(poolEndpoint(endpoints)) {
    std::vector<AiEndpoint> filtered;
    for (auto& ep : endpoints) {
        if (ep.tier != tier) continue;
        filtered.push_back(ep);
        auto slot = std::make_unique<Slot>();
        slot->maxConcurrent = ep.max_concurrent;
        slot->backend = LLMBackend::create(ep);
        backends_.push_back(std::move(slot));
    }
    if (backends_.empty()) {
        for (auto& ep : endpoints) {
            auto slot = std::make_unique<Slot>();
            slot->maxConcurrent = ep.max_concurrent;
            slot->backend = LLMBackend::create(ep);
            backends_.push_back(std::move(slot));
        }
    } else {
        endpoint_ = poolEndpoint(filtered);
    }
}

int BackendPool::totalConcurrency() const {
    int total = 0;
    for (auto& s : backends_) total += s->maxConcurrent;
    return total;
}

BackendPool::Slot& BackendPool::acquire() {
    std::unique_lock lk(mu_);

    while (true) {
        size_t n = backends_.size();
        size_t start = roundRobin_.fetch_add(1) % n;
        for (size_t i = 0; i < n; i++) {
            auto& slot = *backends_[(start + i) % n];
            if (slot.active.load() < slot.maxConcurrent) {
                slot.active.fetch_add(1);
                return slot;
            }
        }
        cv_.wait(lk);
    }
}

void BackendPool::release(Slot& slot) {
    slot.active.fetch_sub(1);
    cv_.notify_one();
}

template <typename Fn>
auto BackendPool::withRetry(Fn&& fn) -> decltype(fn(std::declval<Slot&>())) {
    if (backends_.empty()) throw std::runtime_error("BackendPool: no backends configured");

    std::string lastError;
    for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            int delayMs = 1000 * (1 << (attempt - 1));
            std::cerr << "[pool] retry " << attempt << "/" << MAX_RETRIES
                      << " after " << delayMs << "ms (" << lastError << ")" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }

        auto& slot = acquire();
        try {
            auto result = fn(slot);
            release(slot);
            return result;
        } catch (const std::runtime_error& e) {
            release(slot);
            lastError = e.what();
            if (!isTransient(lastError)) throw;
        } catch (const std::exception& e) {
            release(slot);
            lastError = e.what();
            if (!isTransient(lastError)) throw;
        }
    }

    throw std::runtime_error("BackendPool: all " + std::to_string(MAX_RETRIES + 1) +
                             " attempts failed. Last error: " + lastError);
}

std::string BackendPool::chat(const std::string& system,
                              const std::vector<ChatMessage>& messages) {
    return withRetry([&](Slot& slot) {
        slot.backend->setCancelFlag(cancelFlag_);
        try {
            auto result = slot.backend->chat(system, messages);
            slot.backend->setCancelFlag(nullptr);
            totalPromptTokens += slot.backend->totalPromptTokens.exchange(0);
            totalCompletionTokens += slot.backend->totalCompletionTokens.exchange(0);
            return result;
        } catch (...) {
            slot.backend->setCancelFlag(nullptr);
            throw;
        }
    });
}

ChatResult BackendPool::chatWithUsage(const std::string& system,
                                       const std::vector<ChatMessage>& messages,
                                       int max_tokens) {
    return withRetry([&](Slot& slot) {
        slot.backend->setCancelFlag(cancelFlag_);
        try {
            auto result = slot.backend->chatWithUsage(system, messages, max_tokens);
            slot.backend->setCancelFlag(nullptr);
            totalPromptTokens += result.usage.prompt_tokens;
            totalCompletionTokens += result.usage.completion_tokens;
            return result;
        } catch (...) {
            slot.backend->setCancelFlag(nullptr);
            throw;
        }
    });
}
}  // namespace area
