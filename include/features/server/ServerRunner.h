#pragma once

#include <bits/chrono.h>
#include <stdint.h>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <string>

#include "infra/jobs/JobQueue.h"
#include "infra/llm/LLMBackend.h"
#include "infra/config/Config.h"

namespace area {

using OnJobComplete = std::function<void(int64_t job_id, const std::string& result)>;
using OnJobFail = std::function<void(int64_t job_id, const std::string& error, bool requeue)>;

class ServerRunner {
 public:
    ServerRunner(std::unique_ptr<LLMBackend> backend, int tier, int maxConcurrent,
                 OnJobComplete onComplete, OnJobFail onFail);
    ~ServerRunner();

    void start();
    void stop();

    bool submit(Job job);

    int available() const;
    int tier() const { return tier_; }
    int maxConcurrent() const { return maxConcurrent_; }
    bool healthy() const { return backoffUntil_.load() <= std::chrono::steady_clock::now().time_since_epoch().count(); }
    const std::string& id() const { return backend_->endpoint().id; }
    LLMBackend& backend() { return *backend_; }

 private:
    void workerLoop();
    void applyBackoff();
    void resetBackoff();

    std::unique_ptr<LLMBackend> backend_;
    int tier_;
    int maxConcurrent_;
    OnJobComplete onComplete_;
    OnJobFail onFail_;

    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};

    std::queue<Job> inbox_;
    std::mutex inboxMu_;
    std::condition_variable inboxCv_;

    std::atomic<int> inFlight_{0};

    std::atomic<int64_t> backoffUntil_{0};
    std::mutex backoffMu_;
    int backoffMs_ = 0;
    static constexpr int INITIAL_BACKOFF_MS = 2000;
    static constexpr int MAX_BACKOFF_MS = 300000;
};

}  // namespace area
