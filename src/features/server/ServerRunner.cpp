#include "features/server/ServerRunner.h"

#include <iostream>
#include <nlohmann/json.hpp>

namespace area {

ServerRunner::ServerRunner(std::unique_ptr<LLMBackend> backend, int tier, int maxConcurrent,
                           OnJobComplete onComplete, OnJobFail onFail)
    : backend_(std::move(backend))
    , tier_(tier)
    , maxConcurrent_(maxConcurrent)
    , onComplete_(std::move(onComplete))
    , onFail_(std::move(onFail)) {}

ServerRunner::~ServerRunner() {
    stop();
}

void ServerRunner::start() {
    running_ = true;
    for (int i = 0; i < maxConcurrent_; i++) {
        workers_.emplace_back(&ServerRunner::workerLoop, this);
    }
}

void ServerRunner::stop() {
    running_ = false;
    inboxCv_.notify_all();
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
}

bool ServerRunner::submit(Job job) {
    if (!healthy()) return false;

    {
        std::lock_guard<std::mutex> lk(inboxMu_);
        inbox_.push(std::move(job));
    }
    inboxCv_.notify_one();
    return true;
}

int ServerRunner::available() const {
    return maxConcurrent_ - inFlight_.load();
}

void ServerRunner::workerLoop() {
    while (running_) {
        Job job;
        {
            std::unique_lock<std::mutex> lk(inboxMu_);
            inboxCv_.wait_for(lk, std::chrono::milliseconds(500), [this] {
                return !inbox_.empty() || !running_;
            });
            if (!running_ && inbox_.empty()) return;
            if (inbox_.empty()) continue;
            job = std::move(inbox_.front());
            inbox_.pop();
        }

        // Check if we're in backoff
        if (!healthy()) {
            auto now = std::chrono::steady_clock::now().time_since_epoch().count();
            auto until = backoffUntil_.load();
            if (now < until) {
                auto waitMs = (until - now) / 1000000;
                std::this_thread::sleep_for(std::chrono::milliseconds(waitMs));
            }
        }

        inFlight_++;

        try {
            auto jpayload = nlohmann::json::parse(job.payload);
            std::string prompt = jpayload.value("prompt", "");
            std::string system = jpayload.value("system", "You are a helpful assistant.");

            std::vector<ChatMessage> messages = {{"user", prompt}};
            std::string result = backend_->chat(system, messages);

            inFlight_--;
            resetBackoff();
            onComplete_(job.id, result);
        } catch (const std::exception& e) {
            inFlight_--;
            std::cerr << "[server:" << backend_->endpoint().id << "] job "
                      << job.id << " failed: " << e.what() << std::endl;
            applyBackoff();
            // Requeue so another agent can pick it up
            onFail_(job.id, e.what(), true);
        }
    }
}

void ServerRunner::applyBackoff() {
    std::lock_guard<std::mutex> lk(backoffMu_);
    if (backoffMs_ == 0) {
        backoffMs_ = INITIAL_BACKOFF_MS;
    } else {
        backoffMs_ = std::min(backoffMs_ * 2, MAX_BACKOFF_MS);
    }
    auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(backoffMs_);
    backoffUntil_.store(until.time_since_epoch().count());
    std::cerr << "[server:" << backend_->endpoint().id << "] backing off "
              << backoffMs_ << "ms" << std::endl;
}

void ServerRunner::resetBackoff() {
    std::lock_guard<std::mutex> lk(backoffMu_);
    backoffMs_ = 0;
    backoffUntil_.store(0);
}

} // namespace area
