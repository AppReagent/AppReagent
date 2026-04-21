#include "infra/jobs/JobManager.h"

#include <chrono>
#include <stdint.h>
#include <algorithm>
#include <iostream>
#include <compare>
#include <exception>
#include <string>
#include <utility>

namespace area {
JobManager::JobManager(std::vector<std::unique_ptr<ServerRunner>> runners,
                       JobQueue& queue, int pollIntervalMs, int flushTimeoutSec)
    : runners_(std::move(runners))
    , queue_(queue)
    , pollIntervalMs_(pollIntervalMs)
    , flushTimeoutSec_(flushTimeoutSec) {
    for (auto& r : runners_) {
        if (r->tier() > maxTier_) maxTier_ = r->tier();
    }
}

JobManager::~JobManager() {
    stop();
}

std::unique_ptr<JobManager> JobManager::fromConfig(const Config& config,
                                                    Database& db,
                                                    JobQueue& queue) {
    std::vector<std::unique_ptr<ServerRunner>> runners;

    for (auto& ep : config.ai_endpoints) {
        auto backend = LLMBackend::create(ep);

        auto onComplete = [&queue](int64_t job_id, const std::string& result) {
            queue.complete(job_id, result);
        };
        auto onFail = [&queue](int64_t job_id, const std::string& error, bool requeue) {
            if (requeue) {
                queue.requeue(job_id);
            } else {
                queue.fail(job_id, error);
            }
        };

        auto runner = std::make_unique<ServerRunner>(
            std::move(backend), ep.tier, ep.max_concurrent,
            std::move(onComplete), std::move(onFail));
        runners.push_back(std::move(runner));
    }

    return std::make_unique<JobManager>(
        std::move(runners), queue,
        500, config.flush_timeout_sec);
}

void JobManager::start() {
    queue_.ensureTable();

    for (auto& r : runners_) {
        r->start();
    }

    running_ = true;
    mainThread_ = std::thread(&JobManager::mainLoop, this);
}

void JobManager::stop() {
    running_ = false;
    if (mainThread_.joinable()) {
        mainThread_.join();
    }
    for (auto& r : runners_) {
        r->stop();
    }
}

ServerRunner* JobManager::findServer(int minTier) {
    for (int t = minTier; t <= maxTier_; t++) {
        ServerRunner* best = nullptr;
        int bestAvail = 0;
        for (auto& r : runners_) {
            if (r->tier() == t && r->healthy()) {
                int avail = r->available();
                if (avail > bestAvail) {
                    bestAvail = avail;
                    best = r.get();
                }
            }
        }
        if (best) return best;
    }
    return nullptr;
}

void JobManager::mainLoop() {
    auto lastActivity = std::chrono::steady_clock::now();

    while (running_) {
        int totalAvail = 0;
        for (auto& r : runners_) {
            if (r->healthy()) {
                totalAvail += r->available();
            }
        }

        if (totalAvail <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs_));
            continue;
        }

        std::vector<Job> batch;
        try {
            batch = queue_.dequeueAtOrBelow(maxTier_, totalAvail);
        } catch (const std::exception& e) {
            std::cerr << "[jobmanager] dequeue error: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        if (!batch.empty()) {
            lastActivity = std::chrono::steady_clock::now();

            for (auto& job : batch) {
                ServerRunner* server = findServer(job.tier);
                int64_t jobId = job.id;
                if (server) {
                    if (!server->submit(std::move(job))) {
                        queue_.requeue(jobId);
                    }
                } else {
                    queue_.requeue(jobId);
                }
            }
        } else {
            auto elapsed = std::chrono::steady_clock::now() - lastActivity;
            auto timeout = std::chrono::seconds(flushTimeoutSec_);
            if (elapsed > timeout) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(pollIntervalMs_));
            }
        }
    }
}
}  // namespace area
