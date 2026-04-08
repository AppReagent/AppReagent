#pragma once

#include <atomic>
#include <memory>
#include <thread>
#include <vector>
#include <algorithm>

#include "features/server/ClusterStatus.h"
#include "infra/config/Config.h"
#include "infra/db/Database.h"
#include "infra/jobs/JobQueue.h"
#include "features/server/ServerRunner.h"
#include "infra/llm/LLMBackend.h"

namespace area {
class JobManager : public ClusterStatusProvider {
 public:
    JobManager(std::vector<std::unique_ptr<ServerRunner>> runners,
               JobQueue& queue, int pollIntervalMs = 500,
               int flushTimeoutSec = 15);
    ~JobManager();

    void start();
    void stop();

    static std::unique_ptr<JobManager> fromConfig(const Config& config,
                                                   Database& db,
                                                   JobQueue& queue);

    const std::vector<std::unique_ptr<ServerRunner>>& runners() const { return runners_; }

    ClusterSnapshot snapshot() const override {
        ClusterSnapshot snap;
        for (auto& r : runners_) {
            snap.endpoints.push_back({
                r->id(),
                r->backend().endpoint().model,
                r->tier(),
                r->maxConcurrent() - r->available(),
                r->maxConcurrent(),
                r->healthy()
            });
        }
        return snap;
    }

 private:
    void mainLoop();

    ServerRunner* findServer(int minTier);

    std::vector<std::unique_ptr<ServerRunner>> runners_;
    JobQueue& queue_;
    int pollIntervalMs_;
    int flushTimeoutSec_;

    int maxTier_ = 0;

    std::atomic<bool> running_{false};
    std::thread mainThread_;
};
}  // namespace area
