#pragma once

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include "ClusterStatus.h"
#include "Config.h"
#include "Database.h"
#include "JobQueue.h"
#include "ServerRunner.h"

namespace area {

class JobManager : public ClusterStatusProvider {
public:
    // Takes ownership of runners. Dependency-injected: you build the runners,
    // the manager just routes jobs to them.
    JobManager(std::vector<std::unique_ptr<ServerRunner>> runners,
               JobQueue& queue, int pollIntervalMs = 500,
               int flushTimeoutSec = 15);
    ~JobManager();

    void start();
    void stop();

    // Convenience: build runners from config and wire up the callbacks
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

    // Find a healthy server with capacity, starting at minTier and moving up.
    // Returns nullptr if nothing available.
    ServerRunner* findServer(int minTier);

    std::vector<std::unique_ptr<ServerRunner>> runners_;
    JobQueue& queue_;
    int pollIntervalMs_;
    int flushTimeoutSec_;

    // Max tier across all runners
    int maxTier_ = 0;

    std::atomic<bool> running_{false};
    std::thread mainThread_;
};

} // namespace area
