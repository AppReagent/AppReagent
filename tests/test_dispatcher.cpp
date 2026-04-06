#include <gtest/gtest.h>
#include <atomic>
#include <map>
#include <thread>

#include "ServerRunner.h"
#include "JobManager.h"
#include "LLMBackend.h"
#include "JobQueue.h"

// Helper: make a Job with given id and tier
static area::Job makeJob(int64_t id, int tier = 0, const std::string& payload = R"({"prompt":"test"})") {
    area::Job j;
    j.id = id;
    j.type = "code_scan";
    j.payload = payload;
    j.status = "in_progress";
    j.tier = tier;
    return j;
}

class ServerRunnerTest : public ::testing::Test {
protected:
    std::vector<int64_t> completedIds;
    std::vector<int64_t> failedIds;
    std::vector<int64_t> requeuedIds;
    std::mutex mu;

    area::OnJobComplete onComplete() {
        return [this](int64_t id, const std::string&) {
            std::lock_guard<std::mutex> lk(mu);
            completedIds.push_back(id);
        };
    }

    area::OnJobFail onFail() {
        return [this](int64_t id, const std::string&, bool requeue) {
            std::lock_guard<std::mutex> lk(mu);
            if (requeue) requeuedIds.push_back(id);
            else failedIds.push_back(id);
        };
    }
};

TEST_F(ServerRunnerTest, ProcessesJobs) {
    area::AiEndpoint ep{"test", "mock", "", "auto", "", 0, 2};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setLatencyMs(10);

    std::atomic<int> doneCount{0};
    auto countingComplete = [this, &doneCount](int64_t id, const std::string& r) {
        {
            std::lock_guard<std::mutex> lk(mu);
            completedIds.push_back(id);
        }
        doneCount++;
    };

    area::ServerRunner runner(std::move(backend), 0, 2, countingComplete, onFail());
    runner.start();

    runner.submit(makeJob(1));
    runner.submit(makeJob(2));
    runner.submit(makeJob(3));

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (doneCount.load() < 3 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    runner.stop();

    std::lock_guard<std::mutex> lk(mu);
    EXPECT_EQ(completedIds.size(), 3);
    EXPECT_TRUE(failedIds.empty());
}

TEST_F(ServerRunnerTest, EnforcesMaxConcurrent) {
    area::AiEndpoint ep{"test", "mock", "", "auto", "", 0, 2};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* mock = backend.get();
    mock->setLatencyMs(30);

    std::atomic<int> doneCount{0};
    auto countingComplete = [this, &doneCount](int64_t id, const std::string& r) {
        {
            std::lock_guard<std::mutex> lk(mu);
            completedIds.push_back(id);
        }
        doneCount++;
    };

    area::ServerRunner runner(std::move(backend), 0, 2, countingComplete, onFail());
    runner.start();

    // Submit 6 jobs (inbox buffers them all, 2 workers process at a time)
    for (int i = 1; i <= 6; i++) {
        runner.submit(makeJob(i));
    }

    // Wait for all 6 to complete (not a fixed sleep)
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (doneCount.load() < 6 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    runner.stop();

    // Key: mock should never have seen more than 2 concurrent calls
    // because there are only 2 worker threads
    EXPECT_LE(mock->peakConcurrent(), 2);
    EXPECT_EQ(mock->callCount(), 6);
}

TEST_F(ServerRunnerTest, RequeuesOnFailure) {
    area::AiEndpoint ep{"fail-server", "mock", "", "auto", "", 0, 1};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setFailAfter(0); // fail on first call

    area::ServerRunner runner(std::move(backend), 0, 1, onComplete(), onFail());
    runner.start();

    runner.submit(makeJob(42));

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lk(mu);
            if (!requeuedIds.empty()) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    runner.stop();

    std::lock_guard<std::mutex> lk(mu);
    EXPECT_TRUE(completedIds.empty());
    EXPECT_EQ(requeuedIds.size(), 1);
    EXPECT_EQ(requeuedIds[0], 42);
}

TEST_F(ServerRunnerTest, BackoffOnFailure) {
    area::AiEndpoint ep{"backoff-test", "mock", "", "auto", "", 0, 1};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setFailAfter(0);

    area::ServerRunner runner(std::move(backend), 0, 1, onComplete(), onFail());
    runner.start();

    runner.submit(makeJob(1));

    // Wait for the failure to be processed
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (runner.healthy() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // After failure, server should be unhealthy (in backoff)
    EXPECT_FALSE(runner.healthy());

    runner.stop();
}

TEST_F(ServerRunnerTest, AvailableCapacity) {
    area::AiEndpoint ep{"cap-test", "mock", "", "auto", "", 0, 3};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setLatencyMs(100);

    area::ServerRunner runner(std::move(backend), 0, 3, onComplete(), onFail());
    EXPECT_EQ(runner.available(), 3);
    EXPECT_EQ(runner.tier(), 0);
    EXPECT_EQ(runner.maxConcurrent(), 3);

    runner.start();
    runner.submit(makeJob(1));
    runner.submit(makeJob(2));

    // Wait for jobs to enter in-flight
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (runner.available() > 1 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    EXPECT_LE(runner.available(), 1);

    runner.stop();
}

TEST(TierRouting, FindsCorrectTier) {
    // Build runners at tiers 0, 1, 2
    std::vector<std::pair<int, int>> tiers = {{0, 1}, {1, 3}, {2, 4}};
    std::vector<std::unique_ptr<area::ServerRunner>> runners;

    for (auto& [tier, concurrency] : tiers) {
        area::AiEndpoint ep{"t" + std::to_string(tier), "mock", "", "auto", "", tier, concurrency};
        auto backend = std::make_unique<area::MockBackend>(ep);
        auto runner = std::make_unique<area::ServerRunner>(
            std::move(backend), tier, concurrency,
            [](int64_t, const std::string&) {},
            [](int64_t, const std::string&, bool) {});
        runners.push_back(std::move(runner));
    }

    // Verify tiers
    EXPECT_EQ(runners[0]->tier(), 0);
    EXPECT_EQ(runners[1]->tier(), 1);
    EXPECT_EQ(runners[2]->tier(), 2);

    // All should have capacity initially
    EXPECT_GT(runners[0]->available(), 0);
    EXPECT_GT(runners[1]->available(), 0);
    EXPECT_GT(runners[2]->available(), 0);
}

TEST(TierRouting, ThreeTierConfig) {
    // Mirrors the real config
    std::vector<area::AiEndpoint> endpoints = {
        {"low1", "mock", "", "auto", "", 0, 1},
        {"low2", "mock", "", "auto", "", 0, 1},
        {"med1", "mock", "", "auto", "", 1, 3},
        {"high1", "mock", "", "auto", "", 2, 4},
    };

    std::map<int, int> tierCounts;
    for (auto& ep : endpoints) tierCounts[ep.tier]++;

    EXPECT_EQ(tierCounts[0], 2);
    EXPECT_EQ(tierCounts[1], 1);
    EXPECT_EQ(tierCounts[2], 1);

    // Total capacity: 2*1 + 1*3 + 1*4 = 9
    int totalCap = 0;
    for (auto& ep : endpoints) totalCap += ep.max_concurrent;
    EXPECT_EQ(totalCap, 9);
}

TEST(JobStruct, DefaultTierIsZero) {
    area::Job j;
    EXPECT_EQ(j.tier, 0);
}
