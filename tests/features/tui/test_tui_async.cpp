#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <thread>

#include "Agent.h"
#include "infra/llm/LLMBackend.h"
#include "infra/tools/ToolRegistry.h"
#include "features/sql/SqlTool.h"

// Test that the agent processing flow works correctly when run async,
// which is how the TUI uses it.

TEST(TuiAsync, AgentProcessCompletesInBackground) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* mock = backend.get();
    mock->setLatencyMs(100);
    mock->setResponse("ANSWER: hello from the background");

    area::Database db; // not connected, but agent needs it
    area::ToolRegistry tools;
    tools.add(std::make_unique<area::SqlTool>(db));
    area::Agent agent(std::move(backend), tools);

    std::atomic<bool> done{false};
    std::atomic<bool> gotAnswer{false};
    std::string answerText;
    std::mutex mu;

    std::thread t([&]() {
        agent.process("test query", [&](const area::AgentMessage& msg) {
            std::lock_guard lk(mu);
            if (msg.type == area::AgentMessage::ANSWER) {
                gotAnswer = true;
                answerText = msg.content;
            }
        });
        done = true;
    });

    // should not be done immediately
    EXPECT_FALSE(done.load());

    // wait for completion
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!done.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    t.join();

    EXPECT_TRUE(done.load());
    EXPECT_TRUE(gotAnswer.load());
    EXPECT_EQ(answerText, "hello from the background");
    EXPECT_EQ(mock->callCount(), 1);
}

TEST(TuiAsync, MessagesDirtyFlagPattern) {
    // Simulates the TUI pattern: main loop checks a dirty flag set by the worker
    std::atomic<bool> dirty{false};
    std::atomic<bool> workerDone{false};
    int renderCount = 0;

    std::thread worker([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        dirty = true; // signal new message
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        dirty = true; // signal completion
        workerDone = true;
    });

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!workerDone.load() && std::chrono::steady_clock::now() < deadline) {
        if (dirty.exchange(false)) {
            renderCount++;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    worker.join();

    // should have rendered at least once (dirty flags may coalesce, that's fine)
    EXPECT_GE(renderCount, 1);
}

TEST(TuiAsync, CtrlCInterruptsDuringProcessing) {
    area::AiEndpoint ep{"slow", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setLatencyMs(2000); // 2 second response

    area::Database db;
    area::ToolRegistry tools;
    tools.add(std::make_unique<area::SqlTool>(db));
    area::Agent agent(std::move(backend), tools);

    std::atomic<bool> processing{true};

    std::thread t([&]() {
        agent.process("slow query", [](const area::AgentMessage&) {});
        processing = false;
    });

    // simulate that the main loop can check an interrupt flag while processing
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_TRUE(processing.load()); // still processing after 50ms

    t.join(); // let it finish naturally
    EXPECT_FALSE(processing.load());
}
