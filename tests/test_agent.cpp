#include <gtest/gtest.h>
#include <memory>
#include "Agent.h"
#include "LLMBackend.h"


class AgentMockTest : public ::testing::Test {
protected:
    // Minimal fake database that doesn't connect anywhere
    // We test Agent's LLM interaction, not the DB path
};

TEST(AgentConstruction, AcceptsBackend) {
    // This just verifies compilation and construction work.
    // Full process() tests require a DB connection, so we test
    // the backend wiring here.
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* mockPtr = backend.get();

    mockPtr->setResponse("ANSWER: test answer");

    // We can't construct Agent without a Database reference,
    // but we can verify the backend is created correctly
    EXPECT_EQ(mockPtr->chat("sys", {{"user", "hi"}}), "ANSWER: test answer");
    EXPECT_EQ(mockPtr->callCount(), 1);
}

TEST(AgentConstruction, MockSequenceSimulatesMultiTurn) {
    // Simulate what the agent loop does: first call returns SQL,
    // second call returns ANSWER after seeing results
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    area::MockBackend mock(ep);
    mock.setResponses({
        "SQL: SELECT count(*) FROM malware_samples",
        "ANSWER: There are 42 malware samples in the database."
    });

    auto r1 = mock.chat("system", {{"user", "how many samples?"}});
    EXPECT_EQ(r1.substr(0, 4), "SQL:");

    auto r2 = mock.chat("system", {
        {"user", "how many samples?"},
        {"assistant", r1},
        {"user", "Results (1 rows):\ncount\n-----\n42"}
    });
    EXPECT_EQ(r2.substr(0, 7), "ANSWER:");
    EXPECT_EQ(mock.callCount(), 2);
}
