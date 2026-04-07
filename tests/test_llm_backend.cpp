#include <gtest/gtest.h>
#include "infra/llm/LLMBackend.h"

TEST(LLMBackendFactory, CreatesOllama) {
    area::AiEndpoint ep{"id1", "ollama", "http://localhost:11434", "auto"};
    auto backend = area::LLMBackend::create(ep);
    ASSERT_NE(backend, nullptr);
    EXPECT_EQ(backend->endpoint().provider, "ollama");
    EXPECT_NE(dynamic_cast<area::OllamaBackend*>(backend.get()), nullptr);
}

TEST(LLMBackendFactory, CreatesOpenAI) {
    area::AiEndpoint ep{"id2", "openai", "http://localhost:1234", "qwen2.5-coder-14b"};
    auto backend = area::LLMBackend::create(ep);
    ASSERT_NE(backend, nullptr);
    EXPECT_NE(dynamic_cast<area::OpenAIBackend*>(backend.get()), nullptr);
}

TEST(LLMBackendFactory, LMStudioAliasWorks) {
    area::AiEndpoint ep{"id3", "lmstudio", "http://localhost:1234", "test"};
    auto backend = area::LLMBackend::create(ep);
    ASSERT_NE(backend, nullptr);
    EXPECT_NE(dynamic_cast<area::OpenAIBackend*>(backend.get()), nullptr);
}

TEST(LLMBackendFactory, CreatesMock) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = area::LLMBackend::create(ep);
    ASSERT_NE(backend, nullptr);
    EXPECT_NE(dynamic_cast<area::MockBackend*>(backend.get()), nullptr);
}

TEST(LLMBackendFactory, UnknownProviderThrows) {
    area::AiEndpoint ep{"bad", "anthropic", "http://localhost", "auto"};
    EXPECT_THROW(area::LLMBackend::create(ep), std::runtime_error);
}

class MockBackendTest : public ::testing::Test {
protected:
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    area::MockBackend mock{ep};
    std::vector<area::ChatMessage> msgs{{"user", "hello"}};
};

TEST_F(MockBackendTest, DefaultCannedResponse) {
    auto resp = mock.chat("system prompt", msgs);
    EXPECT_EQ(resp, "ANSWER: mock response");
}

TEST_F(MockBackendTest, CustomCannedResponse) {
    mock.setResponse("SQL: SELECT 1");
    auto resp = mock.chat("sys", msgs);
    EXPECT_EQ(resp, "SQL: SELECT 1");
}

TEST_F(MockBackendTest, SequenceResponses) {
    mock.setResponses({"first", "second", "third"});
    EXPECT_EQ(mock.chat("sys", msgs), "first");
    EXPECT_EQ(mock.chat("sys", msgs), "second");
    EXPECT_EQ(mock.chat("sys", msgs), "third");
    // Wraps around
    EXPECT_EQ(mock.chat("sys", msgs), "first");
}

TEST_F(MockBackendTest, CallCount) {
    EXPECT_EQ(mock.callCount(), 0);
    mock.chat("sys", msgs);
    EXPECT_EQ(mock.callCount(), 1);
    mock.chat("sys", msgs);
    mock.chat("sys", msgs);
    EXPECT_EQ(mock.callCount(), 3);
}

TEST_F(MockBackendTest, TracksLastMessage) {
    std::vector<area::ChatMessage> conversation = {
        {"user", "first"},
        {"assistant", "ok"},
        {"user", "analyze this malware"}
    };
    mock.chat("you are a malware analyst", conversation);
    EXPECT_EQ(mock.lastUserMessage().content, "analyze this malware");
    EXPECT_EQ(mock.lastSystem(), "you are a malware analyst");
}

TEST_F(MockBackendTest, FailAfter) {
    mock.setFailAfter(2);
    EXPECT_NO_THROW(mock.chat("sys", msgs)); // call 1
    EXPECT_NO_THROW(mock.chat("sys", msgs)); // call 2
    EXPECT_THROW(mock.chat("sys", msgs), std::runtime_error); // call 3
}

TEST_F(MockBackendTest, LatencySimulation) {
    mock.setLatencyMs(50);
    auto start = std::chrono::steady_clock::now();
    mock.chat("sys", msgs);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    EXPECT_GE(elapsed, 40); // allow small timing slack
}

TEST_F(MockBackendTest, EndpointAccessor) {
    EXPECT_EQ(mock.endpoint().id, "test");
    EXPECT_EQ(mock.endpoint().provider, "mock");
}
