#include <gtest/gtest.h>
#include "Embedding.h"
#include "Config.h"

using namespace area;

class EmbeddingHelperTest : public ::testing::Test {
protected:
    Database db_;
};

TEST_F(EmbeddingHelperTest, StoreWithoutBackendReturnsEmpty) {
    EmbeddingStore store(db_);
    EXPECT_FALSE(store.hasBackend());

    auto results = store.searchByText("test query");
    EXPECT_TRUE(results.empty());
}

TEST_F(EmbeddingHelperTest, EmbedAndStoreSkipsWithoutBackend) {
    EmbeddingStore store(db_);
    // Should not throw — just silently skips
    EXPECT_NO_THROW(store.embedAndStore("run1", "/path", "hash", "Class", "method", "content"));
}

TEST(EmbeddingBackendTest, CreateOllamaBackend) {
    EmbeddingEndpoint ep;
    ep.provider = "ollama";
    ep.url = "http://localhost:11434";
    ep.model = "nomic-embed-text";
    ep.dimensions = 1536;

    auto backend = EmbeddingBackend::create(ep);
    ASSERT_NE(backend, nullptr);
    EXPECT_EQ(backend->dimensions(), 1536);
}

TEST(EmbeddingBackendTest, CreateOpenAIBackend) {
    EmbeddingEndpoint ep;
    ep.provider = "openai";
    ep.url = "http://localhost:1234";
    ep.model = "text-embedding-3-small";
    ep.dimensions = 1536;

    auto backend = EmbeddingBackend::create(ep);
    ASSERT_NE(backend, nullptr);
    EXPECT_EQ(backend->dimensions(), 1536);
}

TEST(EmbeddingBackendTest, CreateLMStudioBackend) {
    EmbeddingEndpoint ep;
    ep.provider = "lmstudio";
    ep.url = "http://localhost:1234";
    ep.model = "nomic-embed-text";
    ep.dimensions = 1536;

    auto backend = EmbeddingBackend::create(ep);
    ASSERT_NE(backend, nullptr);
}

TEST(EmbeddingBackendTest, UnknownProviderThrows) {
    EmbeddingEndpoint ep;
    ep.provider = "unknown";
    EXPECT_THROW(EmbeddingBackend::create(ep), std::runtime_error);
}

#include "tools/SimilarTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"

TEST(SimilarToolTest, ConstructsWithoutEmbeddingConfig) {
    Config config;
    Database db;
    SimilarTool tool(nullptr, db);
    EXPECT_FALSE(tool.available());
}

TEST(SimilarToolTest, DoesNotMatchNonSimilarActions) {
    Database db;
    SimilarTool tool(nullptr, db);
    Harness h;
    ToolContext ctx{[](const AgentMessage&){}, nullptr, h};

    EXPECT_FALSE(tool.tryExecute("SQL: SELECT 1", ctx).has_value());
    EXPECT_FALSE(tool.tryExecute("SCAN: /path", ctx).has_value());
    EXPECT_FALSE(tool.tryExecute("ANSWER: hello", ctx).has_value());
}

TEST(SimilarToolTest, MatchesSimilarPrefix) {
    Database db;
    SimilarTool tool(nullptr, db);
    Harness h;
    ToolContext ctx{[](const AgentMessage&){}, nullptr, h};

    auto result = tool.tryExecute("SIMILAR: SMS exfiltration", ctx);
    ASSERT_TRUE(result.has_value());
    // Should report embedding not available since no config
    EXPECT_NE(result->observation.find("not available"), std::string::npos);
}

TEST(SimilarToolTest, EmptyQueryReturnsError) {
    Database db;
    SimilarTool tool(nullptr, db);
    Harness h;
    ToolContext ctx{[](const AgentMessage&){}, nullptr, h};

    auto result = tool.tryExecute("SIMILAR:   ", ctx);
    ASSERT_TRUE(result.has_value());
    EXPECT_NE(result->observation.find("Error"), std::string::npos);
}
