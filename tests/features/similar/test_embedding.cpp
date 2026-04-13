#include <gtest/gtest.h>
#include "infra/llm/Embedding.h"
#include "infra/llm/RagProvider.h"
#include "infra/config/Config.h"

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

TEST_F(EmbeddingHelperTest, RagProviderNullWhenNoEmbeddingConfig) {
    Config cfg;
    auto rag = RagProvider::create(cfg, db_);
    EXPECT_EQ(rag, nullptr);
}

TEST_F(EmbeddingHelperTest, RagProviderNullForUnknownProvider) {
    Config cfg;
    EmbeddingEndpoint ep;
    ep.provider = "bogus";
    cfg.embedding = ep;
    auto rag = RagProvider::create(cfg, db_);
    EXPECT_EQ(rag, nullptr);
}

TEST_F(EmbeddingHelperTest, RagProviderVultrRequiresCollectionId) {
    Config cfg;
    EmbeddingEndpoint ep;
    ep.provider = "vultr";
    ep.url = "https://api.vultrinference.com";
    ep.api_key = "test-key";
    // collection_id intentionally left blank
    cfg.embedding = ep;
    auto rag = RagProvider::create(cfg, db_);
    ASSERT_NE(rag, nullptr);
    EXPECT_FALSE(rag->available());
}

TEST_F(EmbeddingHelperTest, RagProviderVultrAvailableWithCollectionId) {
    Config cfg;
    EmbeddingEndpoint ep;
    ep.provider = "vultr";
    ep.url = "https://api.vultrinference.com";
    ep.api_key = "test-key";
    ep.collection_id = "test_collection";
    cfg.embedding = ep;
    auto rag = RagProvider::create(cfg, db_);
    ASSERT_NE(rag, nullptr);
    EXPECT_TRUE(rag->available());  // flags-only check; actual HTTP not exercised
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

#include "features/similar/SimilarTool.h"
#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "infra/agent/Harness.h"

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
