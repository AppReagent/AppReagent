#pragma once

#include <memory>
#include <string>
#include <vector>

#include "infra/config/Config.h"
#include "infra/db/Database.h"

namespace area {

// Computes embedding vectors from text via Ollama or OpenAI-compatible APIs.
class EmbeddingBackend {
public:
    virtual ~EmbeddingBackend() = default;

    virtual std::vector<float> embed(const std::string& text) = 0;

    int dimensions() const { return dimensions_; }

    static std::unique_ptr<EmbeddingBackend> create(const EmbeddingEndpoint& ep);

protected:
    int dimensions_ = 1536;
};

class OllamaEmbeddingBackend : public EmbeddingBackend {
public:
    explicit OllamaEmbeddingBackend(const EmbeddingEndpoint& ep);
    std::vector<float> embed(const std::string& text) override;

private:
    std::string url_;
    std::string model_;
};

class OpenAIEmbeddingBackend : public EmbeddingBackend {
public:
    explicit OpenAIEmbeddingBackend(const EmbeddingEndpoint& ep);
    std::vector<float> embed(const std::string& text) override;

private:
    std::string url_;
    std::string model_;
    std::string api_key_;
};

// Stores and retrieves embeddings from PostgreSQL via pgvector.
class EmbeddingStore {
public:
    EmbeddingStore(Database& db, EmbeddingBackend* backend = nullptr);

    void store(const std::string& run_id,
               const std::string& file_path,
               const std::string& file_hash,
               const std::string& class_name,
               const std::string& method_name,
               const std::string& content,
               const std::vector<float>& embedding);

    struct SearchResult {
        std::string run_id;
        std::string file_path;
        std::string class_name;
        std::string method_name;
        std::string content;
        double similarity;
    };

    // Find top-K similar methods by cosine similarity.
    // If exclude_run_id is non-empty, excludes that run from results.
    std::vector<SearchResult> search(const std::vector<float>& query_embedding,
                                     int top_k = 5,
                                     const std::string& exclude_run_id = "");

    // Convenience: embed text then search.
    std::vector<SearchResult> searchByText(const std::string& text,
                                           int top_k = 5,
                                           const std::string& exclude_run_id = "");

    // Embed and store a method in one call.
    void embedAndStore(const std::string& run_id,
                       const std::string& file_path,
                       const std::string& file_hash,
                       const std::string& class_name,
                       const std::string& method_name,
                       const std::string& content);

    bool hasBackend() const { return backend_ != nullptr; }

    // Delete all embeddings for a run_id.
    void deleteRun(const std::string& run_id);

private:
    Database& db_;
    EmbeddingBackend* backend_;
};

} // namespace area
