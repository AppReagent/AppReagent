#include "Embedding.h"

#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>

namespace area {

// RAII wrapper (same as LLMBackend.cpp)
struct EmbCurlHandle {
    CURL* curl = nullptr;
    struct curl_slist* headers = nullptr;

    EmbCurlHandle() : curl(curl_easy_init()) {
        if (!curl) throw std::runtime_error("curl init failed");
    }
    ~EmbCurlHandle() {
        if (headers) curl_slist_free_all(headers);
        if (curl) curl_easy_cleanup(curl);
    }
    EmbCurlHandle(const EmbCurlHandle&) = delete;
    EmbCurlHandle& operator=(const EmbCurlHandle&) = delete;
};

// --- HTTP helper (same pattern as LLMBackend.cpp) ---

static size_t embCurlWriteCb(char* data, size_t size, size_t nmemb, std::string* out) {
    size_t total = size * nmemb;
    out->append(data, total);
    return total;
}

static std::string embHttpPost(const std::string& url,
                               const std::string& body,
                               const std::string& api_key = "") {
    EmbCurlHandle ch;

    ch.headers = curl_slist_append(ch.headers, "Content-Type: application/json");
    if (!api_key.empty()) {
        ch.headers = curl_slist_append(ch.headers,
            ("Authorization: Bearer " + api_key).c_str());
    }

    std::string response;
    curl_easy_setopt(ch.curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(ch.curl, CURLOPT_HTTPHEADER, ch.headers);
    curl_easy_setopt(ch.curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(ch.curl, CURLOPT_WRITEFUNCTION, embCurlWriteCb);
    curl_easy_setopt(ch.curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(ch.curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(ch.curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(ch.curl);

    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("embedding HTTP request failed: ") + curl_easy_strerror(res));
    }
    return response;
}

// --- EmbeddingBackend factory ---

std::unique_ptr<EmbeddingBackend> EmbeddingBackend::create(const EmbeddingEndpoint& ep) {
    if (ep.provider == "ollama") return std::make_unique<OllamaEmbeddingBackend>(ep);
    if (ep.provider == "openai" || ep.provider == "lmstudio")
        return std::make_unique<OpenAIEmbeddingBackend>(ep);
    throw std::runtime_error("unknown embedding provider: " + ep.provider);
}

// --- Ollama ---

OllamaEmbeddingBackend::OllamaEmbeddingBackend(const EmbeddingEndpoint& ep)
    : url_(ep.url), model_(ep.model) {
    dimensions_ = ep.dimensions;
}

std::vector<float> OllamaEmbeddingBackend::embed(const std::string& text) {
    nlohmann::json body = {
        {"model", model_},
        {"input", text},
    };

    std::string raw = embHttpPost(url_ + "/api/embed", body.dump());
    auto j = nlohmann::json::parse(raw);

    if (j.contains("error")) {
        throw std::runtime_error("ollama embedding error: " + j["error"].dump());
    }

    // Ollama /api/embed returns {"embeddings": [[...]]}
    if (!j.contains("embeddings") || !j["embeddings"].is_array() || j["embeddings"].empty()) {
        throw std::runtime_error("ollama embedding error: response missing 'embeddings' array");
    }
    auto& arr = j["embeddings"][0];
    std::vector<float> result;
    result.reserve(arr.size());
    for (auto& v : arr) {
        result.push_back(v.get<float>());
    }
    return result;
}

// --- OpenAI ---

OpenAIEmbeddingBackend::OpenAIEmbeddingBackend(const EmbeddingEndpoint& ep)
    : url_(ep.url), model_(ep.model), api_key_(ep.api_key) {
    dimensions_ = ep.dimensions;
}

std::vector<float> OpenAIEmbeddingBackend::embed(const std::string& text) {
    nlohmann::json body = {
        {"model", model_},
        {"input", text},
    };

    std::string raw = embHttpPost(url_ + "/v1/embeddings", body.dump(), api_key_);
    auto j = nlohmann::json::parse(raw);

    if (j.contains("error")) {
        throw std::runtime_error("openai embedding error: " + j["error"].dump());
    }

    // OpenAI format: {"data": [{"embedding": [...]}]}
    if (!j.contains("data") || !j["data"].is_array() || j["data"].empty() ||
        !j["data"][0].contains("embedding")) {
        throw std::runtime_error("openai embedding error: response missing 'data[0].embedding'");
    }
    auto& arr = j["data"][0]["embedding"];
    std::vector<float> result;
    result.reserve(arr.size());
    for (auto& v : arr) {
        result.push_back(v.get<float>());
    }
    return result;
}

// --- EmbeddingStore ---

EmbeddingStore::EmbeddingStore(Database& db, EmbeddingBackend* backend)
    : db_(db), backend_(backend) {}

std::string EmbeddingStore::escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    return out;
}

std::string EmbeddingStore::vectorToSql(const std::vector<float>& v) {
    std::ostringstream ss;
    ss << "'[";
    for (size_t i = 0; i < v.size(); i++) {
        if (i > 0) ss << ',';
        ss << v[i];
    }
    ss << "]'";
    return ss.str();
}

void EmbeddingStore::store(const std::string& run_id,
                           const std::string& file_path,
                           const std::string& file_hash,
                           const std::string& class_name,
                           const std::string& method_name,
                           const std::string& content,
                           const std::vector<float>& embedding) {
    std::string sql = "INSERT INTO method_embeddings "
        "(run_id, file_path, file_hash, class_name, method_name, content, embedding) "
        "VALUES ('" +
        escape(run_id) + "', '" + escape(file_path) + "', '" + escape(file_hash) +
        "', '" + escape(class_name) + "', '" + escape(method_name) +
        "', '" + escape(content) + "', " + vectorToSql(embedding) + ")";
    auto result = db_.execute(sql);
    if (!result.ok()) {
        std::cerr << "[embedding] store failed: " << result.error << std::endl;
    }
}

std::vector<EmbeddingStore::SearchResult>
EmbeddingStore::search(const std::vector<float>& query_embedding,
                       int top_k,
                       const std::string& exclude_run_id) {
    std::string vecSql = vectorToSql(query_embedding);
    std::string where;
    if (!exclude_run_id.empty()) {
        where = " WHERE run_id != '" + escape(exclude_run_id) + "'";
    }

    std::string sql =
        "SELECT run_id, file_path, class_name, method_name, content, "
        "1 - (embedding <=> " + vecSql + "::vector) AS similarity "
        "FROM method_embeddings" + where +
        " ORDER BY embedding <=> " + vecSql + "::vector"
        " LIMIT " + std::to_string(top_k);

    auto result = db_.execute(sql);
    std::vector<SearchResult> results;
    if (!result.ok()) {
        std::cerr << "[embedding] search failed: " << result.error << std::endl;
        return results;
    }

    for (auto& row : result.rows) {
        SearchResult sr;
        sr.run_id = row[0];
        sr.file_path = row[1];
        sr.class_name = row[2];
        sr.method_name = row[3];
        sr.content = row[4];
        try { sr.similarity = std::stod(row[5]); } catch (...) { sr.similarity = 0; }
        results.push_back(std::move(sr));
    }
    return results;
}

std::vector<EmbeddingStore::SearchResult>
EmbeddingStore::searchByText(const std::string& text,
                             int top_k,
                             const std::string& exclude_run_id) {
    if (!backend_) return {};
    auto embedding = backend_->embed(text);
    return search(embedding, top_k, exclude_run_id);
}

void EmbeddingStore::embedAndStore(const std::string& run_id,
                                   const std::string& file_path,
                                   const std::string& file_hash,
                                   const std::string& class_name,
                                   const std::string& method_name,
                                   const std::string& content) {
    if (!backend_) return;
    try {
        auto embedding = backend_->embed(content);
        store(run_id, file_path, file_hash, class_name, method_name, content, embedding);
    } catch (const std::exception& e) {
        std::cerr << "[embedding] embed+store failed for " << class_name
                  << "::" << method_name << ": " << e.what() << std::endl;
    }
}

void EmbeddingStore::deleteRun(const std::string& run_id) {
    db_.execute("DELETE FROM method_embeddings WHERE run_id = '" + escape(run_id) + "'");
}

} // namespace area
