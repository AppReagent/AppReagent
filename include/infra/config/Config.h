#pragma once

#include <optional>
#include <string>
#include <vector>

namespace area {

struct AiEndpoint {
    std::string id;
    std::string provider; // "ollama", "openai", or "mock"
    std::string url;
    std::string model = "auto";
    std::string api_key; // for authenticated APIs (Vultr, OpenAI, etc)
    int tier = 0; // 0 = low, 1 = medium, 2 = high
    int max_concurrent = 1;
    int context_window = 8192; // max tokens for this endpoint
};

struct EmbeddingEndpoint {
    std::string provider; // "ollama" or "openai"
    std::string url;
    std::string model;
    std::string api_key;
    int dimensions = 768;
};

struct Config {
    std::string postgres_url;
    std::string postgres_cert;
    std::vector<AiEndpoint> ai_endpoints;
    std::optional<EmbeddingEndpoint> embedding;
    int job_batch_size = 10;
    int flush_timeout_sec = 15; // fire batch after this many seconds of inactivity
    std::string theme = "dark";

    static Config load(const std::string& path = "config.json");
};

} // namespace area
