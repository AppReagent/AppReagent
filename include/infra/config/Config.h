#pragma once

#include <optional>
#include <string>
#include <vector>

namespace area {

struct AiEndpoint {
    std::string id;
    std::string provider;
    std::string url;
    std::string model = "auto";
    std::string api_key;
    int tier = 0;
    int max_concurrent = 1;
    int context_window = 8192;
};

struct EmbeddingEndpoint {
    std::string provider;
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
    int flush_timeout_sec = 15;
    int ws_port = 0;
    std::string theme = "dark";

    static Config load(const std::string& path = "config.json");
};

}  // namespace area
