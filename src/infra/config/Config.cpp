#include "infra/config/Config.h"

#include <algorithm>
#include <fstream>
#include <map>
#include <stdexcept>
#include <utility>

#include "nlohmann/detail/iterators/iter_impl.hpp"
#include <nlohmann/json.hpp>
namespace area {

Config Config::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("could not open " + path);
    }
    auto j = nlohmann::json::parse(file, nullptr, true, true);

    Config c;
    c.postgres_url = j.at("postgres_url").get<std::string>();
    c.postgres_cert = j.at("postgres_cert").get<std::string>();

    if (j.contains("ai_endpoints")) {
        for (auto& ep : j.at("ai_endpoints")) {
            AiEndpoint e;
            e.id = ep.at("id").get<std::string>();
            e.provider = ep.at("provider").get<std::string>();
            e.url = ep.value("url", "");
            e.model = ep.value("model", "auto");
            e.api_key = ep.value("api_key", "");
            e.tier = ep.value("tier", 0);
            e.max_concurrent = ep.value("max_concurrent", 1);
            e.context_window = ep.value("context_window", 8192);
            c.ai_endpoints.push_back(std::move(e));
        }
    }

    if (j.contains("job_batch_size")) {
        c.job_batch_size = j.at("job_batch_size").get<int>();
    }
    if (j.contains("flush_timeout_sec")) {
        c.flush_timeout_sec = j.at("flush_timeout_sec").get<int>();
    }
    if (j.contains("theme")) {
        c.theme = j.at("theme").get<std::string>();
    }
    if (j.contains("ws_port")) {
        c.ws_port = j.at("ws_port").get<int>();
    }

    if (j.contains("embedding")) {
        auto& emb = j.at("embedding");
        EmbeddingEndpoint ep;
        ep.provider = emb.at("provider").get<std::string>();
        ep.url = emb.value("url", "");
        ep.model = emb.at("model").get<std::string>();
        ep.api_key = emb.value("api_key", "");
        ep.dimensions = emb.value("dimensions", 768);
        c.embedding = std::move(ep);
    }

    return c;
}

}  // namespace area
