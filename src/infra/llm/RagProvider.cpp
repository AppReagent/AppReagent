#include "infra/llm/RagProvider.h"

#include <curl/curl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "infra/config/Config.h"
#include "infra/db/Database.h"
#include "infra/llm/Embedding.h"

namespace area {

class CustomRagProvider : public RagProvider {
 public:
    CustomRagProvider(const EmbeddingEndpoint& ep, Database& db)
        : backend_(EmbeddingBackend::create(ep)),
          store_(std::make_unique<EmbeddingStore>(db, backend_.get())) {}

    void addDocument(const std::string& run_id,
                     const std::string& file_path,
                     const std::string& file_hash,
                     const std::string& class_name,
                     const std::string& method_name,
                     const std::string& content) override {
        store_->embedAndStore(run_id, file_path, file_hash,
                              class_name, method_name, content);
    }

    std::vector<RagSearchResult>
    searchByText(const std::string& text,
                 int top_k,
                 const std::string& exclude_run_id) override {
        std::vector<RagSearchResult> out;
        auto rows = store_->searchByText(text, top_k, exclude_run_id);
        out.reserve(rows.size());
        for (auto& r : rows) {
            out.push_back(RagSearchResult{
                std::move(r.run_id),
                std::move(r.file_path),
                std::move(r.class_name),
                std::move(r.method_name),
                std::move(r.content),
                r.similarity,
            });
        }
        return out;
    }

    void deleteRun(const std::string& run_id) override {
        store_->deleteRun(run_id);
    }

    bool available() const override {
        return store_ && store_->hasBackend();
    }

 private:
    std::unique_ptr<EmbeddingBackend> backend_;
    std::unique_ptr<EmbeddingStore> store_;
};

namespace {

struct VultrCurlHandle {
    CURL* curl = nullptr;
    curl_slist* headers = nullptr;

    VultrCurlHandle() : curl(curl_easy_init()) {
        if (!curl) throw std::runtime_error("curl init failed");
    }
    ~VultrCurlHandle() {
        if (headers) curl_slist_free_all(headers);
        if (curl) curl_easy_cleanup(curl);
    }
    VultrCurlHandle(const VultrCurlHandle&) = delete;
    VultrCurlHandle& operator=(const VultrCurlHandle&) = delete;
};

size_t vultrWriteCb(char* data, size_t size, size_t nmemb, std::string* out) {
    size_t total = size * nmemb;
    out->append(data, total);
    return total;
}

struct VultrResp {
    int64_t status = 0;
    std::string body;
};

VultrResp vultrRequest(const std::string& verb,
                       const std::string& url,
                       const std::string& api_key,
                       const std::string& body = "") {
    VultrCurlHandle ch;
    VultrResp resp;

    ch.headers = curl_slist_append(ch.headers, "Content-Type: application/json");
    ch.headers = curl_slist_append(ch.headers, ("Authorization: Bearer " + api_key).c_str());

    curl_easy_setopt(ch.curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(ch.curl, CURLOPT_HTTPHEADER, ch.headers);
    curl_easy_setopt(ch.curl, CURLOPT_CUSTOMREQUEST, verb.c_str());
    curl_easy_setopt(ch.curl, CURLOPT_WRITEFUNCTION, vultrWriteCb);
    curl_easy_setopt(ch.curl, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(ch.curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(ch.curl, CURLOPT_CONNECTTIMEOUT, 5L);
    if (!body.empty()) {
        curl_easy_setopt(ch.curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(ch.curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         static_cast<curl_off_t>(body.size()));
    }

    CURLcode res = curl_easy_perform(ch.curl);
    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("vultr HTTP ") + verb + " failed: " +
                                 curl_easy_strerror(res));
    }
    decltype(0L) response_code = 0;
    curl_easy_getinfo(ch.curl, CURLINFO_RESPONSE_CODE, &response_code);
    resp.status = response_code;
    return resp;
}

std::string makeRagHeader(const std::string& run_id,
                          const std::string& file_path,
                          const std::string& file_hash,
                          const std::string& class_name,
                          const std::string& method_name) {
    nlohmann::json h = {
        {"run_id", run_id},
        {"file_path", file_path},
        {"file_hash", file_hash},
        {"class_name", class_name},
        {"method_name", method_name},
    };
    return h.dump();
}

struct RagHeader {
    std::string run_id;
    std::string file_path;
    std::string file_hash;
    std::string class_name;
    std::string method_name;
    std::string body;
};

RagHeader parseRagHeader(const std::string& stored) {
    RagHeader out;
    auto nl = stored.find('\n');
    if (nl == std::string::npos) {
        out.body = stored;
        return out;
    }
    std::string first = stored.substr(0, nl);
    try {
        auto j = nlohmann::json::parse(first);
        if (j.is_object()) {
            out.run_id = j.value("run_id", "");
            out.file_path = j.value("file_path", "");
            out.file_hash = j.value("file_hash", "");
            out.class_name = j.value("class_name", "");
            out.method_name = j.value("method_name", "");
            out.body = stored.substr(nl + 1);
            return out;
        }
    } catch (...) {
    }
    out.body = stored;
    return out;
}

}  // namespace

class VultrRagProvider : public RagProvider {
 public:
    explicit VultrRagProvider(const EmbeddingEndpoint& ep)
        : base_url_(ep.url), api_key_(ep.api_key), collection_id_(ep.collection_id) {
        while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
        if (collection_id_.empty()) {
            std::cerr << "[rag:vultr] collection_id missing in embedding config — "
                      << "create one via POST /v1/vector_store and set it in config.json"
                      << std::endl;
        }
    }

    void addDocument(const std::string& run_id,
                     const std::string& file_path,
                     const std::string& file_hash,
                     const std::string& class_name,
                     const std::string& method_name,
                     const std::string& content) override {
        if (collection_id_.empty()) return;
        std::string stored = makeRagHeader(run_id, file_path, file_hash, class_name, method_name)
                             + "\n" + content;
        nlohmann::json body = {
            {"content", stored},
            {"description", "run=" + run_id},
        };
        try {
            auto resp = vultrRequest("POST",
                base_url_ + "/v1/vector_store/" + collection_id_ + "/items",
                api_key_, body.dump());
            if (resp.status < 200 || resp.status >= 300) {
                std::cerr << "[rag:vultr] addDocument http " << resp.status
                          << ": " << resp.body.substr(0, 300) << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "[rag:vultr] addDocument failed for "
                      << class_name << "::" << method_name << ": " << e.what() << std::endl;
        }
    }

    std::vector<RagSearchResult>
    searchByText(const std::string& text,
                 int top_k,
                 const std::string& exclude_run_id) override {
        std::vector<RagSearchResult> out;
        if (collection_id_.empty()) return out;

        nlohmann::json body = {
            {"input", text},
            {"top_k", top_k * 2},
        };
        VultrResp resp;
        try {
            resp = vultrRequest("POST",
                base_url_ + "/v1/vector_store/" + collection_id_ + "/search",
                api_key_, body.dump());
        } catch (const std::exception& e) {
            std::cerr << "[rag:vultr] searchByText failed: " << e.what() << std::endl;
            return out;
        }
        if (resp.status < 200 || resp.status >= 300) {
            std::cerr << "[rag:vultr] searchByText http " << resp.status
                      << ": " << resp.body.substr(0, 300) << std::endl;
            return out;
        }

        try {
            auto j = nlohmann::json::parse(resp.body);
            if (!j.contains("results") || !j["results"].is_array()) return out;
            auto& arr = j["results"];
            out.reserve(arr.size());

            for (size_t i = 0; i < arr.size() && static_cast<int>(out.size()) < top_k; i++) {
                auto& item = arr[i];
                std::string stored = item.value("content", "");
                auto meta = parseRagHeader(stored);
                if (!exclude_run_id.empty() && meta.run_id == exclude_run_id) continue;

                double rank_sim = 1.0 - (static_cast<double>(i) / std::max(1, top_k));
                if (rank_sim < 0.0) rank_sim = 0.0;

                out.push_back(RagSearchResult{
                    std::move(meta.run_id),
                    std::move(meta.file_path),
                    std::move(meta.class_name),
                    std::move(meta.method_name),
                    std::move(meta.body),
                    rank_sim,
                });
            }
        } catch (const std::exception& e) {
            std::cerr << "[rag:vultr] searchByText parse failed: " << e.what() << std::endl;
        }
        return out;
    }

    void deleteRun(const std::string& run_id) override {
        if (collection_id_.empty() || run_id.empty()) return;
        VultrResp resp;
        try {
            resp = vultrRequest("GET",
                base_url_ + "/v1/vector_store/" + collection_id_ + "/items",
                api_key_);
        } catch (const std::exception& e) {
            std::cerr << "[rag:vultr] deleteRun list failed: " << e.what() << std::endl;
            return;
        }
        if (resp.status < 200 || resp.status >= 300) return;

        std::vector<std::string> to_delete;
        try {
            auto j = nlohmann::json::parse(resp.body);
            if (j.contains("items") && j["items"].is_array()) {
                for (auto& item : j["items"]) {
                    std::string desc = item.value("description", "");
                    if (desc == "run=" + run_id) {
                        to_delete.push_back(item.value("id", ""));
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[rag:vultr] deleteRun parse failed: " << e.what() << std::endl;
            return;
        }

        for (auto& id : to_delete) {
            if (id.empty()) continue;
            try {
                vultrRequest("DELETE",
                    base_url_ + "/v1/vector_store/" + collection_id_ + "/items/" + id,
                    api_key_);
            } catch (const std::exception& e) {
                std::cerr << "[rag:vultr] delete item " << id << " failed: " << e.what() << std::endl;
            }
        }
    }

    bool available() const override {
        return !base_url_.empty() && !api_key_.empty() && !collection_id_.empty();
    }

 private:
    std::string base_url_;
    std::string api_key_;
    std::string collection_id_;
};

std::unique_ptr<RagProvider> RagProvider::create(const Config& config, Database& db) {
    if (!config.embedding.has_value()) return nullptr;
    const auto& ep = *config.embedding;

    try {
        if (ep.provider == "vultr") {
            return std::make_unique<VultrRagProvider>(ep);
        }
        if (ep.provider == "openai" || ep.provider == "ollama" || ep.provider == "lmstudio") {
            return std::make_unique<CustomRagProvider>(ep, db);
        }
        std::cerr << "[rag] unknown provider: " << ep.provider << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "[rag] init failed: " << e.what() << std::endl;
    }
    return nullptr;
}

}  // namespace area
