#include "LLMBackend.h"

#include <chrono>
#include <curl/curl.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <thread>

namespace area {


std::unique_ptr<LLMBackend> LLMBackend::create(const AiEndpoint& ep) {
    if (ep.provider == "ollama")   return std::make_unique<OllamaBackend>(ep);
    if (ep.provider == "openai" || ep.provider == "lmstudio")
                                   return std::make_unique<OpenAIBackend>(ep);
    if (ep.provider == "mock")     return std::make_unique<MockBackend>(ep);
    throw std::runtime_error("unknown provider: " + ep.provider);
}


static size_t curlWriteCb(char* data, size_t size, size_t nmemb, std::string* out) {
    size_t total = size * nmemb;
    out->append(data, total);
    return total;
}

static int cancelProgressCb(void* clientp, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    auto* flag = static_cast<std::atomic<bool>*>(clientp);
    return (flag && flag->load()) ? 1 : 0;  // non-zero aborts the transfer
}

static std::string httpPost(const std::string& url,
                            const std::string& body,
                            const std::string& api_key = "",
                            long timeoutSec = 60,
                            std::atomic<bool>* cancelFlag = nullptr) {
    CURL* curl = curl_easy_init();
    if (!curl) throw std::runtime_error("curl init failed");

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!api_key.empty()) {
        headers = curl_slist_append(headers,
            ("Authorization: Bearer " + api_key).c_str());
    }

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeoutSec);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);

    if (cancelFlag) {
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, cancelProgressCb);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA, cancelFlag);
    }

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res == CURLE_ABORTED_BY_CALLBACK) {
        throw std::runtime_error("interrupted");
    }
    if (res != CURLE_OK) {
        throw std::runtime_error(std::string("HTTP request failed: ") + curl_easy_strerror(res));
    }
    return response;
}

static nlohmann::json buildMessages(const std::string& system,
                                    const std::vector<ChatMessage>& messages) {
    auto arr = nlohmann::json::array();
    arr.push_back({{"role", "system"}, {"content", system}});
    for (auto& m : messages) {
        arr.push_back({{"role", m.role}, {"content", m.content}});
    }
    return arr;
}

static ChatResult extractResult(const std::string& raw, const std::string& endpointId) {
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(raw);
    } catch (...) {
        if (raw.find("504") != std::string::npos || raw.find("Gateway Time-out") != std::string::npos)
            throw std::runtime_error(endpointId + ": 504 gateway timeout (service down)");
        if (raw.find("502") != std::string::npos)
            throw std::runtime_error(endpointId + ": 502 bad gateway (service down)");
        if (raw.find("503") != std::string::npos)
            throw std::runtime_error(endpointId + ": 503 service unavailable");
        if (raw.find("429") != std::string::npos)
            throw std::runtime_error(endpointId + ": 429 rate limited");
        if (raw.find("401") != std::string::npos || raw.find("Unauthorized") != std::string::npos)
            throw std::runtime_error(endpointId + ": 401 unauthorized (check api_key)");
        throw std::runtime_error(endpointId + ": non-JSON response: " + raw.substr(0, 150));
    }
    if (j.contains("error")) {
        throw std::runtime_error("endpoint " + endpointId + ": " + j["error"].dump());
    }
    ChatResult r;
    if (!j.contains("choices") || !j["choices"].is_array() || j["choices"].empty()) {
        throw std::runtime_error(endpointId + ": response missing 'choices' array");
    }
    auto contentVal = j["choices"][0]["message"]["content"];
    if (contentVal.is_null()) {
        throw std::runtime_error(endpointId + ": response content is null (model returned no text)");
    }
    r.content = contentVal.get<std::string>();
    if (r.content == "None") {
        throw std::runtime_error(endpointId + ": response content is \"None\" (model returned no text)");
    }
    if (j.contains("usage")) {
        r.usage.prompt_tokens = j["usage"].value("prompt_tokens", 0);
        r.usage.completion_tokens = j["usage"].value("completion_tokens", 0);
        r.usage.total_tokens = j["usage"].value("total_tokens", 0);
    }
    return r;
}


std::string OllamaBackend::chat(const std::string& system,
                                const std::vector<ChatMessage>& messages) {
    nlohmann::json body = {
        {"messages", buildMessages(system, messages)},
        {"stream", false},
    };

    // omit model field when "auto" so ollama uses whatever is loaded
    if (endpoint_.model != "auto") {
        body["model"] = endpoint_.model;
    }

    std::string url = endpoint_.url + "/api/chat";
    std::string raw = httpPost(url, body.dump(), "", 60, cancelFlag_);

    // Ollama native API returns {"message": {"content": "..."}}
    auto j = nlohmann::json::parse(raw);
    if (j.contains("error")) {
        throw std::runtime_error("ollama " + endpoint_.id + ": " + j["error"].dump());
    }
    if (!j.contains("message") || !j["message"].contains("content")) {
        throw std::runtime_error("ollama " + endpoint_.id + ": response missing 'message.content'");
    }
    auto contentVal = j["message"]["content"];
    if (contentVal.is_null()) {
        throw std::runtime_error("ollama " + endpoint_.id + ": response content is null");
    }
    std::string content = contentVal.get<std::string>();
    if (content == "None") {
        throw std::runtime_error("ollama " + endpoint_.id + ": response content is \"None\"");
    }
    return content;
}


std::string OpenAIBackend::chat(const std::string& system,
                                const std::vector<ChatMessage>& messages) {
    return chatWithUsage(system, messages).content;
}

ChatResult OpenAIBackend::chatWithUsage(const std::string& system,
                                        const std::vector<ChatMessage>& messages,
                                        int max_tokens) {
    nlohmann::json body = {
        {"messages", buildMessages(system, messages)},
        {"stream", false},
    };

    // Only send max_tokens when explicitly requested.
    // Many providers reject values that exceed their own limits.
    if (max_tokens > 0) {
        int ctx = endpoint_.context_window;
        if (max_tokens > ctx && ctx > 0) max_tokens = ctx;
        body["max_tokens"] = max_tokens;
    }

    if (endpoint_.model != "auto") {
        body["model"] = endpoint_.model;
    }

    std::string url = endpoint_.url + "/v1/chat/completions";
    std::string raw = httpPost(url, body.dump(), endpoint_.api_key, 60, cancelFlag_);
    auto result = extractResult(raw, endpoint_.id);
    totalPromptTokens += result.usage.prompt_tokens;
    totalCompletionTokens += result.usage.completion_tokens;
    return result;
}


MockBackend::MockBackend(const AiEndpoint& ep) : LLMBackend(ep) {
    // If url points to a .json file, load keyword→response mappings
    if (!ep.url.empty() && ep.url.size() > 5 && ep.url.substr(ep.url.size() - 5) == ".json") {
        loadResponseFile(ep.url);
    }
}

void MockBackend::loadResponseFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    try {
        auto j = nlohmann::json::parse(content);
        if (j.is_object()) {
            for (auto& [key, val] : j.items()) {
                if (val.is_string()) {
                    routedResponses_.emplace_back(key, val.get<std::string>());
                }
            }
        }
    } catch (...) {}
}

std::string MockBackend::chat(const std::string& system,
                              const std::vector<ChatMessage>& messages) {
    // Track concurrent calls (all atomics for thread safety)
    int now = ++concurrent_;
    int prev = peakConcurrent_.load();
    while (now > prev && !peakConcurrent_.compare_exchange_weak(prev, now)) {}

    int count = ++callCount_;

    {
        std::lock_guard lk(mu_);
        lastSystem_ = system;
        if (!messages.empty()) {
            lastUser_ = messages.back();
        }
    }

    int latency = latencyMs_.load();
    if (latency > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(latency));
    }

    concurrent_--;

    int failAt = failAfter_.load();
    if (failAt >= 0 && count > failAt) {
        throw std::runtime_error("mock failure after " + std::to_string(failAt) + " calls");
    }

    {
        std::lock_guard lk(mu_);

        // Check routed responses: match keyword against system + user prompt
        if (!routedResponses_.empty() && !messages.empty()) {
            std::string haystack = system + "\n" + messages.back().content;
            for (auto& [keyword, response] : routedResponses_) {
                if (haystack.find(keyword) != std::string::npos) {
                    return response;
                }
            }
        }

        if (!sequence_.empty()) {
            size_t idx = seqIdx_.fetch_add(1) % sequence_.size();
            return sequence_[idx];
        }
        return canned_;
    }
}

} // namespace area
