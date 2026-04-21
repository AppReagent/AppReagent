#include "features/scan/ScanOutputFile.h"

#include <chrono>
#include <filesystem>
#include <map>
#include <stdexcept>

#include "nlohmann/detail/json_ref.hpp"
#include "nlohmann/detail/output/serializer.hpp"
#include "nlohmann/json.hpp"

namespace fs = std::filesystem;

namespace area {
void ScanOutputFile::open(const std::string& run_id) {
    if (file_.is_open()) file_.close();
    fs::create_directories("scan-outputs");
    path_ = "scan-outputs/" + run_id + ".jsonl";
    file_.open(path_, std::ios::app);
    if (!file_.is_open()) {
        throw std::runtime_error("Failed to open " + path_);
    }
}

ScanOutputFile::LoadResult ScanOutputFile::load(const std::string& jsonl_path) {
    LoadResult result;
    std::ifstream f(jsonl_path);
    if (!f.is_open()) {
        throw std::runtime_error("Failed to open " + jsonl_path);
    }

    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        try {
            auto j = nlohmann::json::parse(line);
            std::string type = j.value("type", "");
            if (type == "metadata") {
                result.run_id = j.value("run_id", "");
                result.target_path = j.value("target_path", "");
                result.goal = j.value("goal", "");
            } else if (type == "file_result") {
                std::string hash = j.value("file_hash", "");
                if (!hash.empty()) {
                    result.completed_hashes.insert(hash);
                }
            }
        } catch (...) {
        }
    }
    return result;
}

void ScanOutputFile::writeMetadata(const std::string& target_path, const std::string& run_id,
                                    const std::string& goal) {
    nlohmann::json meta = {
        {"type", "metadata"},
        {"run_id", run_id},
        {"target_path", target_path},
        {"ts", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    if (!goal.empty()) meta["goal"] = goal;
    writeLine(meta);
}

void ScanOutputFile::writeLLMCall(const std::string& file_path, const std::string& file_hash,
                                  const std::string& node, const std::string& prompt,
                                  const std::string& response, double elapsed_ms) {
    writeLine({
        {"type", "llm_call"},
        {"file_path", file_path},
        {"file_hash", file_hash},
        {"node", node},
        {"prompt", prompt},
        {"response", response},
        {"elapsed_ms", elapsed_ms}
    });
}

void ScanOutputFile::writeFileResult(const std::string& file_path, const std::string& file_hash,
                                     const std::string& risk, int risk_score,
                                     const std::string& recommendation,
                                     const nlohmann::json& risk_profile, double elapsed_ms) {
    writeLine({
        {"type", "file_result"},
        {"file_path", file_path},
        {"file_hash", file_hash},
        {"risk", risk},
        {"risk_score", risk_score},
        {"recommendation", recommendation},
        {"risk_profile", risk_profile},
        {"elapsed_ms", elapsed_ms}
    });
}

void ScanOutputFile::writeSynthesis(const std::string& raw_response,
                                     const nlohmann::json& parsed) {
    writeLine({
        {"type", "scan_synthesis"},
        {"raw_response", raw_response},
        {"parsed", parsed}
    });
}

void ScanOutputFile::writeLine(const nlohmann::json& j) {
    std::lock_guard lk(mu_);
    if (file_.is_open()) {
        file_ << j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
        file_.flush();
    }
}
}  // namespace area
