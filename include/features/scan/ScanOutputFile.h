#pragma once

#include <fstream>
#include <mutex>
#include <string>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace area {

class ScanOutputFile {
 public:
    struct LoadResult {
        std::string run_id;
        std::string target_path;
        std::string goal;
        std::unordered_set<std::string> completed_hashes;
    };

    void open(const std::string& run_id);

    static LoadResult load(const std::string& jsonl_path);

    void writeMetadata(const std::string& target_path, const std::string& run_id,
                       const std::string& goal = "");
    void writeLLMCall(const std::string& file_path, const std::string& file_hash,
                      const std::string& node, const std::string& prompt,
                      const std::string& response, double elapsed_ms);
    void writeFileResult(const std::string& file_path, const std::string& file_hash,
                         const std::string& risk, int risk_score,
                         const std::string& recommendation,
                         const nlohmann::json& risk_profile, double elapsed_ms);

    void writeSynthesis(const std::string& raw_response, const nlohmann::json& parsed);

    std::string path() const { return path_; }

 private:
    void writeLine(const nlohmann::json& j);
    std::string path_;
    std::ofstream file_;
    std::mutex mu_;
};

}  // namespace area
