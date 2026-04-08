#pragma once

#include <optional>
#include <string>
#include "infra/db/Database.h"

namespace area {

class ScanLog {
 public:
    explicit ScanLog(Database& db);

    void ensureTables();
    void dropTables();

    bool fileCompleted(const std::string& run_id, const std::string& file_hash);

    struct ExistingScan {
        std::string run_id;
        int file_count = 0;
        int flagged_count = 0;
        int max_risk = 0;
        std::string latest;
    };
    std::optional<ExistingScan> findRecentScan(const std::string& path);

    std::string findCachedPrompt(const std::string& run_id, const std::string& prompt_hash);

    void logLLMCall(const std::string& run_id,
                    const std::string& file_path,
                    const std::string& file_hash,
                    const std::string& node_name,
                    int tier,
                    const std::string& prompt,
                    const std::string& prompt_hash,
                    const std::string& response,
                    double latency_ms);

    void logScanResult(const std::string& run_id,
                       const std::string& file_path,
                       const std::string& file_hash,
                       const std::string& risk_profile_json,
                       const std::string& recommendation,
                       int risk_score);

    void logMethodCall(const std::string& run_id,
                       const std::string& file_path,
                       const std::string& file_hash,
                       const std::string& caller_class,
                       const std::string& caller_method,
                       const std::string& callee_class,
                       const std::string& callee_method,
                       const std::string& invoke_type);

    void logMethodFinding(const std::string& run_id,
                          const std::string& file_path,
                          const std::string& file_hash,
                          const std::string& class_name,
                          const std::string& method_name,
                          const std::string& api_calls,
                          const std::string& findings,
                          const std::string& reasoning,
                          bool relevant,
                          double confidence,
                          const std::string& threat_category = "none");

    void storeFile(const std::string& run_id, const std::string& file_path,
                   const std::string& file_hash, const std::string& contents);

    void deleteRun(const std::string& run_id);

    static std::string sha256(const std::string& data);
    static std::string generateRunId();
    static std::string loadDDL();

    static std::string bytesToPgHex(const std::string& data);

 private:
    Database& db_;
};

}  // namespace area
