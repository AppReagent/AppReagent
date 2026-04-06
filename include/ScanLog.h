#pragma once

#include <string>
#include "Database.h"

namespace area {

class ScanLog {
public:
    explicit ScanLog(Database& db);

    void ensureTables();
    void dropTables();

    // Check if a file (by content hash) has already been scanned in this run
    bool fileCompleted(const std::string& run_id, const std::string& file_hash);

    // Check if a prompt (by hash) has already been run in this run, return cached response
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

    // Store a file's contents in the database for a given run
    void storeFile(const std::string& run_id, const std::string& file_path,
                   const std::string& file_hash, const std::string& contents);

    // Delete all data for a run_id from scan_results, llm_calls, method_calls, and scan_files
    void deleteRun(const std::string& run_id);

    static std::string sha256(const std::string& data);
    static std::string generateRunId();
    static std::string loadDDL();
    // Encode binary data as PostgreSQL hex BYTEA literal (\xDEAD...)
    static std::string bytesToPgHex(const std::string& data);

private:
    Database& db_;
};

} // namespace area
