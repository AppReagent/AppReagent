#include "ScanLog.h"

#include <fstream>
#include <iostream>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <iomanip>

namespace area {

ScanLog::ScanLog(Database& db) : db_(db) {}

std::string ScanLog::sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string ScanLog::bytesToPgHex(const std::string& data) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 + data.size() * 2);
    result += "\\x";
    for (unsigned char c : data) {
        result += hex[c >> 4];
        result += hex[c & 0x0f];
    }
    return result;
}

std::string ScanLog::generateRunId() {
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(0, sizeof(chars) - 2);
    std::string id;
    for (int i = 0; i < 11; i++) id += chars[dist(gen)];
    return id;
}

void ScanLog::dropTables() {
    db_.execute("DROP TABLE IF EXISTS llm_calls CASCADE");
    db_.execute("DROP TABLE IF EXISTS scan_results CASCADE");
    db_.execute("DROP TABLE IF EXISTS method_embeddings CASCADE");
    db_.execute("DROP TABLE IF EXISTS scan_files CASCADE");
}

void ScanLog::ensureTables() {
    std::string ddl = loadDDL();
    // Split on semicolons and execute each statement
    std::istringstream ss(ddl);
    std::string stmt;
    while (std::getline(ss, stmt, ';')) {
        while (!stmt.empty() && (stmt[0] == ' ' || stmt[0] == '\n' || stmt[0] == '\r')) stmt.erase(0, 1);
        while (!stmt.empty() && (stmt.back() == ' ' || stmt.back() == '\n' || stmt.back() == '\r')) stmt.pop_back();
        if (!stmt.empty()) {
            auto qr = db_.execute(stmt);
            if (!qr.ok()) {
                std::cerr << "[ddl] warning: " << qr.error << std::endl;
            }
        }
    }
}

std::string ScanLog::loadDDL() {
    // Try ddl.sql relative to executable, then current directory
    for (auto& path : {"ddl.sql"}) {
        std::ifstream f(path);
        if (f.is_open()) {
            std::ostringstream ss;
            ss << f.rdbuf();
            return ss.str();
        }
    }
    throw std::runtime_error("ddl.sql not found");
}

bool ScanLog::fileCompleted(const std::string& run_id, const std::string& file_hash) {
    auto result = db_.executeParams(
        "SELECT 1 FROM scan_results WHERE run_id = $1 AND file_hash = $2 LIMIT 1",
        {run_id, file_hash});
    return result.ok() && !result.rows.empty();
}

std::string ScanLog::findCachedPrompt(const std::string& run_id, const std::string& prompt_hash) {
    auto result = db_.executeParams(
        "SELECT response FROM llm_calls WHERE run_id = $1 AND prompt_hash = $2 LIMIT 1",
        {run_id, prompt_hash});
    if (result.ok() && !result.rows.empty() && !result.rows[0].empty()
        && result.rows[0][0] != "NULL") {
        return result.rows[0][0];
    }
    return "";
}

void ScanLog::logLLMCall(const std::string& run_id,
                         const std::string& file_path,
                         const std::string& file_hash,
                         const std::string& node_name,
                         int tier,
                         const std::string& prompt,
                         const std::string& prompt_hash,
                         const std::string& response,
                         double latency_ms) {
    db_.executeParams(
        "INSERT INTO llm_calls (run_id, file_path, file_hash, node_name, tier, "
        "prompt, prompt_hash, response, latency_ms) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        {run_id, file_path, file_hash, node_name, std::to_string(tier),
         prompt, prompt_hash, response, std::to_string(latency_ms)});
}

void ScanLog::logScanResult(const std::string& run_id,
                            const std::string& file_path,
                            const std::string& file_hash,
                            const std::string& risk_profile_json,
                            const std::string& recommendation,
                            int risk_score) {
    db_.executeParams(
        "INSERT INTO scan_results (run_id, file_path, file_hash, risk_profile, "
        "recommendation, risk_score) VALUES ($1, $2, $3, $4, $5, $6)",
        {run_id, file_path, file_hash, risk_profile_json, recommendation,
         std::to_string(risk_score)});
}

void ScanLog::logMethodCall(const std::string& run_id,
                            const std::string& file_path,
                            const std::string& file_hash,
                            const std::string& caller_class,
                            const std::string& caller_method,
                            const std::string& callee_class,
                            const std::string& callee_method,
                            const std::string& invoke_type) {
    db_.executeParams(
        "INSERT INTO method_calls (run_id, file_path, file_hash, caller_class, "
        "caller_method, callee_class, callee_method, invoke_type) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        {run_id, file_path, file_hash, caller_class, caller_method,
         callee_class, callee_method, invoke_type});
}

void ScanLog::logMethodFinding(const std::string& run_id,
                               const std::string& file_path,
                               const std::string& file_hash,
                               const std::string& class_name,
                               const std::string& method_name,
                               const std::string& api_calls,
                               const std::string& findings,
                               const std::string& reasoning,
                               bool relevant,
                               double confidence,
                               const std::string& threat_category) {
    db_.executeParams(
        "INSERT INTO method_findings (run_id, file_path, file_hash, class_name, "
        "method_name, api_calls, findings, reasoning, relevant, confidence, "
        "threat_category) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        {run_id, file_path, file_hash, class_name, method_name,
         api_calls, findings, reasoning, std::string(relevant ? "true" : "false"),
         std::to_string(confidence), threat_category});
}

void ScanLog::storeFile(const std::string& run_id, const std::string& file_path,
                        const std::string& file_hash, const std::string& contents) {
    std::string pgHex = bytesToPgHex(contents);
    db_.executeParams(
        "INSERT INTO scan_files (run_id, file_path, file_hash, file_size, contents) "
        "VALUES ($1, $2, $3, $4, $5) "
        "ON CONFLICT (run_id, file_hash) DO NOTHING",
        {run_id, file_path, file_hash, std::to_string(contents.size()), pgHex});
}

void ScanLog::deleteRun(const std::string& run_id) {
    db_.executeParams("DELETE FROM scan_results WHERE run_id = $1", {run_id});
    db_.executeParams("DELETE FROM llm_calls WHERE run_id = $1", {run_id});
    db_.executeParams("DELETE FROM method_calls WHERE run_id = $1", {run_id});
    db_.executeParams("DELETE FROM method_findings WHERE run_id = $1", {run_id});
    db_.executeParams("DELETE FROM scan_files WHERE run_id = $1", {run_id});
}

} // namespace area
