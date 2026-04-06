#include "ScanLog.h"

#include <fstream>
#include <iostream>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <iomanip>

namespace area {

ScanLog::ScanLog(Database& db) : db_(db) {}

std::string ScanLog::escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    return out;
}

std::string ScanLog::sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
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
    auto result = db_.execute(
        "SELECT 1 FROM scan_results WHERE run_id = '" + escape(run_id) +
        "' AND file_hash = '" + escape(file_hash) + "' LIMIT 1");
    return result.ok() && !result.rows.empty();
}

std::string ScanLog::findCachedPrompt(const std::string& run_id, const std::string& prompt_hash) {
    auto result = db_.execute(
        "SELECT response FROM llm_calls WHERE run_id = '" + escape(run_id) +
        "' AND prompt_hash = '" + escape(prompt_hash) + "' LIMIT 1");
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
    std::string sql = "INSERT INTO llm_calls (run_id, file_path, file_hash, node_name, tier, prompt, prompt_hash, response, latency_ms) VALUES ('" +
        escape(run_id) + "', '" + escape(file_path) + "', '" + escape(file_hash) +
        "', '" + escape(node_name) + "', " + std::to_string(tier) + ", '" +
        escape(prompt) + "', '" + escape(prompt_hash) + "', '" +
        escape(response) + "', " + std::to_string(latency_ms) + ")";
    db_.execute(sql);
}

void ScanLog::logScanResult(const std::string& run_id,
                            const std::string& file_path,
                            const std::string& file_hash,
                            const std::string& risk_profile_json,
                            const std::string& recommendation,
                            int risk_score) {
    std::string sql = "INSERT INTO scan_results (run_id, file_path, file_hash, risk_profile, recommendation, risk_score) VALUES ('" +
        escape(run_id) + "', '" + escape(file_path) + "', '" + escape(file_hash) +
        "', '" + escape(risk_profile_json) + "', '" + escape(recommendation) +
        "', " + std::to_string(risk_score) + ")";
    db_.execute(sql);
}

void ScanLog::logMethodCall(const std::string& run_id,
                            const std::string& file_path,
                            const std::string& file_hash,
                            const std::string& caller_class,
                            const std::string& caller_method,
                            const std::string& callee_class,
                            const std::string& callee_method,
                            const std::string& invoke_type) {
    std::string sql = "INSERT INTO method_calls "
        "(run_id, file_path, file_hash, caller_class, caller_method, "
        "callee_class, callee_method, invoke_type) VALUES ('" +
        escape(run_id) + "', '" + escape(file_path) + "', '" + escape(file_hash) +
        "', '" + escape(caller_class) + "', '" + escape(caller_method) +
        "', '" + escape(callee_class) + "', '" + escape(callee_method) +
        "', '" + escape(invoke_type) + "')";
    db_.execute(sql);
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
    std::string sql = "INSERT INTO method_findings "
        "(run_id, file_path, file_hash, class_name, method_name, "
        "api_calls, findings, reasoning, relevant, confidence, threat_category) VALUES ('" +
        escape(run_id) + "', '" + escape(file_path) + "', '" + escape(file_hash) +
        "', '" + escape(class_name) + "', '" + escape(method_name) +
        "', '" + escape(api_calls) + "', '" + escape(findings) +
        "', '" + escape(reasoning) + "', " + (relevant ? "true" : "false") +
        ", " + std::to_string(confidence) +
        ", '" + escape(threat_category) + "')";
    db_.execute(sql);
}

void ScanLog::deleteRun(const std::string& run_id) {
    db_.execute("DELETE FROM scan_results WHERE run_id = '" + escape(run_id) + "'");
    db_.execute("DELETE FROM llm_calls WHERE run_id = '" + escape(run_id) + "'");
    db_.execute("DELETE FROM method_calls WHERE run_id = '" + escape(run_id) + "'");
    db_.execute("DELETE FROM method_findings WHERE run_id = '" + escape(run_id) + "'");
}

} // namespace area
