#pragma once

#include <mutex>
#include <string>
#include <vector>
#include <libpq-fe.h>

namespace area {

struct QueryResult {
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;
    double duration_ms = 0;
    std::string error;
    bool ok() const { return error.empty(); }
};

class Database {
public:
    Database();
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    void connect(const std::string& url, const std::string& postgres_cert_path);
    bool isConnected() const { return conn_ != nullptr; }
    std::string getSchema();
    QueryResult execute(const std::string& sql);
    QueryResult executeParams(const std::string& sql, const std::vector<std::string>& params);

private:
    PGconn* conn_ = nullptr;
    std::mutex mu_;
};

} // namespace area
