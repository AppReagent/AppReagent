#pragma once

#include <memory>
#include <string>
#include <vector>

namespace area {

class Database;
struct Config;

struct RagSearchResult {
    std::string run_id;
    std::string file_path;
    std::string class_name;
    std::string method_name;
    std::string content;
    double similarity;
};

class RagProvider {
 public:
    virtual ~RagProvider() = default;

    virtual void addDocument(const std::string& run_id,
                             const std::string& file_path,
                             const std::string& file_hash,
                             const std::string& class_name,
                             const std::string& method_name,
                             const std::string& content) = 0;

    virtual std::vector<RagSearchResult>
    searchByText(const std::string& text,
                 int top_k = 5,
                 const std::string& exclude_run_id = "") = 0;

    virtual void deleteRun(const std::string& run_id) = 0;

    virtual bool available() const = 0;

    static std::unique_ptr<RagProvider> create(const Config& config, Database& db);
};

}  // namespace area
