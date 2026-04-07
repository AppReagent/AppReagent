#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <unordered_set>

#include <nlohmann/json.hpp>

#include "Config.h"
#include "infra/db/Database.h"
#include "infra/llm/Embedding.h"
#include "ScanLog.h"
#include "ScanOutputFile.h"

namespace area { class EventBus; }
namespace area::graph {
    class GraphRunner;
    class TaskGraph;
    struct TierBackends;
}

namespace area {

struct ScanSummary {
    std::string run_id;
    int files_total = 0;
    int files_scanned = 0;
    int files_skipped = 0;
    int files_relevant = 0;
    int files_partial = 0;
    int files_irrelevant = 0;
    int files_error = 0;
    bool paused = false;
    std::string answer;
    int risk_score = 0;
};

class ScanCommand {
public:
    ScanCommand(const Config& config, Database& db);

    ScanSummary run(const std::string& target_path, const std::string& run_id = "",
                    const std::string& goal = "");

    ScanSummary runFromFile(const std::string& jsonl_path);

    void setPromptsDir(const std::string& dir) { promptsOverride_ = dir; }

    using ProgressCallback = std::function<void(int files_scanned, int files_total)>;
    void setProgressCallback(ProgressCallback cb) { progressCb_ = cb; }

    using LogCallback = std::function<void(const std::string& message)>;
    void setLogCallback(LogCallback cb) { logCb_ = cb; }

    void setInterruptFlag(std::shared_ptr<std::atomic<bool>> flag) { interrupt_ = flag; }

    void setEventBus(EventBus* bus) { events_ = bus; }

    std::string outputPath() const { return output_.path(); }

private:
    std::vector<std::string> findScanFiles(const std::string& dir);
    std::string readFile(const std::string& path);
    void emitLog(const std::string& msg);

    std::string expandGoal(const std::string& goal, const std::string& promptsDir,
                           const graph::TierBackends& backends);
    void processFile(const std::string& filePath, const std::string& runId,
                     const std::string& scanGoal, graph::GraphRunner& runner,
                     const graph::TaskGraph& graph, ScanSummary& summary,
                     std::vector<nlohmann::json>& fileProfiles);
    void synthesizeResults(const std::string& runId, const std::string& scanGoal,
                           const std::string& promptsDir,
                           const graph::TierBackends& backends,
                           std::vector<nlohmann::json>& fileProfiles,
                           ScanSummary& summary);

    const Config& config_;
    Database& db_;
    ScanLog log_;
    ScanOutputFile output_;
    std::unordered_set<std::string> completedHashes_;
    std::string promptsOverride_;
    ProgressCallback progressCb_;
    LogCallback logCb_;
    std::shared_ptr<std::atomic<bool>> interrupt_;
    EventBus* events_ = nullptr;
    std::unique_ptr<EmbeddingBackend> embeddingBackend_;
    std::unique_ptr<EmbeddingStore> embeddingStore_;
};

} // namespace area
