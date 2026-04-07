#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include "infra/config/Config.h"
#include "infra/db/Database.h"
#include "infra/llm/Embedding.h"

namespace area { class EventBus; }

namespace area {

struct AnalysisResult {
    std::string run_id;
    std::string summary;
    std::string threat_level;
    int confidence = 0;
    int risk_score = 0;
    std::string full_json;  // raw JSON from synthesis
};

class AnalyzeCommand {
public:
    AnalyzeCommand(const Config& config, Database& db);

    // Analyze a completed scan by run_id.
    // If run_id is "latest", finds the most recent scan.
    AnalysisResult run(const std::string& run_id);

    using LogCallback = std::function<void(const std::string& message)>;
    void setLogCallback(LogCallback cb) { logCb_ = cb; }

    void setEventBus(EventBus* bus) { events_ = bus; }
    void setForceReanalyze(bool force) { forceReanalyze_ = force; }

private:
    void emitLog(const std::string& msg);
    std::string resolveRunId(const std::string& run_id);
    std::string loadScanGoal(const std::string& run_id);

    const Config& config_;
    Database& db_;
    std::unique_ptr<EmbeddingBackend> embeddingBackend_;
    std::unique_ptr<EmbeddingStore> embeddingStore_;
    LogCallback logCb_;
    EventBus* events_ = nullptr;
    bool forceReanalyze_ = false;
};

} // namespace area
