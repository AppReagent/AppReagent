#pragma once

#include <string>
#include "tools/Tool.h"

namespace area {

class Config;
class Database;
class EventBus;

class AnalyzeTool : public Tool {
public:
    AnalyzeTool(const Config* config, Database& db, EventBus* events = nullptr)
        : config_(config), db_(db), events_(events) {}

    std::string name() const override { return "ANALYZE"; }
    std::string description() const override {
        return "<run_id> | latest — run RAG-augmented analysis on a completed scan. "
               "Retrieves similar methods from the embedding corpus to produce deeper threat assessments.\n"
               "  Example: ANALYZE: latest\n"
               "  Example: ANALYZE: abc123XYZ_w";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    const Config* config_;
    Database& db_;
    EventBus* events_;
};

} // namespace area
