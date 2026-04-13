#pragma once

#include <memory>
#include <optional>
#include <string>

#include "infra/tools/Tool.h"
#include "infra/config/Config.h"
#include "infra/db/Database.h"
#include "infra/llm/RagProvider.h"

namespace area {

class SimilarTool : public Tool {
 public:
    SimilarTool(const Config* config, Database& db);

    std::string name() const override { return "SIMILAR"; }
    std::string description() const override {
        return "<query text> — search for methods with similar code or behavior "
               "across all scans using vector embeddings. "
               "Returns top matches ranked by cosine similarity.\n"
               "  Example: SIMILAR: SMS sending with content from contacts\n"
               "  Example: SIMILAR: native JNI calls that load shared libraries";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

    bool available() const { return rag_ && rag_->available(); }

 private:
    std::unique_ptr<RagProvider> rag_;
};

}  // namespace area
