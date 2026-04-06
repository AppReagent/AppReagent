#pragma once

#include "tools/Tool.h"
#include "Config.h"
#include "Database.h"
#include "Embedding.h"

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

    bool available() const { return store_ && store_->hasBackend(); }

private:
    std::unique_ptr<EmbeddingBackend> backend_;
    std::unique_ptr<EmbeddingStore> store_;
};

} // namespace area
