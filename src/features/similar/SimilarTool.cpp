#include "features/similar/SimilarTool.h"

#include <stddef.h>
#include <iomanip>
#include <sstream>
#include <exception>
#include <functional>
#include <vector>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"

namespace area {
SimilarTool::SimilarTool(const Config* config, Database& db) {
    if (config && config->embedding.has_value()) {
        try {
            backend_ = EmbeddingBackend::create(*config->embedding);
            store_ = std::make_unique<EmbeddingStore>(db, backend_.get());
        } catch (const std::exception& e) {
        }
    }
}

std::optional<ToolResult> SimilarTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("SIMILAR:"))
        return std::nullopt;

    std::string query = action.substr(8);
    while (!query.empty() && query[0] == ' ') query.erase(0, 1);
    while (!query.empty() && query.back() == ' ') query.pop_back();

    if (query.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a search query after SIMILAR:"};
    }

    if (!store_ || !store_->hasBackend()) {
        return ToolResult{"OBSERVATION: Error — embedding search not available. "
                          "Configure an embedding endpoint in config.json."};
    }

    ctx.cb({AgentMessage::THINKING, "Searching embeddings: " + query});

    std::vector<EmbeddingStore::SearchResult> results;
    try {
        results = store_->searchByText(query, 10);
    } catch (const std::exception& e) {
        ctx.cb({AgentMessage::ERROR, std::string("Embedding search failed: ") + e.what()});
        return ToolResult{"OBSERVATION: Embedding search failed: " + std::string(e.what())};
    }

    if (results.empty()) {
        ctx.cb({AgentMessage::RESULT, "No similar methods found."});
        return ToolResult{"OBSERVATION: No similar methods found in the embedding store. "
                          "Run a scan first to populate embeddings."};
    }

    std::ostringstream out;
    out << results.size() << " similar methods found:\n\n";

    for (size_t i = 0; i < results.size(); i++) {
        auto& r = results[i];
        out << (i + 1) << ". " << r.class_name << "::" << r.method_name
            << " (similarity=" << std::fixed << std::setprecision(3) << r.similarity << ")\n"
            << "   file: " << r.file_path << "\n"
            << "   run:  " << r.run_id << "\n";

        std::string preview = r.content.substr(0, 200);
        if (r.content.size() > 200) preview += "...";

        for (auto& c : preview) {
            if (c == '\n') c = ' ';
        }
        out << "   preview: " << preview << "\n\n";
    }

    std::string formatted = out.str();
    ctx.cb({AgentMessage::RESULT, formatted});

    return ToolResult{"OBSERVATION: " + formatted +
        "Use SQL queries on scan_results or llm_calls with the run_id to get full details."};
}
}  // namespace area
