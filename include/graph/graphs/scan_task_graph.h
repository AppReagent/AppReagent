#pragma once

#include <string>
#include <unordered_map>

#include "graph/engine/task_graph.h"
#include "infra/llm/LLMBackend.h"

namespace area { class EmbeddingStore; }

namespace area::graph {

struct TierBackends {
    std::unordered_map<int, area::LLMBackend*> backends;

    area::LLMBackend* at(int tier) const;
};

std::string loadPrompt(const std::string& path);

TaskGraph buildScanTaskGraph(const TierBackends& backends,
                             const std::string& prompts_dir = "prompts",
                             area::EmbeddingStore* embeddingStore = nullptr);

} // namespace area::graph
