#pragma once

#include <string>
#include <unordered_map>

#include "graph/engine/task_graph.h"
#include "LLMBackend.h"

namespace area { class EmbeddingStore; }

namespace area::graph {

struct TierBackends {
    std::unordered_map<int, area::LLMBackend*> backends;

    area::LLMBackend* at(int tier) const {
        auto it = backends.find(tier);
        if (it != backends.end()) return it->second;
        // fall back to nearest available tier
        area::LLMBackend* best = nullptr;
        int bestDist = 999;
        for (auto& [t, b] : backends) {
            int dist = std::abs(t - tier);
            if (dist < bestDist) { bestDist = dist; best = b; }
        }
        if (!best) throw std::runtime_error("no backends configured");
        return best;
    }
};

std::string loadPrompt(const std::string& path);

TaskGraph buildScanTaskGraph(const TierBackends& backends,
                             const std::string& prompts_dir = "prompts",
                             area::EmbeddingStore* embeddingStore = nullptr);

} // namespace area::graph
