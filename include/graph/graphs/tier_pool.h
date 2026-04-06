#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "BackendPool.h"
#include "Config.h"
#include "LLMBackend.h"
#include "graph/graphs/scan_task_graph.h"

namespace area::graph {

class TierPool {
public:
    explicit TierPool(const std::vector<area::AiEndpoint>& endpoints) {
        std::unordered_map<int, std::vector<area::AiEndpoint>> byTier;
        for (auto& ep : endpoints) {
            byTier[ep.tier].push_back(ep);
        }

        for (auto& [tier, eps] : byTier) {
            auto pool = std::make_unique<area::BackendPool>(eps);
            tiers_[tier] = pool.get();
            owned_.push_back(std::move(pool));
        }
    }

    TierBackends backends() const {
        TierBackends tb;
        tb.backends = tiers_;
        return tb;
    }

    area::LLMBackend* at(int tier) const {
        auto it = tiers_.find(tier);
        if (it == tiers_.end()) return nullptr;
        return it->second;
    }

    int totalConcurrency() const {
        int total = 0;
        for (auto& pool : owned_) {
            total += pool->totalConcurrency();
        }
        return total;
    }

private:
    std::unordered_map<int, area::LLMBackend*> tiers_;
    std::vector<std::unique_ptr<area::BackendPool>> owned_;
};

} // namespace area::graph
