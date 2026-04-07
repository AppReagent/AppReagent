#include "graph/graphs/tier_pool.h"

namespace area::graph {

TierPool::TierPool(const std::vector<area::AiEndpoint>& endpoints) {
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

TierBackends TierPool::backends() const {
    TierBackends tb;
    tb.backends = tiers_;
    return tb;
}

area::LLMBackend* TierPool::at(int tier) const {
    auto it = tiers_.find(tier);
    if (it == tiers_.end()) return nullptr;
    return it->second;
}

int TierPool::totalConcurrency() const {
    int total = 0;
    for (auto& pool : owned_) {
        total += pool->totalConcurrency();
    }
    return total;
}

} // namespace area::graph
