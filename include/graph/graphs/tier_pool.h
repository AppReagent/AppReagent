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
    explicit TierPool(const std::vector<area::AiEndpoint>& endpoints);

    TierBackends backends() const;
    area::LLMBackend* at(int tier) const;
    int totalConcurrency() const;

private:
    std::unordered_map<int, area::LLMBackend*> tiers_;
    std::vector<std::unique_ptr<area::BackendPool>> owned_;
};

} // namespace area::graph
