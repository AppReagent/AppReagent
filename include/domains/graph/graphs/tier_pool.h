#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "infra/llm/BackendPool.h"
#include "infra/config/Config.h"
#include "infra/llm/LLMBackend.h"
#include "domains/graph/graphs/scan_task_graph.h"

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
