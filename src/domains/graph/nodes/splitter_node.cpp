#include "domains/graph/nodes/splitter_node.h"

#include <map>
#include <stdexcept>

#include "domains/graph/engine/node.h"
#include "nlohmann/json.hpp"
namespace area::graph {

NodeResult SplitterNode::execute(TaskContext ctx) {
    return NodeResult::fanout(fn_(ctx));
}

NodeResult CollectorNode::execute(TaskContext) {
    throw std::runtime_error("CollectorNode::execute should not be called directly");
}

TaskContext CollectorNode::collect(const std::vector<TaskContext>& items) {
    if (fn_) return fn_(items);

    TaskContext result;
    nlohmann::json collected = nlohmann::json::array();
    for (auto& item : items) {
        collected.push_back(item.data());
    }
    result.set("collected", std::move(collected));
    return result;
}

}  // namespace area::graph
