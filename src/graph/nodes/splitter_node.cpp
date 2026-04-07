#include "graph/nodes/splitter_node.h"

namespace area::graph {

NodeResult SplitterNode::execute(TaskContext ctx) {
    return NodeResult::fanout(fn_(std::move(ctx)));
}

NodeResult CollectorNode::execute(TaskContext) {
    throw std::runtime_error("CollectorNode::execute should not be called directly");
}

TaskContext CollectorNode::collect(std::vector<TaskContext> items) {
    if (fn_) return fn_(std::move(items));

    // Default: merge all items into a json array under "collected"
    TaskContext result;
    nlohmann::json collected = nlohmann::json::array();
    for (auto& item : items) {
        collected.push_back(item.data());
    }
    result.set("collected", std::move(collected));
    return result;
}

} // namespace area::graph
