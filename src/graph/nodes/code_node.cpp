#include "graph/nodes/code_node.h"

namespace area::graph {

NodeResult CodeNode::execute(TaskContext ctx) {
    return NodeResult::single(fn_(std::move(ctx)));
}

NodeResult PredicateCodeNode::execute(TaskContext ctx) {
    bool result = fn_(ctx);
    return NodeResult::branched(std::move(ctx), result ? "pass" : "fail");
}

NodeResult DecisionCodeNode::execute(TaskContext ctx) {
    std::string branch = fn_(ctx);
    return NodeResult::branched(std::move(ctx), std::move(branch));
}

NodeResult ExitNode::execute(TaskContext ctx) {
    ctx.discarded = true;
    if (fn_) fn_(ctx);
    return NodeResult::exited();
}

} // namespace area::graph
