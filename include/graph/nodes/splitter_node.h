#pragma once

#include <functional>
#include "../engine/node.h"

namespace area::graph {

// Fan-out: takes input and produces N TaskContexts.
class SplitterNode : public Node {
public:
    using Fn = std::function<std::vector<TaskContext>(TaskContext)>;

    SplitterNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override {
        return NodeResult::fanout(fn_(std::move(ctx)));
    }

private:
    Fn fn_;
};

// Fan-in: collects all non-exited sibling TaskContexts into one.
// The runner calls collectOne() for each completed sibling, then finalize().
class CollectorNode : public Node {
public:
    using Fn = std::function<TaskContext(std::vector<TaskContext>)>;

    CollectorNode(const std::string& name, Fn fn = nullptr) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext) override {
        // not called directly; the runner calls collect() instead
        throw std::runtime_error("CollectorNode::execute should not be called directly");
    }

    TaskContext collect(std::vector<TaskContext> items) {
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

private:
    Fn fn_;
};

} // namespace area::graph
