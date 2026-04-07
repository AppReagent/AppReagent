#pragma once

#include <memory>
#include <string>
#include <vector>

#include "task_context.h"

namespace area::graph {

struct NodeResult {
    std::vector<TaskContext> outputs;
    std::string branch;
    bool exit = false;

    static NodeResult single(TaskContext ctx) {
        return {{std::move(ctx)}, {}, false};
    }
    static NodeResult branched(TaskContext ctx, std::string branch) {
        return {{std::move(ctx)}, std::move(branch), false};
    }
    static NodeResult fanout(std::vector<TaskContext> contexts) {
        return {std::move(contexts), {}, false};
    }
    static NodeResult exited() {
        return {{}, {}, true};
    }
};

class Node {
public:
    explicit Node(std::string name) : name_(std::move(name)) {}
    virtual ~Node() = default;

    const std::string& name() const { return name_; }

    virtual NodeResult execute(TaskContext ctx) = 0;

private:
    std::string name_;
};

using NodePtr = std::shared_ptr<Node>;

} // namespace area::graph
