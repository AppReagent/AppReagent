#pragma once

#include <functional>
#include "../engine/node.h"

namespace area::graph {

class SplitterNode : public Node {
public:
    using Fn = std::function<std::vector<TaskContext>(TaskContext)>;

    SplitterNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override;

private:
    Fn fn_;
};

class CollectorNode : public Node {
public:
    using Fn = std::function<TaskContext(std::vector<TaskContext>)>;

    CollectorNode(const std::string& name, Fn fn = nullptr) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext) override;

    TaskContext collect(std::vector<TaskContext> items);

private:
    Fn fn_;
};

} // namespace area::graph
