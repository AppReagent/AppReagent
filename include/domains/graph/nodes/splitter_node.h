#pragma once

#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "../engine/node.h"
#include "domains/graph/engine/task_context.h"

namespace area::graph {

class SplitterNode : public Node {
 public:
    using Fn = std::function<std::vector<TaskContext>(const TaskContext&)>;

    SplitterNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override;

 private:
    Fn fn_;
};

class CollectorNode : public Node {
 public:
    using Fn = std::function<TaskContext(const std::vector<TaskContext>&)>;

    explicit CollectorNode(const std::string& name, Fn fn = nullptr) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext) override;

    TaskContext collect(const std::vector<TaskContext>& items);

 private:
    Fn fn_;
};

}  // namespace area::graph
