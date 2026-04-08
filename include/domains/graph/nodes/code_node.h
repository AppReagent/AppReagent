#pragma once

#include <functional>
#include <string>
#include <utility>

#include "../engine/node.h"
#include "domains/graph/engine/task_context.h"

namespace area::graph {

class CodeNode : public Node {
 public:
    using Fn = std::function<TaskContext(TaskContext)>;

    CodeNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override;

 private:
    Fn fn_;
};

class PredicateCodeNode : public Node {
 public:
    using Fn = std::function<bool(const TaskContext&)>;

    PredicateCodeNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override;

 private:
    Fn fn_;
};

class DecisionCodeNode : public Node {
 public:
    using Fn = std::function<std::string(const TaskContext&)>;

    DecisionCodeNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override;

 private:
    Fn fn_;
};

class ExitNode : public Node {
 public:
    using Fn = std::function<void(TaskContext&)>;

    explicit ExitNode(const std::string& name, Fn fn = nullptr) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override;

 private:
    Fn fn_;
};

}  // namespace area::graph
