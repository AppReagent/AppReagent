#pragma once

#include <functional>
#include "../engine/node.h"

namespace area::graph {

// Runs a user-supplied function. The most basic node.
class CodeNode : public Node {
public:
    using Fn = std::function<TaskContext(TaskContext)>;

    CodeNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override {
        return NodeResult::single(fn_(std::move(ctx)));
    }

private:
    Fn fn_;
};

// Runs a boolean function. Routes to "pass" or "fail" branch.
class PredicateCodeNode : public Node {
public:
    using Fn = std::function<bool(const TaskContext&)>;

    PredicateCodeNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override {
        bool result = fn_(ctx);
        return NodeResult::branched(std::move(ctx), result ? "pass" : "fail");
    }

private:
    Fn fn_;
};

// Runs a function that returns a branch key string.
class DecisionCodeNode : public Node {
public:
    using Fn = std::function<std::string(const TaskContext&)>;

    DecisionCodeNode(const std::string& name, Fn fn) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override {
        std::string branch = fn_(ctx);
        return NodeResult::branched(std::move(ctx), std::move(branch));
    }

private:
    Fn fn_;
};

// Terminates a task early. Marks it as discarded.
class ExitNode : public Node {
public:
    using Fn = std::function<void(TaskContext&)>;

    ExitNode(const std::string& name, Fn fn = nullptr) : Node(name), fn_(std::move(fn)) {}

    NodeResult execute(TaskContext ctx) override {
        ctx.discarded = true;
        if (fn_) fn_(ctx);
        return NodeResult::exited();
    }

private:
    Fn fn_;
};

} // namespace area::graph
