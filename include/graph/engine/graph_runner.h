#pragma once

#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include "task_context.h"
#include "task_graph.h"
#include "../nodes/code_node.h"
#include "../nodes/splitter_node.h"

namespace area::graph {

using NodeCallback = std::function<void(const std::string& node_name, const TaskContext& ctx)>;

class GraphRunner {
public:
    void onNodeStart(NodeCallback cb) { std::lock_guard lk(cbMu_); onStart_ = std::move(cb); }
    void onNodeEnd(NodeCallback cb) { std::lock_guard lk(cbMu_); onEnd_ = std::move(cb); }
    void setMaxParallel(int n) { maxParallel_ = n; }

    TaskContext run(const TaskGraph& graph, TaskContext initial);

private:
    struct RunState {
        const TaskGraph& graph;
        std::vector<TaskContext> collected;
    };

    TaskContext executeFrom(RunState& state, const std::string& nodeName, TaskContext ctx);

    void emitStart(const std::string& name, const TaskContext& ctx);
    void emitEnd(const std::string& name, const TaskContext& ctx);

    NodeCallback onStart_;
    NodeCallback onEnd_;
    std::mutex cbMu_;
    int maxParallel_ = 0; // 0 = unlimited
};

} // namespace area::graph
