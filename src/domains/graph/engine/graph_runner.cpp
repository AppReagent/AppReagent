#include "domains/graph/engine/graph_runner.h"

#include <semaphore>
#include <stdexcept>
#include <thread>

namespace area::graph {

void GraphRunner::emitStart(const std::string& name, const TaskContext& ctx) {
    std::lock_guard lk(cbMu_);
    if (onStart_) onStart_(name, ctx);
}

void GraphRunner::emitEnd(const std::string& name, const TaskContext& ctx) {
    std::lock_guard lk(cbMu_);
    if (onEnd_) onEnd_(name, ctx);
}

TaskContext GraphRunner::run(const TaskGraph& graph, TaskContext initial) {
    if (graph.entry().empty()) {
        throw std::runtime_error("graph has no entry node");
    }
    RunState state{graph, {}};
    return executeFrom(state, graph.entry(), std::move(initial));
}

TaskContext GraphRunner::executeFrom(RunState& state, const std::string& nodeName, TaskContext ctx) {
    Node* node = state.graph.getNode(nodeName);
    if (!node) {
        throw std::runtime_error("node not found: " + nodeName);
    }

    emitStart(nodeName, ctx);

    auto* collector = dynamic_cast<CollectorNode*>(node);
    if (collector) {
        auto result = collector->collect(std::move(state.collected));
        state.collected.clear();
        emitEnd(nodeName, result);

        auto nextEdges = state.graph.edgesFrom(nodeName);
        if (nextEdges.empty()) return result;
        return executeFrom(state, nextEdges[0]->to, std::move(result));
    }

    NodeResult nr = node->execute(std::move(ctx));

    if (nr.exit) {
        TaskContext discarded;
        discarded.discarded = true;
        emitEnd(nodeName, discarded);
        return discarded;
    }

    // Detect splitter nodes by presence of a "collect" edge OR multi-output.
    // Single-function ELF binaries produce 1 output but still need collector routing
    // when a "collect" edge exists.
    std::string subgraphEntry;
    std::string collectorName;
    for (auto* e : state.graph.allEdgesFrom(nodeName)) {
        if (e->branch == "collect") {
            collectorName = e->to;
        } else if (e->branch.empty()) {
            subgraphEntry = e->to;
        }
    }
    bool isSplitter = !collectorName.empty() || nr.outputs.size() > 1;

    if (isSplitter && !nr.outputs.empty()) {
        emitEnd(nodeName, nr.outputs[0]);
        if (subgraphEntry.empty()) {
            throw std::runtime_error("splitter node " + nodeName + " has no downstream edge");
        }

        std::vector<TaskContext> collected;
        std::mutex collectedMu;
        size_t n = nr.outputs.size();

        int concurrency = maxParallel_ > 0 ? maxParallel_ : (int)n;

        if (concurrency <= 1) {
            for (auto& splitCtx : nr.outputs) {
                RunState subState{state.graph, {}};
                auto result = executeFrom(subState, subgraphEntry, std::move(splitCtx));
                if (!result.discarded) {
                    collected.push_back(std::move(result));
                }
            }
        } else {
            std::counting_semaphore<> sem(concurrency);
            std::vector<std::thread> threads;

            for (auto& splitCtx : nr.outputs) {
                sem.acquire();
                threads.emplace_back([&, ctx = std::move(splitCtx)]() mutable {
                    try {
                        RunState subState{state.graph, {}};
                        auto result = executeFrom(subState, subgraphEntry, std::move(ctx));
                        if (!result.discarded) {
                            std::lock_guard lk(collectedMu);
                            collected.push_back(std::move(result));
                        }
                    } catch (...) {
                        // Ensure semaphore is always released even on exception
                    }
                    sem.release();
                });
            }

            for (auto& t : threads) t.join();
        }

        if (!collectorName.empty()) {
            state.collected = std::move(collected);
            return executeFrom(state, collectorName, TaskContext{});
        }

        if (!collected.empty()) return std::move(collected[0]);
        TaskContext empty;
        empty.discarded = true;
        return empty;
    }

    if (nr.outputs.empty()) {
        throw std::runtime_error("node " + nodeName + " produced no output");
    }
    auto& output = nr.outputs[0];
    emitEnd(nodeName, output);

    if (!nr.branch.empty()) {
        auto branchEdges = state.graph.edgesFrom(nodeName, nr.branch);
        if (branchEdges.empty()) {
            auto defaults = state.graph.edgesFrom(nodeName);
            if (defaults.empty()) return output;
            return executeFrom(state, defaults[0]->to, std::move(output));
        }
        return executeFrom(state, branchEdges[0]->to, std::move(output));
    }

    auto nextEdges = state.graph.edgesFrom(nodeName);
    if (nextEdges.empty()) return output;
    return executeFrom(state, nextEdges[0]->to, std::move(output));
}

} // namespace area::graph
