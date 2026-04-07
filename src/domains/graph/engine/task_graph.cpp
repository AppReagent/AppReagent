#include "domains/graph/engine/task_graph.h"

namespace area::graph {

TaskGraph::TaskGraph(std::string name) : name_(std::move(name)) {}

const std::string& TaskGraph::name() const { return name_; }

void TaskGraph::addNode(NodePtr node) {
    auto name = node->name();
    if (nodes_.contains(name)) {
        throw std::runtime_error("duplicate node name: " + name);
    }
    order_.push_back(name);
    nodes_[name] = std::move(node);
}

void TaskGraph::edge(const std::string& from, const std::string& to) {
    edges_.push_back({from, to, ""});
}

void TaskGraph::edge(const NodePtr& from, const NodePtr& to) {
    edge(from->name(), to->name());
}

void TaskGraph::branch(const std::string& from, const std::string& branch_key, const std::string& to) {
    edges_.push_back({from, to, branch_key});
}

void TaskGraph::branch(const NodePtr& from, const std::string& branch_key, const NodePtr& to) {
    branch(from->name(), branch_key, to->name());
}

void TaskGraph::setEntry(const std::string& name) { entry_ = name; }
void TaskGraph::setEntry(const NodePtr& node) { entry_ = node->name(); }
void TaskGraph::setOutput(const std::string& name) { output_ = name; }
void TaskGraph::setOutput(const NodePtr& node) { output_ = node->name(); }

Node* TaskGraph::getNode(const std::string& name) const {
    auto it = nodes_.find(name);
    return it != nodes_.end() ? it->second.get() : nullptr;
}

const std::string& TaskGraph::entry() const { return entry_; }
const std::string& TaskGraph::output() const { return output_; }
const std::vector<Edge>& TaskGraph::edges() const { return edges_; }
const std::vector<std::string>& TaskGraph::nodeOrder() const { return order_; }

std::vector<const Edge*> TaskGraph::edgesFrom(const std::string& node, const std::string& branch) const {
    std::vector<const Edge*> result;
    for (auto& e : edges_) {
        if (e.from == node) {
            if (branch.empty() && e.branch.empty()) {
                result.push_back(&e);
            } else if (!branch.empty() && e.branch == branch) {
                result.push_back(&e);
            }
        }
    }
    return result;
}

std::vector<const Edge*> TaskGraph::allEdgesFrom(const std::string& node) const {
    std::vector<const Edge*> result;
    for (auto& e : edges_) {
        if (e.from == node) result.push_back(&e);
    }
    return result;
}

} // namespace area::graph
