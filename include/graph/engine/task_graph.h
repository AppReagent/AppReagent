#pragma once

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "node.h"

namespace area::graph {

struct Edge {
    std::string from;
    std::string to;
    std::string branch; // empty = default, otherwise branch key for decision/predicate
};

class TaskGraph {
public:
    explicit TaskGraph(std::string name) : name_(std::move(name)) {}

    const std::string& name() const { return name_; }

    template <typename T, typename... Args>
    std::shared_ptr<T> add(const std::string& name, Args&&... args) {
        auto node = std::make_shared<T>(name, std::forward<Args>(args)...);
        addNode(node);
        return node;
    }

    void addNode(NodePtr node) {
        auto name = node->name();
        if (nodes_.contains(name)) {
            throw std::runtime_error("duplicate node name: " + name);
        }
        order_.push_back(name);
        nodes_[name] = std::move(node);
    }

    void edge(const std::string& from, const std::string& to) {
        edges_.push_back({from, to, ""});
    }
    void edge(const NodePtr& from, const NodePtr& to) {
        edge(from->name(), to->name());
    }

    void branch(const std::string& from, const std::string& branch_key, const std::string& to) {
        edges_.push_back({from, to, branch_key});
    }
    void branch(const NodePtr& from, const std::string& branch_key, const NodePtr& to) {
        branch(from->name(), branch_key, to->name());
    }

    void setEntry(const std::string& name) { entry_ = name; }
    void setEntry(const NodePtr& node) { entry_ = node->name(); }
    void setOutput(const std::string& name) { output_ = name; }
    void setOutput(const NodePtr& node) { output_ = node->name(); }

    Node* getNode(const std::string& name) const {
        auto it = nodes_.find(name);
        return it != nodes_.end() ? it->second.get() : nullptr;
    }

    const std::string& entry() const { return entry_; }
    const std::string& output() const { return output_; }
    const std::vector<Edge>& edges() const { return edges_; }
    const std::vector<std::string>& nodeOrder() const { return order_; }

    std::vector<const Edge*> edgesFrom(const std::string& node, const std::string& branch = "") const {
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

    std::vector<const Edge*> allEdgesFrom(const std::string& node) const {
        std::vector<const Edge*> result;
        for (auto& e : edges_) {
            if (e.from == node) result.push_back(&e);
        }
        return result;
    }

private:
    std::string name_;
    std::unordered_map<std::string, NodePtr> nodes_;
    std::vector<std::string> order_; // insertion order
    std::vector<Edge> edges_;
    std::string entry_;
    std::string output_;
};

} // namespace area::graph
