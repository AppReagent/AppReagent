#pragma once

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
    explicit TaskGraph(std::string name);

    const std::string& name() const;

    template <typename T, typename... Args>
    std::shared_ptr<T> add(const std::string& name, Args&&... args) {
        auto node = std::make_shared<T>(name, std::forward<Args>(args)...);
        addNode(node);
        return node;
    }

    void addNode(NodePtr node);

    void edge(const std::string& from, const std::string& to);
    void edge(const NodePtr& from, const NodePtr& to);

    void branch(const std::string& from, const std::string& branch_key, const std::string& to);
    void branch(const NodePtr& from, const std::string& branch_key, const NodePtr& to);

    void setEntry(const std::string& name);
    void setEntry(const NodePtr& node);
    void setOutput(const std::string& name);
    void setOutput(const NodePtr& node);

    Node* getNode(const std::string& name) const;

    const std::string& entry() const;
    const std::string& output() const;
    const std::vector<Edge>& edges() const;
    const std::vector<std::string>& nodeOrder() const;

    std::vector<const Edge*> edgesFrom(const std::string& node, const std::string& branch = "") const;
    std::vector<const Edge*> allEdgesFrom(const std::string& node) const;

private:
    std::string name_;
    std::unordered_map<std::string, NodePtr> nodes_;
    std::vector<std::string> order_; // insertion order
    std::vector<Edge> edges_;
    std::string entry_;
    std::string output_;
};

} // namespace area::graph
