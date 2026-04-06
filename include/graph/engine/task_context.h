#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>

namespace area::graph {

class TaskContext {
public:
    void set(const std::string& key, nlohmann::json value) { data_[key] = std::move(value); }
    const nlohmann::json& get(const std::string& key) const { return data_.at(key); }
    bool has(const std::string& key) const { return data_.contains(key); }
    void remove(const std::string& key) { data_.erase(key); }

    const nlohmann::json& data() const { return data_; }

    void merge(const TaskContext& other) {
        for (auto& [k, v] : other.data_.items()) {
            data_[k] = v;
        }
    }

    std::string task_id;
    std::string parent_task_id;
    int error_count = 0;
    bool discarded = false;
    std::string discard_reason;

private:
    nlohmann::json data_ = nlohmann::json::object();
};

} // namespace area::graph
