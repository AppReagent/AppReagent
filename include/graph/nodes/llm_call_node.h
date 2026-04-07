#pragma once

#include <string>

#include "../engine/node.h"
#include "LLMBackend.h"

namespace area::graph {

struct LLMCallConfig {
    int tier = 0;
    std::string prompt_template;
    std::string system_prompt = "You are a helpful assistant.";
    float temperature = 0.0f;
    int max_tokens = 15000;
};

std::string resolveTemplate(const std::string& tmpl, const TaskContext& ctx);

class LLMCallNode : public Node {
public:
    LLMCallNode(const std::string& name, LLMCallConfig config, area::LLMBackend* backend);

    NodeResult execute(TaskContext ctx) override;

    const LLMCallConfig& config() const;

private:
    LLMCallConfig config_;
    area::LLMBackend* backend_;
};

} // namespace area::graph
