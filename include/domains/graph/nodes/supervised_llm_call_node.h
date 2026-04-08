#pragma once

#include <functional>
#include <string>

#include "../engine/node.h"
#include "infra/llm/LLMBackend.h"
#include "domains/graph/engine/task_context.h"

namespace area::graph {

struct SupervisedLLMCallConfig {
    int tier = 0;
    std::string prompt_template;
    std::string system_prompt = "You are a helpful assistant.";
    std::string supervisor_prompt;
    std::string supervisor_system = "You are a quality assurance reviewer.";
    int max_retries = 3;
    float temperature = 0.0f;
    int max_tokens = 15000;
};

using ValidationFn = std::function<bool(const std::string& response, const TaskContext& ctx)>;

class SupervisedLLMCallNode : public Node {
 public:
    SupervisedLLMCallNode(const std::string& name,
                          SupervisedLLMCallConfig config,
                          area::LLMBackend* worker_backend,
                          area::LLMBackend* supervisor_backend,
                          ValidationFn validation = nullptr);

    NodeResult execute(TaskContext ctx) override;

 private:
    SupervisedLLMCallConfig config_;
    area::LLMBackend* workerBackend_;
    area::LLMBackend* supervisorBackend_;
    ValidationFn validation_;
};

}  // namespace area::graph
