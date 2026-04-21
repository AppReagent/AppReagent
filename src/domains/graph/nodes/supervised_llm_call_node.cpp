#include "domains/graph/nodes/supervised_llm_call_node.h"

#include <stddef.h>

#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>
#include <cctype>
#include <exception>
#include <map>
#include <utility>
#include <vector>

#include "util/string_util.h"
#include "domains/graph/engine/node.h"
#include "domains/graph/nodes/llm_call_node.h"
#include "nlohmann/json.hpp"

namespace area::graph {

SupervisedLLMCallNode::SupervisedLLMCallNode(const std::string& name,
                                             SupervisedLLMCallConfig config,
                                             area::LLMBackend* worker_backend,
                                             area::LLMBackend* supervisor_backend,
                                             ValidationFn validation)
    : Node(name)
    , config_(std::move(config))
    , workerBackend_(worker_backend)
    , supervisorBackend_(supervisor_backend)
    , validation_(std::move(validation)) {
}

NodeResult SupervisedLLMCallNode::execute(TaskContext ctx) {
    std::string prompt = resolveTemplate(config_.prompt_template, ctx);
    std::string system = resolveTemplate(config_.system_prompt, ctx);

    for (int attempt = 0; attempt <= config_.max_retries; attempt++) {
        ctx.error_count = attempt;

        std::string workerResponse;
        try {
            std::vector<area::ChatMessage> msgs = {{"user", prompt}};
            workerResponse = workerBackend_->chat(system, msgs);
        } catch (const std::exception& e) {
            std::cerr << "[supervised:" << name() << "] worker error (attempt "
                      << attempt + 1 << "): " << e.what() << std::endl;
            int backoffMs = 1000 * (1 << std::min(attempt, 4));
            std::this_thread::sleep_for(std::chrono::milliseconds(backoffMs));
            continue;
        }

        if (validation_ && !validation_(workerResponse, ctx)) {
            std::cerr << "[supervised:" << name() << "] validation failed, attempt "
                      << attempt + 1 << "/" << config_.max_retries + 1 << std::endl;
            continue;
        }

        std::string supervisorVerdict;
        if (workerBackend_ != supervisorBackend_) {
            try {
                std::string supPrompt = resolveTemplate(config_.supervisor_prompt, ctx);
                supPrompt += "\n\nOriginal prompt given to worker:\n" + prompt;
                supPrompt += "\n\nWorker output to review:\n" + workerResponse;
                std::vector<area::ChatMessage> supMsgs = {{"user", supPrompt}};
                supervisorVerdict = supervisorBackend_->chat(
                    resolveTemplate(config_.supervisor_system, ctx), supMsgs);
            } catch (const std::exception& e) {
                std::cerr << "[supervised:" << name() << "] supervisor error: " << e.what() << std::endl;
                continue;
            }

            std::string trimmed = supervisorVerdict;
            area::util::ltrimInPlace(trimmed);
            std::string prefix;
            for (size_t i = 0; i < std::min(trimmed.size(), static_cast<size_t>(4)); i++)
                prefix += std::toupper(static_cast<unsigned char>(trimmed[i]));
            if (prefix == "FAIL") {
                std::cerr << "[supervised:" << name() << "] supervisor rejected, attempt "
                          << attempt + 1 << "/" << config_.max_retries + 1
                          << ": " << supervisorVerdict.substr(0, 120) << std::endl;
                continue;
            }
        }

        ctx.set("llm_response", workerResponse);
        ctx.set("llm_prompt", prompt);
        ctx.set("supervisor_verdict", supervisorVerdict);
        ctx.error_count = 0;
        return NodeResult::single(std::move(ctx));
    }

    ctx.set("llm_error", "max retries exhausted after " +
            std::to_string(config_.max_retries + 1) + " attempts");
    return NodeResult::single(std::move(ctx));
}

}  // namespace area::graph
