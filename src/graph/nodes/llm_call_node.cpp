#include "graph/nodes/llm_call_node.h"

#include <regex>

namespace area::graph {

std::string resolveTemplate(const std::string& tmpl, const TaskContext& ctx) {
    std::string result = tmpl;
    std::regex re(R"(\{\{(\w+)\}\})");
    std::smatch match;
    std::string working = result;
    std::string output;

    auto it = working.cbegin();
    auto end = working.cend();
    while (std::regex_search(it, end, match, re)) {
        output.append(it, it + match.position());
        std::string key = match[1].str();
        if (ctx.has(key)) {
            auto& val = ctx.get(key);
            if (val.is_string()) {
                output += val.get<std::string>();
            } else {
                output += val.dump();
            }
        } else {
            output += match[0].str(); // leave unresolved
        }
        it += match.position() + match.length();
    }
    output.append(it, end);
    return output;
}

LLMCallNode::LLMCallNode(const std::string& name, LLMCallConfig config, area::LLMBackend* backend)
    : Node(name), config_(std::move(config)), backend_(backend) {}

NodeResult LLMCallNode::execute(TaskContext ctx) {
    std::string prompt = resolveTemplate(config_.prompt_template, ctx);
    std::string system = resolveTemplate(config_.system_prompt, ctx);

    std::vector<area::ChatMessage> messages = {{"user", prompt}};
    std::string response = backend_->chat(system, messages);

    ctx.set("llm_response", response);
    ctx.set("llm_prompt", prompt);
    return NodeResult::single(std::move(ctx));
}

const LLMCallConfig& LLMCallNode::config() const { return config_; }

} // namespace area::graph
