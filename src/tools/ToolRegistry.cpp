#include "tools/ToolRegistry.h"
#include "tools/ToolContext.h"

namespace area {

void ToolRegistry::add(std::unique_ptr<Tool> tool) {
    tools_.push_back(std::move(tool));
}

std::optional<ToolResult> ToolRegistry::dispatch(const std::string& action, ToolContext& ctx) {
    for (auto& tool : tools_) {
        auto result = tool->tryExecute(action, ctx);
        if (result.has_value()) return result;
    }
    return std::nullopt;
}

std::string ToolRegistry::describeAll() const {
    std::string out = "AVAILABLE TOOLS — use exactly one per turn:\n\n";
    for (auto& tool : tools_) {
        out += tool->name() + ": " + tool->description() + "\n\n";
    }
    out += "ANSWER: <text> — provide a final answer to the user. Cite specific methods, "
           "classes, and evidence from the code. Do not answer without evidence.\n";
    return out;
}

std::vector<std::string> ToolRegistry::prefixes() const {
    std::vector<std::string> result;
    for (auto& tool : tools_) {
        result.push_back(tool->name() + ":");
    }
    return result;
}

} // namespace area
