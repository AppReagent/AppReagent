#include "tools/ShellTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"
#include "Harness.h"
#include "Sandbox.h"

namespace area {

std::optional<ToolResult> ShellTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("SHELL:") != 0)
        return std::nullopt;

    std::string command = action.substr(6);
    while (!command.empty() && command[0] == ' ') command.erase(0, 1);

    if (ctx.confirm) {
        auto r = ctx.confirm("SHELL: " + command);
        if (r.action == ConfirmResult::DENY)
            return ToolResult{"User denied this action."};
        if (r.action == ConfirmResult::CUSTOM)
            command = r.customText;
    }

    if (!sandbox_) {
        ctx.cb({AgentMessage::ERROR, "Shell not available (no sandbox configured)"});
        return ToolResult{"OBSERVATION: Error — shell not available. Sandbox not configured."};
    }

    ctx.cb({AgentMessage::THINKING, "Running: " + command});
    auto result = sandbox_->exec(command);

    std::string output = result.output;
    if (output.empty()) output = "(no output)";
    std::string exitStr = "exit code: " + std::to_string(result.exit_code);
    std::string observation = exitStr + "\n" + output;

    ctx.cb({AgentMessage::RESULT, observation});

    std::string sensorFeedback = ctx.harness.runSensors("shell", command, observation);

    std::string feedback = "OBSERVATION: " + observation;
    if (!sensorFeedback.empty()) {
        feedback += "\n\nSENSOR FEEDBACK:\n" + sensorFeedback;
    }
    return ToolResult{feedback};
}

} // namespace area
