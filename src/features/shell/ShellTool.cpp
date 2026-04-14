#include "features/shell/ShellTool.h"

#include <sys/wait.h>

#include <array>
#include <functional>
#include <memory>
#include <sstream>

#include "infra/agent/Agent.h"
#include "infra/agent/Harness.h"
#include "infra/tools/ToolContext.h"
#include "util/string_util.h"

namespace area {
namespace {
struct HostExecResult {
    std::string output;
    int exitCode = -1;
};

HostExecResult runHostCommand(const std::string& command, int timeoutSec) {
    std::ostringstream wrapped;
    wrapped << "timeout " << timeoutSec
            << " bash -lc " << util::shellQuote(command)
            << " 2>&1";

    FILE* pipe = popen(wrapped.str().c_str(), "r");
    if (pipe == nullptr) {
        return {"failed to execute command", -1};
    }

    auto pcloseDeleter = [](FILE* f) { return pclose(f); };
    std::unique_ptr<FILE, decltype(pcloseDeleter)> pipeGuard(pipe, pcloseDeleter);
    std::array<char, 4096> buffer{};
    std::string output;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipeGuard.get()) != nullptr) {
        output += buffer.data();
    }

    int status = pclose(pipeGuard.release());
    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    const size_t maxOutput = 8192;
    if (output.size() > maxOutput) {
        output.resize(maxOutput);
        output += "\n... (output truncated at " + std::to_string(maxOutput) + " bytes)";
    }
    while (!output.empty() && output.back() == '\n') output.pop_back();
    return {output, exitCode};
}
}  // namespace

std::optional<ToolResult> ShellTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("SHELL:"))
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

    ctx.cb({AgentMessage::THINKING, "Running: " + command});
    auto result = runHostCommand(command, 60);

    std::string output = result.output;
    if (output.empty()) output = "(no output)";
    std::string exitStr = "exit code: " + std::to_string(result.exitCode);
    std::string observation = exitStr + "\n" + output;

    ctx.cb({AgentMessage::RESULT, observation});

    std::string sensorFeedback = ctx.harness.runSensors("shell", command, observation);

    std::string feedback = "OBSERVATION: " + observation;
    if (!sensorFeedback.empty()) {
        feedback += "\n\nSENSOR FEEDBACK:\n" + sensorFeedback;
    }
    return ToolResult{feedback};
}

}  // namespace area
