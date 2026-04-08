#include "features/tui/TuiTool.h"

#include <algorithm>
#include <cctype>
#include <functional>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"

namespace area {

std::optional<ToolResult> TuiTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("TUI:") && !action.starts_with("TUI "))
        return std::nullopt;

    std::string rest = action.substr(action.find(':') != std::string::npos
                                     ? action.find(':') + 1
                                     : 4);
    while (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
    std::transform(rest.begin(), rest.end(), rest.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    bool show = false;
    std::string panel;

    if (rest.starts_with("show ")) {
        show = true;
        panel = rest.substr(5);
    } else if (rest.starts_with("hide ")) {
        show = false;
        panel = rest.substr(5);
    } else {
        return ToolResult{"Error: expected 'show <panel>' or 'hide <panel>'. Panels: task"};
    }

    while (!panel.empty() && panel.back() == ' ') panel.pop_back();

    if (panel != "task") {
        return ToolResult{"Error: unknown panel '" + panel + "'. Available panels: task"};
    }

    std::string payload = R"({"panel":")" + panel + R"(","visible":)" + (show ? "true" : "false") + "}";
    ctx.cb({AgentMessage::TUI_CONTROL, payload});

    std::string obs = "Task pane " + std::string(show ? "shown" : "hidden") + ".";
    return ToolResult{"OBSERVATION: " + obs};
}

}  // namespace area
