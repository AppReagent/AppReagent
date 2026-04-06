#include "tools/TuiTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"

#include <algorithm>

namespace area {

std::optional<ToolResult> TuiTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("TUI:") != 0 && action.find("TUI ") != 0)
        return std::nullopt;

    // Parse: "TUI: show task", "TUI: hide task"
    std::string rest = action.substr(action.find(':') != std::string::npos
                                     ? action.find(':') + 1
                                     : 4);
    // Trim leading whitespace
    while (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
    // Lowercase
    std::transform(rest.begin(), rest.end(), rest.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    bool show = false;
    std::string panel;

    if (rest.find("show ") == 0) {
        show = true;
        panel = rest.substr(5);
    } else if (rest.find("hide ") == 0) {
        show = false;
        panel = rest.substr(5);
    } else {
        return ToolResult{"Error: expected 'show <panel>' or 'hide <panel>'. Panels: task"};
    }

    // Trim panel name
    while (!panel.empty() && panel.back() == ' ') panel.pop_back();

    if (panel != "task") {
        return ToolResult{"Error: unknown panel '" + panel + "'. Available panels: task"};
    }

    // Emit TUI_CONTROL message — the server/TUI intercepts this
    std::string payload = R"({"panel":")" + panel + R"(","visible":)" + (show ? "true" : "false") + "}";
    ctx.cb({AgentMessage::TUI_CONTROL, payload});

    std::string obs = "Task pane " + std::string(show ? "shown" : "hidden") + ".";
    return ToolResult{"OBSERVATION: " + obs};
}

} // namespace area
