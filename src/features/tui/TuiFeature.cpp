#include "features/tui/TuiFeature.h"

#include <algorithm>
#include <map>
#include <memory>
#include <stdexcept>

#include "features/tui/HeadlessTui.h"
#include "mcp/McpTool.h"
#include "nlohmann/detail/json_ref.hpp"
#include "nlohmann/json.hpp"
using json = nlohmann::json;

namespace area::features::tui {

struct TuiState {
    std::string binary;
    std::string sockPath;
    std::unique_ptr<HeadlessTui> tui;

    HeadlessTui& ensure() {
        if (!tui) {
            tui = std::make_unique<HeadlessTui>(binary, sockPath);
        }
        if (!tui->isRunning()) {
            if (!tui->start())
                throw std::runtime_error("Failed to start headless TUI.");
        }
        return *tui;
    }

    std::string screenResult() {
        auto& t = *tui;
        return "[" + std::to_string(t.cols()) + "x" + std::to_string(t.rows()) +
               " cursor=" + std::to_string(t.cursorRow() + 1) + ":" +
               std::to_string(t.cursorCol() + 1) + "]\n" + t.screenText();
    }
};

void registerTools(mcp::McpServer& server,
                   const std::string& binary,
                   const std::string& sockPath) {
    auto state = std::make_shared<TuiState>();
    state->binary = binary;
    state->sockPath = sockPath;

    server.registerTool({
        "area_tui_screen",
        "Get the current TUI screen as plain text. Starts the headless TUI "
        "if not already running. Use this to see what the TUI displays.",
        {{"type", "object"}, {"properties", {
             {"wait_ms", {{"type", "integer"},
                          {"description",
                           "Milliseconds to wait for output to settle "
                           "(default: 200, max: 2000)."}}}
        }}},
        [state](const json& args) -> mcp::ToolResult {
            auto& tui = state->ensure();
            int waitMs = std::clamp(args.value("wait_ms", 200), 0, 2000);
            tui.drainAndSettle(waitMs);
            return {state->screenResult(), false};
        }
    });

    server.registerTool({
        "area_tui_click",
        "Click at a position in the TUI. Coordinates are 1-based. "
        "Returns the screen after the click.",
        {{"type", "object"},
         {"properties", {
             {"row", {{"type", "integer"}, {"description", "Row (1-based)."}}},
             {"col", {{"type", "integer"}, {"description", "Column (1-based)."}}},
             {"button", {{"type", "string"}, {"enum", {"left", "right"}},
                         {"description", "Mouse button (default: left)."}}}
         }},
         {"required", json::array({"row", "col"})}},
        [state](const json& args) -> mcp::ToolResult {
            auto& tui = state->ensure();
            int row = args.value("row", 1);
            int col = args.value("col", 1);
            std::string button = args.value("button", "left");
            int btn = (button == "right") ? 2 : 0;
            tui.sendMouseClick(row, col, btn);
            tui.sendMouseRelease(row, col, btn);
            tui.drainAndSettle(200);
            return {state->screenResult(), false};
        }
    });

    server.registerTool({
        "area_tui_type",
        "Type text into the TUI. Does not press Enter automatically. "
        "Returns the screen after typing.",
        {{"type", "object"},
         {"properties", {
             {"text", {{"type", "string"},
                       {"description", "Text to type."}}}
         }},
         {"required", json::array({"text"})}},
        [state](const json& args) -> mcp::ToolResult {
            auto& tui = state->ensure();
            auto text = args.value("text", "");
            if (text.empty()) return {"'text' is required.", true};
            tui.sendText(text);
            tui.drainAndSettle(100);
            return {state->screenResult(), false};
        }
    });

    server.registerTool({
        "area_tui_key",
        "Press a special key. Supported: enter, escape, up, down, left, "
        "right, backspace, tab, pageup, pagedown, ctrl+a, ctrl+b, ctrl+c, "
        "ctrl+e, ctrl+k, ctrl+l, ctrl+u, ctrl+w. Returns screen after.",
        {{"type", "object"},
         {"properties", {
             {"key", {{"type", "string"},
                      {"description", "Key name (e.g. 'enter', 'ctrl+c')."}}}
         }},
         {"required", json::array({"key"})}},
        [state](const json& args) -> mcp::ToolResult {
            auto& tui = state->ensure();
            auto key = args.value("key", "");
            if (key.empty()) return {"'key' is required.", true};
            tui.sendKey(key);
            tui.drainAndSettle(200);
            return {state->screenResult(), false};
        }
    });

    server.registerTool({
        "area_tui_resize",
        "Resize the virtual terminal. Returns the screen after resize.",
        {{"type", "object"}, {"properties", {
             {"rows", {{"type", "integer"},
                       {"description", "Terminal height (default: 24)."}}},
             {"cols", {{"type", "integer"},
                       {"description", "Terminal width (default: 80)."}}}
        }}},
        [state](const json& args) -> mcp::ToolResult {
            auto& tui = state->ensure();
            int rows = args.value("rows", 24);
            int cols = args.value("cols", 80);
            rows = std::clamp(rows, 5, 200);
            cols = std::clamp(cols, 20, 400);
            tui.resize(rows, cols);
            tui.drainAndSettle(300);
            return {state->screenResult(), false};
        }
    });
}

}  // namespace area::features::tui
