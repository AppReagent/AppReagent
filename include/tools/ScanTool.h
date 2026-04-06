#pragma once

#include <string>
#include "tools/Tool.h"

namespace area {

class Config;
class Database;
class EventBus;
class ScanState;

class ScanTool : public Tool {
public:
    ScanTool(const Config* config, Database& db, ScanState* state,
             const std::string& chatId, EventBus* events = nullptr)
        : config_(config), db_(db), state_(state), chatId_(chatId), events_(events) {}

    std::string name() const override { return "SCAN"; }
    std::string description() const override {
        return "<path> | <goal> — scan .smali files with a specific analysis goal. "
               "Returns a cross-file synthesis that directly answers the goal question.\n"
               "  Goals can be high-level (automatically expanded) or detailed with specific APIs.\n"
               "  Example: SCAN: /path/to/app | Does this application exhibit ransomware behavior?\n"
               "  Example: SCAN: /path/to/app | Identify C2 communication patterns — look for "
               "java.net.Socket, HttpURLConnection, OkHttp, encoded URLs, or native socket calls.";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    const Config* config_;
    Database& db_;
    ScanState* state_;
    std::string chatId_;
    EventBus* events_;
};

} // namespace area
