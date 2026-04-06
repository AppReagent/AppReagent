#pragma once

#include "tools/Tool.h"
#include "Database.h"

namespace area {

class CallGraphTool : public Tool {
public:
    explicit CallGraphTool(Database& db) : db_(db) {}

    std::string name() const override { return "CALLGRAPH"; }
    std::string description() const override {
        return "<run_id> <class>::<method> | callers | callees — query the method call graph "
               "built during scanning. Shows which methods call a given method (callers) or "
               "which methods it calls (callees). Defaults to callees.\n"
               "  Example: CALLGRAPH: latest Lcom/example/Malware;::sendSMS callees\n"
               "  Example: CALLGRAPH: latest Landroid/telephony/SmsManager;::sendTextMessage callers\n"
               "  Example: CALLGRAPH: abc123 Lcom/example/Malware;::onCreate";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    Database& db_;
};

} // namespace area
