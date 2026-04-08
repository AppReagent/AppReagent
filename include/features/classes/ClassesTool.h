#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class ClassesTool : public Tool {
 public:
    std::string name() const override { return "CLASSES"; }
    std::string description() const override {
        return "<path> [| <filter>] — list all classes in a decompiled app directory. "
               "Shows class hierarchy (superclass, interfaces), method count, and field count, "
               "grouped by package. Use filter to narrow results by class or package name.\n"
               "  Example: CLASSES: /path/to/decompiled-app\n"
               "  Example: CLASSES: /path/to/app | com.example.network\n"
               "  Example: CLASSES: /path/to/app | Service";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

}  // namespace area
