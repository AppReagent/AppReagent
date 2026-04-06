#pragma once

#include "tools/Tool.h"

namespace area {

class StringsTool : public Tool {
public:
    std::string name() const override { return "STRINGS"; }
    std::string description() const override {
        return "<path> [| <filter>] — extract hardcoded strings from smali/code files. "
               "Pulls const-string values, URLs, IPs, file paths, and other string literals. "
               "Optional filter to search within extracted strings.\n"
               "  Example: STRINGS: /path/to/app\n"
               "  Example: STRINGS: /path/to/File.smali | http\n"
               "  Example: STRINGS: /samples/app | .com";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

} // namespace area
