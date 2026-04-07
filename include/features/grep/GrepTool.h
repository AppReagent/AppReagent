#pragma once

#include "infra/tools/Tool.h"

namespace area {

class GrepTool : public Tool {
public:
    std::string name() const override { return "GREP"; }
    std::string description() const override {
        return "<pattern> [| <path>] — search code files for a text pattern. "
               "Returns matching lines with file path and line number. "
               "Searches .smali, .xml, .java, .kt, .json, .txt, .properties files. "
               "Pattern is case-insensitive substring match.\n"
               "  Example: GREP: HttpURLConnection | /path/to/app\n"
               "  Example: GREP: invoke-virtual.*sendTextMessage\n"
               "  Example: GREP: const-string.*http | /samples/app";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

} // namespace area
