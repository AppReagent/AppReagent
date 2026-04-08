#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class FindFilesTool : public Tool {
 public:
    std::string name() const override { return "FIND_FILES"; }
    std::string description() const override {
        return "<query> [| <root>] — search for files or directories matching a name/pattern. "
               "Groups results by directory with scannable file counts (.smali, ELF). "
               "Use when the user gives a rough filename or app name and you need to find the actual path.\n"
               "  Example: FIND_FILES: SmsExfil\n"
               "  Example: FIND_FILES: *.smali | /home/user/samples";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

}  // namespace area
