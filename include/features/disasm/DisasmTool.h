#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class DisasmTool : public Tool {
 public:
    std::string name() const override { return "DISASM"; }
    std::string description() const override {
        return "<path> [| <class>::<method>] — display the source code of a smali method "
               "or ELF function. Without a method filter, lists all methods in the file.\n"
               "  Example: DISASM: /path/to/SmsExfil.smali | sendStolenData\n"
               "  Example: DISASM: /path/to/SmsExfil.smali (lists all methods)\n"
               "  Example: DISASM: /path/to/lib.so | main";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

}  // namespace area
