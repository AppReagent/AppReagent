#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class DecompileTool : public Tool {
 public:
    std::string name() const override { return "DECOMPILE"; }
    std::string description() const override {
        return "<path> [| method <name>] — decompile smali bytecode into readable pseudo-Java. "
               "Shows method bodies as approximate Java source with type names, method calls, and control flow. "
               "Without a method name, decompiles all methods in the file.\n"
               "  Example: DECOMPILE: /path/to/MyClass.smali | method exfiltrateData\n"
               "  Example: DECOMPILE: /path/to/MyClass.smali";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

}  // namespace area
