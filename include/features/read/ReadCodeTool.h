#pragma once

#include "infra/tools/Tool.h"

namespace area {

class ReadCodeTool : public Tool {
public:
    std::string name() const override { return "READ"; }
    std::string description() const override {
        return "<path> [method_name] — read and display source code from a file. "
               "For .smali files, optionally specify a method name to show only that method. "
               "For ELF binaries, disassembles and shows functions. "
               "Use this to examine code the user asks about or to verify scan findings.\n"
               "  Example: READ: /path/to/SmsExfil.smali\n"
               "  Example: READ: /path/to/SmsExfil.smali sendStolenData\n"
               "  Example: READ: /path/to/libnative.so";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

} // namespace area
