#pragma once

#include "tools/Tool.h"

namespace area {

class ReadFileTool : public Tool {
public:
    std::string name() const override { return "READ"; }
    std::string description() const override {
        return "<path> [| <start>-<end>] or <path> | method <name> — "
               "read a file and display its contents with line numbers. "
               "Optionally specify a line range or extract a specific method from smali.\n"
               "  Example: READ: /path/to/File.smali\n"
               "  Example: READ: /path/to/File.smali | 10-50\n"
               "  Example: READ: /path/to/File.smali | method sendSMS";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

} // namespace area
