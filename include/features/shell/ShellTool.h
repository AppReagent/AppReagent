#pragma once

#include "infra/tools/Tool.h"

namespace area {

class Sandbox;

class ShellTool : public Tool {
public:
    explicit ShellTool(Sandbox* sandbox) : sandbox_(sandbox) {}

    std::string name() const override { return "SHELL"; }
    std::string description() const override {
        return "<command> — run a command in a sandboxed Docker container "
               "(Python 3.11, numpy, pandas, matplotlib, no internet). "
               "/samples is read-only, /workspace is writable.";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    Sandbox* sandbox_;
};

} // namespace area
