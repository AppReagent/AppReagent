#pragma once

#include "tools/Tool.h"

namespace area {

class Sandbox;

class DecompileTool : public Tool {
public:
    explicit DecompileTool(Sandbox* sandbox) : sandbox_(sandbox) {}

    std::string name() const override { return "DECOMPILE"; }
    std::string description() const override {
        return "<path-to-APK> [| <output-dir>] — decompile an Android APK to extract "
               "smali bytecode, resources, and AndroidManifest.xml using apktool. "
               "Output is ready for scanning.\n"
               "  Example: DECOMPILE: /path/to/app.apk\n"
               "  Example: DECOMPILE: /path/to/app.apk | /tmp/decompiled";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    Sandbox* sandbox_;
};

} // namespace area
