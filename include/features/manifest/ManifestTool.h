#pragma once

#include "infra/tools/Tool.h"

namespace area {

class ManifestTool : public Tool {
public:
    std::string name() const override { return "MANIFEST"; }
    std::string description() const override {
        return "<path> — parse AndroidManifest.xml and display app metadata: "
               "permissions, activities, services, receivers, providers, and intent filters. "
               "Path can be the manifest file directly or a directory containing it.\n"
               "  Example: MANIFEST: /path/to/AndroidManifest.xml\n"
               "  Example: MANIFEST: /path/to/decompiled-app";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

} // namespace area
