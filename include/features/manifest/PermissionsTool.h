#pragma once

#include "infra/tools/Tool.h"

namespace area {

class PermissionsTool : public Tool {
public:
    std::string name() const override { return "PERMISSIONS"; }
    std::string description() const override {
        return "<path-to-AndroidManifest.xml-or-directory> — parse AndroidManifest.xml "
               "for permissions, exported components, intent filters, receivers, services, "
               "and content providers. Flags dangerous permission combinations.\n"
               "  Example: PERMISSIONS: /path/to/AndroidManifest.xml\n"
               "  Example: PERMISSIONS: /path/to/decompiled-app/";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

} // namespace area
