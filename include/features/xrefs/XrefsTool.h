#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {

class XrefsTool : public Tool {
 public:
    std::string name() const override { return "XREFS"; }
    std::string description() const override {
        return "<identifier> [| <path>] — find all cross-references to a class, method, "
               "field, or string across smali code. Shows where the identifier is used "
               "(invocations, field accesses, instantiations, string references).\n"
               "  Example: XREFS: Lcom/example/NetworkHelper;\n"
               "  Example: XREFS: sendTextMessage | /samples/app\n"
               "  Example: XREFS: HttpURLConnection | /path/to/decompiled";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;
};

}  // namespace area
