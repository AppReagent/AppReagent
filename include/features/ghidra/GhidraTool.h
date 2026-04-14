#pragma once

#include <optional>
#include <string>

#include "infra/tools/Tool.h"

namespace area {
class GhidraTool : public Tool {
 public:
    std::string name() const override { return "GHIDRA"; }
    std::string description() const override {
        return "<path> [| <mode> [| <filter>]] — deep binary analysis using Ghidra's "
               "decompiler and program analysis. Works on ELF, PE, Mach-O, and raw "
               "object files. Provides decompiled C code, function signatures, imports, "
               "exports, strings with cross-references, and call graphs.\n"
               "  Modes: overview (default), decompile, disasm, strings, imports, xrefs, "
               "function_at, data_at, all\n"
               "  Filter: function name substring OR hex address (0x1000D02E or 1000D02E).\n"
               "    When given an address, decompile and function_at resolve to the "
               "function containing that address. data_at resolves the defined data item "
               "at that address. xrefs works for both code and data addresses.\n"
               "  Example: GHIDRA: /path/to/binary.elf\n"
               "  Example: GHIDRA: /path/to/binary.so | decompile | main\n"
               "  Example: GHIDRA: /path/to/binary.so | disasm | 0x40123a\n"
               "  Example: GHIDRA: /path/to/binary.dll | decompile | 0x10001656\n"
               "  Example: GHIDRA: /path/to/binary.dll | function_at | 0x10001656\n"
               "  Example: GHIDRA: /path/to/binary.dll | data_at | 0x1001D988\n"
               "  Example: GHIDRA: /path/to/malware.elf | strings\n"
               "  Example: GHIDRA: /path/to/lib.o | xrefs | connect\n"
               "  Example: GHIDRA: /path/to/binary.dll | xrefs | 0x1000D02E\n"
               "  Example: GHIDRA: /path/to/binary | all";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

 protected:
    virtual std::optional<std::string> checkEnvironment() const;
    virtual std::string runGhidra(const std::string& binaryPath,
                                  const std::string& mode,
                                  const std::string& filter,
                                  const std::string& outputPath,
                                  std::string& ghidraLog);

 private:
    std::string formatOverview(const std::string& jsonPath);
    std::string formatDecompile(const std::string& jsonPath);
    std::string formatDisasm(const std::string& jsonPath);
    std::string formatStrings(const std::string& jsonPath);
    std::string formatImports(const std::string& jsonPath);
    std::string formatXrefs(const std::string& jsonPath);
    std::string formatFunctionAt(const std::string& jsonPath);
    std::string formatDataAt(const std::string& jsonPath);
    std::string formatAll(const std::string& jsonPath);
};
}  // namespace area
