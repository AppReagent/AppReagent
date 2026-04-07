#pragma once

#include "tools/Tool.h"

namespace area {

class GhidraTool : public Tool {
public:
    std::string name() const override { return "GHIDRA"; }
    std::string description() const override {
        return "<path> [| <mode> [| <filter>]] — deep binary analysis using Ghidra's "
               "decompiler and program analysis. Works on ELF, PE, Mach-O, and raw "
               "object files. Provides decompiled C code, function signatures, imports, "
               "exports, strings with cross-references, and call graphs.\n"
               "  Modes: overview (default), decompile, strings, imports, xrefs, all\n"
               "  Example: GHIDRA: /path/to/binary.elf\n"
               "  Example: GHIDRA: /path/to/binary.so | decompile | main\n"
               "  Example: GHIDRA: /path/to/malware.elf | strings\n"
               "  Example: GHIDRA: /path/to/lib.o | xrefs | connect\n"
               "  Example: GHIDRA: /path/to/binary | all";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    // Returns "" on success, error message on failure.
    std::string runGhidra(const std::string& binaryPath,
                          const std::string& mode,
                          const std::string& filter,
                          const std::string& outputPath,
                          std::string& ghidraLog);

    std::string formatOverview(const std::string& jsonPath);
    std::string formatDecompile(const std::string& jsonPath);
    std::string formatStrings(const std::string& jsonPath);
    std::string formatImports(const std::string& jsonPath);
    std::string formatXrefs(const std::string& jsonPath);
    std::string formatAll(const std::string& jsonPath);
};

} // namespace area
