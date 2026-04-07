#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace area::graph {

// Compute file-level threat signals for an ELF binary from its import/export lists.
nlohmann::json computeElfFileSignals(const std::vector<std::string>& imports,
                                      const std::vector<std::string>& exports);

// Compute method-level static analysis for a single ELF function.
// disasm: Capstone disassembly text of the function.
// importsSummary: human-readable imports summary for context.
nlohmann::json computeElfMethodStaticAnalysis(const std::string& disasm,
                                               const std::string& importsSummary);

} // namespace area::graph
