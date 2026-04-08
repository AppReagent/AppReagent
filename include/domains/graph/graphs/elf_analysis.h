#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace area::graph {

nlohmann::json computeElfFileSignals(const std::vector<std::string>& imports,
                                      const std::vector<std::string>& exports);

nlohmann::json computeElfMethodStaticAnalysis(const std::string& disasm,
                                               const std::string& importsSummary);

}
