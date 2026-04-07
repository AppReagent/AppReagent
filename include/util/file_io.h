#pragma once

#include <fstream>
#include <sstream>
#include <string>

namespace area::util {

std::string readFile(const std::string& path);
std::string readFileOrThrow(const std::string& path);

/// Resolve the path to the current executable via /proc/self/exe.
/// Handles the " (deleted)" suffix that appears after in-place binary replacement.
/// Returns empty string on failure.
std::string selfExe();

} // namespace area::util
