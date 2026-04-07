#pragma once

#include <string>
#include <vector>

namespace area::mcp {

struct CmdResult {
    std::string output;
    int exitCode;
};

/// Fork+exec a command, capture stdout+stderr, return output and exit code.
CmdResult exec(const std::string& workDir, const std::vector<std::string>& argv);

/// Trim output to maxLen, keeping the tail.
std::string trimOutput(std::string s, size_t maxLen = 4000);

/// Check if a string is a valid name (alphanumeric, hyphens, underscores).
bool isValidName(const std::string& s);

} // namespace area::mcp
