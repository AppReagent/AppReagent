#pragma once

#include <stddef.h>
#include <string>
#include <vector>

namespace area::mcp {

struct CmdResult {
    std::string output;
    int exitCode;
};

CmdResult exec(const std::string& workDir, const std::vector<std::string>& argv);

std::string trimOutput(std::string s, size_t maxLen = 4000);

bool isValidName(const std::string& s);

}  // namespace area::mcp
