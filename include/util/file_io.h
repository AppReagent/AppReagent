#pragma once

#include <fstream>
#include <sstream>
#include <string>

namespace area::util {

std::string readFile(const std::string& path);
std::string readFileOrThrow(const std::string& path);

} // namespace area::util
