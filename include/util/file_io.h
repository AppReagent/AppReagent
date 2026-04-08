#pragma once

#include <string>

namespace area::util {

std::string readFile(const std::string& path);
std::string readFileOrThrow(const std::string& path);

std::string selfExe();

}
