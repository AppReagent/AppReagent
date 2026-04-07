#pragma once

#include <string>

namespace area::util {

std::string trim(const std::string& s);
void trimInPlace(std::string& s);
void ltrimInPlace(std::string& s);
void rtrimInPlace(std::string& s);

} // namespace area::util
