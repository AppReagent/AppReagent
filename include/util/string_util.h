#pragma once

#include <string>

namespace area::util {

std::string trim(const std::string& s);
void trimInPlace(std::string& s);
void ltrimInPlace(std::string& s);
void rtrimInPlace(std::string& s);

std::string shellEscape(const std::string& s);

std::string shellQuote(const std::string& s);

std::string truncateUTF8(const std::string& s, int maxBytes);

}  // namespace area::util
