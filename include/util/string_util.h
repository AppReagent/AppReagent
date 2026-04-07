#pragma once

#include <string>

namespace area::util {

std::string trim(const std::string& s);
void trimInPlace(std::string& s);
void ltrimInPlace(std::string& s);
void rtrimInPlace(std::string& s);

/// Escape single quotes for safe use inside a single-quoted shell argument.
std::string shellEscape(const std::string& s);

/// Return a fully single-quoted shell argument.
std::string shellQuote(const std::string& s);

/// Truncate to at most maxBytes without splitting a multi-byte UTF-8 character.
std::string truncateUTF8(const std::string& s, int maxBytes);

} // namespace area::util
