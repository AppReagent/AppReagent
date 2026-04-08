#pragma once

#include <string>

namespace area::util {

std::string escapeNewlines(const std::string& s);
std::string unescapeNewlines(const std::string& s);

}
