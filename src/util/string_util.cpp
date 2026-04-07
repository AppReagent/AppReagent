#include "util/string_util.h"

namespace area::util {

std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\n')) start++;
    size_t end = s.size();
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\n')) end--;
    return s.substr(start, end - start);
}

void trimInPlace(std::string& s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    auto pos = s.find_first_not_of(" \n");
    if (pos == std::string::npos) s.clear();
    else if (pos > 0) s.erase(0, pos);
}

void ltrimInPlace(std::string& s) {
    auto pos = s.find_first_not_of(" \n");
    if (pos == std::string::npos) s.clear();
    else if (pos > 0) s.erase(0, pos);
}

void rtrimInPlace(std::string& s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\n')) s.pop_back();
}

std::string shellEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\'') out += "'\\''";
        else out += c;
    }
    return out;
}

std::string shellQuote(const std::string& s) {
    return "'" + shellEscape(s) + "'";
}

} // namespace area::util
