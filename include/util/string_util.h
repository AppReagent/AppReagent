#pragma once

#include <string>

namespace area::util {

inline std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\n')) start++;
    size_t end = s.size();
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\n')) end--;
    return s.substr(start, end - start);
}

inline void trimInPlace(std::string& s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    while (!s.empty() && (s[0] == '\n' || s[0] == ' ')) s.erase(0, 1);
}

inline void ltrimInPlace(std::string& s) {
    while (!s.empty() && (s[0] == ' ' || s[0] == '\n')) s.erase(0, 1);
}

inline void rtrimInPlace(std::string& s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\n')) s.pop_back();
}

} // namespace area::util
