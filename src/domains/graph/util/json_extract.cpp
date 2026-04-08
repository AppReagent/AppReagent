#include "domains/graph/util/json_extract.h"

#include <stddef.h>

namespace area::graph {

std::string extractJson(const std::string& text) {
    auto start = text.find("```json");
    if (start != std::string::npos) {
        auto nl = text.find('\n', start);
        if (nl != std::string::npos) {
            start = nl + 1;
            auto end = text.find("```", start);
            if (end != std::string::npos) return text.substr(start, end - start);
        }
    }
    start = text.find("```");
    if (start != std::string::npos) {
        auto nl = text.find('\n', start);
        if (nl != std::string::npos) {
            start = nl + 1;
            auto end = text.find("```", start);
            if (end != std::string::npos) return text.substr(start, end - start);
        }
    }
    start = text.find('{');
    if (start != std::string::npos) {
        int depth = 0;
        for (size_t i = start; i < text.size(); i++) {
            if (text[i] == '{') {
                depth++;
            } else if (text[i] == '}') {
                depth--;
                if (depth == 0) {
                    return text.substr(start, i - start + 1);
                }
            }
        }
    }
    return text;
}

}  // namespace area::graph
