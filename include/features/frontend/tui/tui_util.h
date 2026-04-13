#pragma once

#include <cmath>
#include <string>
#include <vector>
#include "infra/agent/Agent.h"

namespace area::tui {

/// A styled span within a markdown line.
struct MarkdownSpan {
    enum Style { NORMAL, BOLD, CODE };
    Style style;
    std::string text;
};

/// Parse inline markdown (** and `) into styled spans.
inline std::vector<MarkdownSpan> parseMarkdownSpans(const std::string& text) {
    std::vector<MarkdownSpan> spans;
    size_t i = 0;
    bool inBold = false;
    bool inCode = false;
    std::string current;

    auto flush = [&](MarkdownSpan::Style style) {
        if (!current.empty()) {
            spans.push_back({style, current});
            current.clear();
        }
    };

    while (i < text.size()) {
        if (!inCode && i + 1 < text.size() && text[i] == '*' && text[i + 1] == '*') {
            auto prevStyle = inBold ? MarkdownSpan::BOLD : MarkdownSpan::NORMAL;
            flush(prevStyle);
            inBold = !inBold;
            i += 2;
            continue;
        }
        if (!inBold && text[i] == '`') {
            auto prevStyle = inCode ? MarkdownSpan::CODE : MarkdownSpan::NORMAL;
            flush(prevStyle);
            inCode = !inCode;
            i++;
            continue;
        }
        current += text[i];
        i++;
    }
    // Flush remaining
    auto finalStyle = inBold ? MarkdownSpan::BOLD : inCode ? MarkdownSpan::CODE : MarkdownSpan::NORMAL;
    flush(finalStyle);
    return spans;
}

inline double flowNoise(double x, double t) {
    return std::sin(x * 0.3 + t * 0.007) * 0.5
         + std::sin(x * 0.5 + t * 0.012 + 2.1) * 0.3
         + std::sin(x * 0.9 + t * 0.018 + 4.7) * 0.2;
}

inline double noise2d(double x, double y, double t) {
    return (std::sin(x * 0.3 + t * 0.15 + y * 0.2) * 0.5
          + std::sin(x * 0.7 + t * 0.23 + y * 0.5 + 2.1) * 0.3
          + std::sin(x * 1.1 + t * 0.31 + y * 0.8 + 4.7) * 0.2
          + 1.0) * 0.5;
}

inline AgentMessage::Type parseAgentType(const std::string& t) {
    if (t == "thinking") return AgentMessage::THINKING;
    if (t == "sql")      return AgentMessage::SQL;
    if (t == "result")   return AgentMessage::RESULT;
    if (t == "answer")   return AgentMessage::ANSWER;
    if (t == "error")    return AgentMessage::ERROR;
    return AgentMessage::ANSWER;
}

}  // namespace area::tui
