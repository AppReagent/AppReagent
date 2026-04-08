#pragma once

#include <cmath>
#include <string>
#include "infra/agent/Agent.h"

namespace area::tui {

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
