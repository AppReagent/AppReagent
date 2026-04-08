#include "infra/agent/Agent.h"

#include <stddef.h>
#include <algorithm>
#include <cctype>
#include <exception>
#include <optional>
#include <utility>

#include "infra/tools/ToolContext.h"
#include "util/file_io.h"
#include "util/string_util.h"
#include "infra/config/Config.h"
#include "infra/tools/Tool.h"

namespace area {
Agent::Agent(std::unique_ptr<LLMBackend> backend, ToolRegistry& tools, Harness harness)
    : ownedBackend_(std::move(backend)), backend_(ownedBackend_.get()),
      tools_(tools), harness_(std::move(harness)) {
    backend_->setCancelFlag(&interrupted_);
}

Agent::Agent(LLMBackend* sharedBackend, ToolRegistry& tools, Harness harness)
    : backend_(sharedBackend), tools_(tools), harness_(std::move(harness)) {
    backend_->setCancelFlag(&interrupted_);
}

void Agent::interrupt() {
    interrupted_.store(true);
}

void Agent::clearHistory() {
    history_.clear();
}

std::string Agent::extractThought(const std::string& response, std::string& thought) {
    thought.clear();

    auto tPos = response.find("THOUGHT:");
    if (tPos == std::string::npos) return response;

    std::vector<std::string> actionPrefixes = {"ACTION:", "ANSWER:"};
    for (auto& p : tools_.prefixes()) {
        actionPrefixes.push_back(p);
    }

    std::string afterThought = response.substr(tPos + 8);
    size_t actionStart = std::string::npos;
    for (auto& prefix : actionPrefixes) {
        auto pos = afterThought.find(prefix);
        if (pos != std::string::npos && pos < actionStart) {
            actionStart = pos;
        }
    }

    if (actionStart != std::string::npos) {
        thought = afterThought.substr(0, actionStart);
        util::trimInPlace(thought);

        std::string action = afterThought.substr(actionStart);
        if (action.starts_with("ACTION:")) {
            action = action.substr(7);
            util::ltrimInPlace(action);
        }
        return action;
    }

    thought = afterThought;
    util::trimInPlace(thought);
    return "";
}

int Agent::estimateTokens() const {
    int chars = 0;
    for (auto& m : history_) {
        chars += static_cast<int>(m.content.size());
    }
    chars += static_cast<int>(systemContext_.size());
    return chars / 4;
}

int Agent::contextPercent() const {
    int window = backend_->endpoint().context_window;
    if (window <= 0) return 0;
    int tokens = estimateTokens();
    int pct = (tokens * 100) / window;
    return std::min(pct, 100);
}

void Agent::compressHistory(MessageCallback cb) {
    if (history_.size() <= 2) return;

    std::string compressPrompt = util::readFile("prompts/compress.prompt");
    if (compressPrompt.empty()) {
        compressPrompt =
            "Summarize this conversation concisely. Preserve key facts, "
            "schema details, and the user's current line of inquiry. "
            "Discard raw query results and failed attempts.";
    }

    cb({AgentMessage::THINKING, "Compressing context..."});

    std::string summary;
    try {
        summary = backend_->chat(compressPrompt, history_);
    } catch (const std::exception& e) {
        cb({AgentMessage::ERROR, std::string("Compression failed: ") + e.what()});
        return;
    }

    history_.clear();
    history_.push_back({"user", "Here is a summary of our conversation so far:\n\n" + summary});
    history_.push_back({"assistant",
        "THOUGHT: I have the context from our conversation.\n"
        "ANSWER: Understood. How can I help you next?"});
}

static std::string templateReplace(const std::string& s, const std::string& key, const std::string& val) {
    std::string result = s;
    std::string placeholder = "{{" + key + "}}";
    size_t pos = result.find(placeholder);
    if (pos != std::string::npos) {
        result.replace(pos, placeholder.size(), val);
    }
    return result;
}

std::string Agent::buildSystemPrompt() const {
    std::string prompt;
    if (!promptsDir_.empty()) {
        try {
            prompt = util::readFileOrThrow(promptsDir_ + "/agent_system.prompt"); } catch (...) {
        }
    }
    if (prompt.empty()) {
        prompt = util::readFile("prompts/agent_system.prompt");
    }
    if (prompt.empty()) {
        prompt = "You are AppReagent, a reverse engineering agent.\n\n"
                 "{{system_context}}\n\n{{tools}}\n\n{{guides}}\n";
    }

    prompt = templateReplace(prompt, "tools", tools_.describeAll());
    prompt = templateReplace(prompt, "system_context", systemContext_);
    prompt = templateReplace(prompt, "guides", harness_.guideText());

    return prompt;
}

void Agent::process(const std::string& userInput, MessageCallback cb,
                    ConfirmCallback confirm) {
    if (contextPercent() >= static_cast<int>((COMPRESS_THRESHOLD * 100))) {
        compressHistory(cb);
    }

    history_.push_back({"user", userInput});
    interrupted_.store(false);

    std::string systemPrompt = buildSystemPrompt();

    for (int iter = 0; iter < MAX_ITERATIONS; iter++) {
        if (interrupted_.load()) {
            cb({AgentMessage::ANSWER, "(interrupted)"});
            return;
        }

        if (iter > 0 && contextPercent() >= static_cast<int>((COMPRESS_THRESHOLD * 100))) {
            compressHistory(cb);
        }

        if (iter == ITERATION_WARNING) {
            history_.push_back({"user",
                "SYSTEM: You have used " + std::to_string(iter) + " of " +
                std::to_string(MAX_ITERATIONS) + " iterations. "
                "Wrap up your investigation and provide an ANSWER with the evidence gathered so far. "
                "If you need more analysis, recommend specific follow-up steps the user can request."});
        }

        std::string rawResponse;
        try {
            rawResponse = backend_->chat(systemPrompt, history_);
        } catch (const std::exception& e) {
            cb({AgentMessage::ERROR, std::string("API error: ") + e.what()});
            return;
        }

        if (interrupted_.load()) {
            history_.push_back({"assistant", rawResponse});
            cb({AgentMessage::ANSWER, "(interrupted)"});
            return;
        }

        std::string thought;
        std::string action = extractThought(rawResponse, thought);

        if (!thought.empty()) {
            cb({AgentMessage::THINKING, thought});
        }

        if (action.empty()) action = rawResponse;

        if (action.starts_with("ANSWER:")) {
            std::string answer = action.substr(7);
            util::ltrimInPlace(answer);

            std::string sensorFeedback = harness_.runSensors("answer", answer, "");
            if (!sensorFeedback.empty() && iter < MAX_ITERATIONS - 1) {
                history_.push_back({"assistant", rawResponse});
                history_.push_back({"user", "SENSOR FEEDBACK on your answer:\n" + sensorFeedback +
                    "\nPlease reconsider and provide a more complete answer."});
                continue;
            }

            history_.push_back({"assistant", rawResponse});
            cb({AgentMessage::ANSWER, answer});
            return;
        }

        ToolContext toolCtx{cb, confirm, harness_};
        auto toolResult = tools_.dispatch(action, toolCtx);

        if (toolResult.has_value()) {
            history_.push_back({"assistant", rawResponse});

            std::string toolName;
            for (auto& prefix : tools_.prefixes()) {
                if (action.starts_with(prefix)) {
                    toolName = prefix;

                    if (!toolName.empty() && toolName.back() == ':')
                        toolName.pop_back();

                    for (auto& c : toolName)
                        c = std::tolower(static_cast<unsigned char>(c));
                    break;
                }
            }
            if (!toolName.empty()) {
                std::string sensorFeedback = harness_.runSensors(
                    toolName, action, toolResult->observation);
                if (!sensorFeedback.empty()) {
                    history_.push_back({"user", toolResult->observation +
                        "\n\nSENSOR FEEDBACK:\n" + sensorFeedback});
                    continue;
                }
            }

            history_.push_back({"user", toolResult->observation});
            continue;
        }

        history_.push_back({"assistant", rawResponse});
        cb({AgentMessage::ANSWER, action});
        return;
    }

    cb({AgentMessage::ANSWER, "(max iterations reached)"});
}
}  // namespace area
