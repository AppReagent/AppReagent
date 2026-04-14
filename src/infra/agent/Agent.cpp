#include "infra/agent/Agent.h"

#include <stddef.h>
#include <algorithm>
#include <cctype>
#include <deque>
#include <exception>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <utility>

#include "infra/events/EventBus.h"
#include "infra/tools/ToolContext.h"
#include "util/file_io.h"
#include "util/string_util.h"
#include "infra/config/Config.h"
#include "infra/tools/Tool.h"

namespace area {
namespace {
std::string toLowerCopy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

bool containsAny(const std::string& haystack, std::initializer_list<const char*> needles) {
    for (const char* needle : needles) {
        if (haystack.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool looksLikeBinaryInvestigation(const std::string& userInput) {
    std::string lower = toLowerCopy(userInput);

    bool hasGhidraData = containsAny(lower, {"ghidra data", "ghidra:", "ghidra output"});
    bool hasBinaryPath = containsAny(lower, {".dll", ".exe", ".elf", ".so", ".bin", ".o"});
    bool hasBinaryQuestion = containsAny(lower, {
        "interesting functions",
        "suspicious strings",
        "entry point",
        "imports",
        "exports",
        "obfus",
        "xor",
        "network ioc",
        "host ioc",
        "dllmain",
        "malware"
    });

    return (hasGhidraData || hasBinaryPath) && hasBinaryQuestion;
}

std::vector<std::string> extractGhidraBinaryPaths(const std::string& userInput) {
    std::vector<std::string> paths;
    std::set<std::string> seen;
    std::istringstream stream(userInput);
    std::string line;
    const std::string prefix = "========== GHIDRA: ";
    const std::string suffix = " ==========";

    while (std::getline(stream, line)) {
        if (!line.starts_with(prefix) || !line.ends_with(suffix)) continue;
        std::string path = line.substr(prefix.size(), line.size() - prefix.size() - suffix.size());
        util::trimInPlace(path);
        if (!path.empty() && seen.insert(path).second) {
            paths.push_back(path);
        }
    }

    return paths;
}

std::optional<std::string> extractLineHexAddress(const std::string& userInput,
                                                 const std::string& marker) {
    std::istringstream stream(userInput);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.find(marker) == std::string::npos) continue;

        auto atPos = line.find('@');
        if (atPos != std::string::npos) {
            std::string tail = line.substr(atPos + 1);
            util::trimInPlace(tail);
            std::string value;
            for (char c : tail) {
                if (!std::isxdigit(static_cast<unsigned char>(c))) break;
                value += c;
            }
            if (!value.empty()) return "0x" + value;
        }

        for (size_t i = 0; i < line.size(); i++) {
            if (!std::isxdigit(static_cast<unsigned char>(line[i]))) continue;
            size_t j = i;
            while (j < line.size() && std::isxdigit(static_cast<unsigned char>(line[j]))) j++;
            if (j - i >= 8) return "0x" + line.substr(i, j - i);
            i = j;
        }
    }

    return std::nullopt;
}

std::optional<std::string> extractStringAddress(const std::string& userInput,
                                                const std::string& literal) {
    std::istringstream stream(userInput);
    std::string line;
    std::string needle = "\"" + literal + "\"";

    while (std::getline(stream, line)) {
        if (line.find(needle) == std::string::npos) continue;
        auto lbr = line.find('[');
        auto rbr = line.find(']', lbr == std::string::npos ? 0 : lbr + 1);
        if (lbr == std::string::npos || rbr == std::string::npos || rbr <= lbr + 1) continue;
        std::string addr = line.substr(lbr + 1, rbr - lbr - 1);
        util::trimInPlace(addr);
        if (!addr.empty()) return "0x" + addr;
    }

    return std::nullopt;
}

bool containsCaseInsensitive(const std::string& haystack, const std::string& needle) {
    return toLowerCopy(haystack).find(toLowerCopy(needle)) != std::string::npos;
}

struct AddressQuery {
    std::string value;
    bool dataHint = false;
};

std::string extractQuestionSection(const std::string& userInput) {
    std::string lower = toLowerCopy(userInput);
    size_t cut = std::string::npos;
    for (const std::string& marker : {
             "========================= ghidra data",
             "========== ghidra:",
             "ghidra data:"
         }) {
        auto pos = lower.find(marker);
        if (pos != std::string::npos) {
            cut = std::min(cut, pos);
        }
    }
    if (cut == std::string::npos) return userInput;
    return userInput.substr(0, cut);
}

std::vector<AddressQuery> extractQuestionAddresses(const std::string& userInput) {
    std::vector<AddressQuery> addrs;
    std::set<std::string> seen;
    std::string question = extractQuestionSection(userInput);
    std::string lower = toLowerCopy(question);
    std::regex pattern(R"((?:0x)?([0-9a-f]{8,16}))");

    for (std::sregex_iterator it(lower.begin(), lower.end(), pattern), end; it != end; ++it) {
        std::string addr = "0x" + (*it)[1].str();
        if (!seen.insert(addr).second) continue;

        size_t pos = static_cast<size_t>(it->position(0));
        size_t start = pos > 48 ? pos - 48 : 0;
        std::string context = lower.substr(start, pos - start);
        bool dataHint = containsAny(context, {
            "data at",
            "string at",
            "bytes at",
            "buffer at",
            "contents at"
        });

        addrs.push_back({addr, dataHint});
        if (addrs.size() >= 3) break;
    }

    return addrs;
}

void appendUniqueAction(std::deque<std::string>& queue,
                        std::set<std::string>& seen,
                        const std::string& action) {
    if (action.empty()) return;
    if (seen.insert(action).second) {
        queue.push_back(action);
    }
}

std::vector<std::string> extractDecompileTargets(const std::string& observation) {
    std::vector<std::string> addrs;
    std::set<std::string> seen;
    std::istringstream stream(observation);
    std::string line;

    while (std::getline(stream, line)) {
        auto atPos = line.find(" @ ");
        if (atPos == std::string::npos) continue;
        std::string tail = line.substr(atPos + 3);
        util::trimInPlace(tail);
        if (tail.starts_with("EXTERNAL:")) continue;

        std::string value;
        for (char c : tail) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) break;
            value += c;
        }
        if (value.size() < 8) continue;

        std::string addr = "0x" + value;
        if (seen.insert(addr).second) {
            addrs.push_back(addr);
        }
    }

    std::sort(addrs.begin(), addrs.end());
    return addrs;
}

int countParamsInSignature(const std::string& signature) {
    auto lpar = signature.find('(');
    auto rpar = signature.rfind(')');
    if (lpar == std::string::npos || rpar == std::string::npos || rpar <= lpar) return -1;

    std::string params = signature.substr(lpar + 1, rpar - lpar - 1);
    util::trimInPlace(params);
    if (params.empty() || params == "void") return 0;

    int count = 1;
    for (char c : params) {
        if (c == ',') count++;
    }
    return count;
}

int countLocalDeclarations(const std::vector<std::string>& lines) {
    bool inBody = false;
    int count = 0;

    for (const auto& rawLine : lines) {
        std::string line = rawLine;
        util::trimInPlace(line);
        if (line.empty()) continue;
        if (!inBody) {
            if (line == "{") inBody = true;
            continue;
        }
        if (!line.ends_with(";")) break;
        if (line.find('=') != std::string::npos) break;
        if (line.starts_with("if") || line.starts_with("for") || line.starts_with("do")
            || line.starts_with("while") || line.starts_with("return")) {
            break;
        }
        count++;
    }

    return count;
}

std::string summarizeGhidraObservation(const std::string& action,
                                       const std::string& observation) {
    std::istringstream stream(observation);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(stream, line)) lines.push_back(line);

    std::vector<std::string> notes;
    if (action.find("| xrefs |") != std::string::npos) {
        for (const auto& rawLine : lines) {
            std::string trimmed = rawLine;
            util::trimInPlace(trimmed);
            if (trimmed.starts_with("Import: ")
                || trimmed.starts_with("Function: ")
                || trimmed.starts_with("Data: ")) {
                notes.push_back(trimmed);
            } else if (trimmed.starts_with("Functions calling:")
                       || trimmed.starts_with("Type: ")
                       || trimmed.starts_with("Requested address:")) {
                notes.push_back(trimmed);
            } else if (trimmed.starts_with("Value: ")
                       || trimmed.starts_with("Offset from start:")) {
                notes.push_back(trimmed);
            } else if (trimmed.starts_with("callsites (")
                       || trimmed.starts_with("direct callees:")) {
                notes.push_back(trimmed);
            } else if (trimmed.find(" @ ") != std::string::npos
                       && trimmed.find(" - ") != std::string::npos) {
                notes.push_back("Function summary: " + trimmed);
            } else if (trimmed.starts_with("FUN_") || trimmed.starts_with("unknown @")) {
                notes.push_back("Callsite: " + trimmed);
                if (notes.size() >= 6) break;
            }
        }
    } else if (action.find("| decompile |") != std::string::npos) {
        std::string banner;
        std::string signature;
        for (const auto& rawLine : lines) {
            std::string trimmed = rawLine;
            util::trimInPlace(trimmed);
            if (trimmed.starts_with("--- ") && banner.empty()) {
                banner = trimmed;
            } else if (trimmed.ends_with(")") && signature.empty()) {
                signature = trimmed;
            }
        }
        if (!banner.empty()) notes.push_back(banner);
        if (!signature.empty()) {
            notes.push_back("Signature: " + signature);
            int params = countParamsInSignature(signature);
            if (params >= 0) {
                notes.push_back("Parameter count: " + std::to_string(params));
            }
        }

        int locals = countLocalDeclarations(lines);
        if (locals > 0) {
            notes.push_back("Local declaration count: " + std::to_string(locals));
        }

        for (const auto& rawLine : lines) {
            std::string trimmed = rawLine;
            util::trimInPlace(trimmed);
            if (trimmed.find("Sleep(") != std::string::npos
                || trimmed.find("GetSystemDefaultLangID(") != std::string::npos
                || trimmed.find("GetLastInputInfo(") != std::string::npos
                || trimmed.find("WinExec(") != std::string::npos
                || trimmed.find("socket(") != std::string::npos
                || trimmed.find("connect(") != std::string::npos
                || trimmed.find("CreateProcess") != std::string::npos) {
                notes.push_back("Key line: " + trimmed);
            }
        }
    } else if (action.find("| function_at |") != std::string::npos) {
        for (const auto& rawLine : lines) {
            std::string trimmed = rawLine;
            util::trimInPlace(trimmed);
            if (trimmed.starts_with("Requested address: ")
                || trimmed.starts_with("Function: ")
                || trimmed.starts_with("Signature: ")
                || trimmed.starts_with("Calling convention: ")
                || trimmed.starts_with("Size: ")
                || trimmed.starts_with("Offset from entry: ")
                || trimmed.starts_with("Callers: ")
                || trimmed.starts_with("Thunk: ")) {
                notes.push_back(trimmed);
            }
        }
    } else if (action.find("| data_at |") != std::string::npos) {
        for (const auto& rawLine : lines) {
            std::string trimmed = rawLine;
            util::trimInPlace(trimmed);
            if (trimmed.starts_with("Requested address: ")
                || trimmed.starts_with("Data: ")
                || trimmed.starts_with("Type: ")
                || trimmed.starts_with("Value: ")
                || trimmed.starts_with("Bytes: ")
                || trimmed.starts_with("ASCII: ")
                || trimmed.starts_with("Likely single-byte XOR decode: ")
                || trimmed.starts_with("Offset from start: ")
                || trimmed.starts_with("References: ")
                || trimmed.starts_with("Referenced by: ")) {
                notes.push_back(trimmed);
            }
        }
    } else if (action.find("| disasm |") != std::string::npos) {
        for (const auto& rawLine : lines) {
            std::string trimmed = rawLine;
            util::trimInPlace(trimmed);
            if (trimmed.starts_with("Function: ")
                || trimmed.starts_with("Requested address: ")
                || trimmed.starts_with("Offset from entry: ")
                || trimmed.starts_with("Instructions shown: ")) {
                notes.push_back(trimmed);
            } else if (trimmed.starts_with("=> ")) {
                notes.push_back("Target instruction: " + trimmed);
            }
        }
    }

    if (notes.empty()) return "";

    std::ostringstream out;
    out << "BOOTSTRAP EVIDENCE from " << action << ":\n";
    for (const auto& note : notes) {
        out << "- " << note << "\n";
    }
    return out.str();
}

std::string buildRuntimeGuidance(const std::string& userInput) {
    if (!looksLikeBinaryInvestigation(userInput)) return "";

    return
        "BINARY ANALYSIS WITH GHIDRA — this request is asking for malware triage from binary data.\n"
        "- Do not stop at prefetched overview/imports/strings if they are already present.\n"
        "- Pick 3-6 GHIDRA follow-up calls before answering.\n"
        "- Start from entry point, likely DllMain, exports, suspicious imports, and high-signal strings.\n"
        "- Use GHIDRA xrefs on imports, strings, symbols, and addresses to find wrapper "
        "functions that implement behavior.\n"
        "- Then use GHIDRA decompile on the most suspicious functions or exact addresses "
        "to read the real logic.\n"
        "- When a prompt or observation contains a hex address, call GHIDRA directly on "
        "that address instead of guessing names.\n"
        "- Prefer concrete evidence such as import callers, decompiled loops, decoded "
        "data, mutex names, filenames, registry keys, and network indicators.\n";
}
}  // namespace

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

void Agent::setEventBus(EventBus* bus, const std::string& chatId) {
    eventBus_ = bus;
    chatId_ = chatId;
}

void Agent::emitEvent(const AgentMessage& msg) {
    if (!eventBus_) return;

    EventType type;
    switch (msg.type) {
        case AgentMessage::THINKING:    type = EventType::AGENT_THOUGHT; break;
        case AgentMessage::ANSWER:      type = EventType::AGENT_ANSWER; break;
        case AgentMessage::SQL:         type = EventType::AGENT_MSG_SQL; break;
        case AgentMessage::RESULT:      type = EventType::AGENT_MSG_RESULT; break;
        case AgentMessage::ERROR:       type = EventType::AGENT_MSG_ERROR; break;
        case AgentMessage::TUI_CONTROL: type = EventType::AGENT_MSG_TUI_CONTROL; break;
        default: return;
    }

    eventBus_->emit({type, "agent", msg.content, chatId_});
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

    AgentMessage thinkMsg{AgentMessage::THINKING, "Compressing context..."};
    cb(thinkMsg);
    emitEvent(thinkMsg);

    std::string summary;
    try {
        summary = backend_->chat(compressPrompt, history_);
    } catch (const std::exception& e) {
        AgentMessage errMsg{AgentMessage::ERROR, std::string("Compression failed: ") + e.what()};
        cb(errMsg);
        emitEvent(errMsg);
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

std::string Agent::buildSystemPrompt(const std::string& userInput) const {
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

    std::string runtimeGuidance = buildRuntimeGuidance(userInput);
    if (!runtimeGuidance.empty()) {
        prompt += "\n\n" + runtimeGuidance;
    }

    return prompt;
}

void Agent::process(const std::string& userInput, MessageCallback cb,
                    ConfirmCallback confirm) {
    if (contextPercent() >= static_cast<int>((COMPRESS_THRESHOLD * 100))) {
        compressHistory(cb);
    }

    history_.push_back({"user", userInput});
    interrupted_.store(false);

    std::string systemPrompt = buildSystemPrompt(userInput);
    std::string bootstrapMemo;

    if (looksLikeBinaryInvestigation(userInput)) {
        auto paths = extractGhidraBinaryPaths(userInput);
        if (!paths.empty()) {
            const std::string& path = paths.front();
            std::deque<std::string> bootstrapActions;
            std::set<std::string> seenActions;

            for (const auto& addr : extractQuestionAddresses(userInput)) {
                if (addr.dataHint) {
                    appendUniqueAction(bootstrapActions, seenActions,
                                       "GHIDRA: " + path + " | data_at | " + addr.value);
                    appendUniqueAction(bootstrapActions, seenActions,
                                       "GHIDRA: " + path + " | xrefs | " + addr.value);
                } else {
                    appendUniqueAction(bootstrapActions, seenActions,
                                       "GHIDRA: " + path + " | function_at | " + addr.value);
                    appendUniqueAction(bootstrapActions, seenActions,
                                       "GHIDRA: " + path + " | decompile | " + addr.value);
                    appendUniqueAction(bootstrapActions, seenActions,
                                       "GHIDRA: " + path + " | disasm | " + addr.value);
                }
            }
            if (auto dllMain = extractLineHexAddress(userInput, "Likely DllMain:")) {
                appendUniqueAction(bootstrapActions, seenActions,
                                   "GHIDRA: " + path + " | decompile | " + *dllMain);
            }
            if (containsCaseInsensitive(userInput, "gethostbyname")) {
                appendUniqueAction(bootstrapActions, seenActions,
                                   "GHIDRA: " + path + " | xrefs | gethostbyname");
            }
            if (containsCaseInsensitive(userInput, "\"Sleep\"")
                || containsCaseInsensitive(userInput, " Sleep ")) {
                appendUniqueAction(bootstrapActions, seenActions,
                                   "GHIDRA: " + path + " | xrefs | Sleep");
            }
            if (containsCaseInsensitive(userInput, "GetSystemDefaultLangID")) {
                appendUniqueAction(bootstrapActions, seenActions,
                                   "GHIDRA: " + path + " | xrefs | GetSystemDefaultLangID");
            }
            if (containsCaseInsensitive(userInput, "GetLastInputInfo")) {
                appendUniqueAction(bootstrapActions, seenActions,
                                   "GHIDRA: " + path + " | xrefs | GetLastInputInfo");
            }
            if (auto addr = extractStringAddress(userInput, "cmd.exe")) {
                appendUniqueAction(bootstrapActions, seenActions,
                                   "GHIDRA: " + path + " | xrefs | " + *addr);
            }

            ToolContext toolCtx{cb, confirm, harness_};
            int bootstrapBudget = 8;
            std::vector<std::string> bootstrapSummaries;
            while (!bootstrapActions.empty() && bootstrapBudget-- > 0) {
                std::string action = bootstrapActions.front();
                bootstrapActions.pop_front();

                history_.push_back({"assistant",
                    "THOUGHT: I should gather concrete binary evidence before answering.\n" + action});

                auto toolResult = tools_.dispatch(action, toolCtx);
                if (!toolResult.has_value()) continue;

                history_.push_back({"user", toolResult->observation});
                std::string summary = summarizeGhidraObservation(action, toolResult->observation);
                if (!summary.empty()) {
                    bootstrapSummaries.push_back(summary);
                }

                if (action.find("| xrefs |") == std::string::npos) continue;

                auto targets = extractDecompileTargets(toolResult->observation);
                int followups = 0;
                for (const auto& target : targets) {
                    appendUniqueAction(bootstrapActions, seenActions,
                                       "GHIDRA: " + path + " | decompile | " + target);
                    appendUniqueAction(bootstrapActions, seenActions,
                                       "GHIDRA: " + path + " | disasm | " + target);
                    if (++followups >= 2) break;
                }
            }

            if (!bootstrapSummaries.empty()) {
                std::ostringstream memo;
                memo << "BOOTSTRAP SUMMARY — use these exact findings when relevant:\n";
                for (const auto& summary : bootstrapSummaries) {
                    memo << summary << "\n";
                }
                bootstrapMemo = memo.str();
                history_.push_back({"user", bootstrapMemo});
            }
        }
    }

    for (int iter = 0; iter < MAX_ITERATIONS; iter++) {
        if (interrupted_.load()) {
            AgentMessage msg{AgentMessage::ANSWER, "(interrupted)"};
            cb(msg);
            emitEvent(msg);
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
            AgentMessage msg{AgentMessage::ERROR, std::string("API error: ") + e.what()};
            cb(msg);
            emitEvent(msg);
            return;
        }

        if (interrupted_.load()) {
            history_.push_back({"assistant", rawResponse});
            AgentMessage msg{AgentMessage::ANSWER, "(interrupted)"};
            cb(msg);
            emitEvent(msg);
            return;
        }

        std::string thought;
        std::string action = extractThought(rawResponse, thought);

        if (!thought.empty()) {
            AgentMessage msg{AgentMessage::THINKING, thought};
            cb(msg);
            emitEvent(msg);
        }

        if (action.empty()) action = rawResponse;

        if (action.starts_with("ANSWER:")) {
            std::string answer = action.substr(7);
            util::ltrimInPlace(answer);

            if (!bootstrapMemo.empty() && iter < MAX_ITERATIONS - 1) {
                std::string lowerAnswer = toLowerCopy(answer);
                bool citesImportAddr = answer.find("EXTERNAL:") != std::string::npos;
                bool citesCallCounts = lowerAnswer.find("functions calling") != std::string::npos
                    || lowerAnswer.find("call sites") != std::string::npos;
                bool citesParamCount = lowerAnswer.find("parameter count") != std::string::npos
                    || lowerAnswer.find("0 parameter") != std::string::npos
                    || lowerAnswer.find("1 parameter") != std::string::npos;
                bool citesKeyLine = lowerAnswer.find("sleep(") != std::string::npos
                    || lowerAnswer.find("getsystemdefaultlangid") != std::string::npos
                    || lowerAnswer.find("winexec(") != std::string::npos;
                if (!citesImportAddr || !citesCallCounts || !citesParamCount || !citesKeyLine) {
                    history_.push_back({"assistant", rawResponse});
                    history_.push_back({"user",
                        "SYSTEM: Revise the answer and explicitly cite the exact bootstrap "
                        "evidence already gathered, including import addresses, xref counts, "
                        "parameter counts, and key decompiled lines when relevant.\n\n"
                        + bootstrapMemo});
                    continue;
                }
            }

            std::string sensorFeedback = harness_.runSensors("answer", answer, "");
            if (!sensorFeedback.empty() && iter < MAX_ITERATIONS - 1) {
                history_.push_back({"assistant", rawResponse});
                history_.push_back({"user", "SENSOR FEEDBACK on your answer:\n" + sensorFeedback +
                    "\nPlease reconsider and provide a more complete answer."});
                continue;
            }

            history_.push_back({"assistant", rawResponse});
            AgentMessage msg{AgentMessage::ANSWER, answer};
            cb(msg);
            emitEvent(msg);
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
        AgentMessage msg{AgentMessage::ANSWER, action};
        cb(msg);
        emitEvent(msg);
        return;
    }

    AgentMessage msg{AgentMessage::ANSWER, "(max iterations reached)"};
    cb(msg);
    emitEvent(msg);
}
}  // namespace area
