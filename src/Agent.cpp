#include "Agent.h"
#include "tools/ToolContext.h"
#include "util/file_io.h"
#include "util/string_util.h"

#include <sstream>

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
        chars += (int)m.content.size();
    }
    chars += (int)systemContext_.size();
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
    history_.push_back({"assistant", "THOUGHT: I have the context from our conversation.\nANSWER: Understood. How can I help you next?"});
}

std::string Agent::buildSystemPrompt() const {
    std::string prompt =
        "You are AppReagent, an expert Android and Linux application reverse engineering agent. "
        "You help users understand, analyze, and investigate applications at the code level — "
        "finding behaviors, tracing data flows, identifying security issues, and answering any "
        "question about app internals.\n\n"

        "When a user asks about an app, follow this workflow:\n"
        "1. SEARCH — Use GREP to find relevant code patterns (API calls, classes, strings)\n"
        "2. READ — Use READ to examine the actual source code in context\n"
        "3. CROSS-REFERENCE — Use XREFS to trace how components connect across the app\n"
        "4. EXTRACT — Use STRINGS to find hardcoded data (URLs, keys, IPs, commands)\n"
        "5. METADATA — Use MANIFEST to check permissions and declared components\n"
        "6. DEEP ANALYZE — Use SCAN for LLM-powered behavioral analysis of entire files/directories\n"
        "7. QUERY — Use FIND, SIMILAR, SQL to search previous scan results\n\n"

        "Android reverse engineering patterns — use these with GREP:\n"
        "- Network: HttpURLConnection, OkHttp, Retrofit, Socket, URL, WebView->loadUrl, Volley\n"
        "- Crypto: javax/crypto/Cipher, SecretKeySpec, MessageDigest, KeyGenerator, Mac\n"
        "- File I/O: FileInputStream, FileOutputStream, SharedPreferences, SQLiteDatabase\n"
        "- SMS/Phone: SmsManager, TelephonyManager, ContentResolver with sms or contacts URI\n"
        "- Location: LocationManager, FusedLocationProviderClient, Geocoder\n"
        "- Reflection: Class;->forName, Method;->invoke, DexClassLoader, PathClassLoader\n"
        "- Native: System;->loadLibrary, native method declarations, JNI\n"
        "- Obfuscation: encrypted strings, reflection-based calls, dynamic class loading, base64\n"
        "- IPC: Intent, BroadcastReceiver, ContentProvider, Binder, Messenger\n"
        "- Device info: Build;->MODEL, TelephonyManager;->getDeviceId, Settings$Secure\n\n"

        "In smali bytecode:\n"
        "- Method calls: invoke-virtual, invoke-static, invoke-direct, invoke-interface\n"
        "- Field access: iget/iput, sget/sput (with -object, -wide, -boolean, etc.)\n"
        "- Strings: const-string, const-string/jumbo\n"
        "- Types: new-instance, const-class, check-cast, instance-of\n"
        "- Methods: .method ... .end method blocks\n\n";

    if (!systemContext_.empty()) {
        prompt += systemContext_ + "\n\n";
    }

    prompt += tools_.describeAll();
    prompt += "\nAlways use absolute paths. Expand ~ to the user's home directory.\n";
    prompt += "If the user refers to code without a path, use FIND_FILES to locate it first.\n\n";

    std::string guides = harness_.guideText();
    if (!guides.empty()) {
        prompt += guides;
    }

    return prompt;
}

void Agent::process(const std::string& userInput, MessageCallback cb,
                    ConfirmCallback confirm) {
    if (contextPercent() >= (int)(COMPRESS_THRESHOLD * 100)) {
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

        if (action.find("ANSWER:") == 0) {
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
            history_.push_back({"user", toolResult->observation});
            continue;
        }

        history_.push_back({"assistant", rawResponse});
        cb({AgentMessage::ANSWER, action});
        return;
    }

    cb({AgentMessage::ANSWER, "(max iterations reached)"});
}

} // namespace area
