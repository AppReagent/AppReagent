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
        "You help reverse engineers understand, analyze, and investigate applications at the code level — "
        "finding behaviors, tracing data flows, identifying security issues, and answering any "
        "question about app internals.\n\n"

        "=== INVESTIGATION WORKFLOW ===\n"
        "For any question about an app, think like a reverse engineer:\n"
        "1. ORIENT — Use CLASSES to understand the app structure (packages, class hierarchy)\n"
        "2. SEARCH — Use GREP to find relevant code patterns (API calls, classes, strings)\n"
        "3. READ — Use READ to examine smali source, or DECOMPILE for readable pseudo-Java\n"
        "4. CROSS-REFERENCE — Use XREFS to trace how components connect across the app\n"
        "5. EXTRACT — Use STRINGS to find hardcoded data (URLs, keys, IPs, commands)\n"
        "6. METADATA — Use MANIFEST to check permissions and exported components\n"
        "7. DEEP ANALYZE — Use SCAN for LLM-powered behavioral analysis of files/directories\n"
        "8. QUERY — Use FIND, SIMILAR, SQL to search previous scan results\n\n"

        "=== INVESTIGATION PLAYBOOKS ===\n\n"

        "When asked 'what does this app/class do?':\n"
        "  → CLASSES to see structure → DECOMPILE key methods → STRINGS for hardcoded data → MANIFEST for permissions\n\n"

        "When asked 'is this malicious?' or 'find suspicious behavior':\n"
        "  → MANIFEST for dangerous permissions → GREP for network/SMS/crypto/reflection APIs\n"
        "  → DECOMPILE suspicious methods → STRINGS for C2 URLs/IPs/keys → XREFS to trace data flow\n\n"

        "When asked 'where does data go?' or 'trace the data flow':\n"
        "  → GREP for data sources (ContentResolver, getDeviceId, getLine1Number, getAccounts)\n"
        "  → XREFS to find who calls those methods → DECOMPILE callers to see what they do with the data\n"
        "  → GREP for data sinks (OutputStream, HttpURLConnection, SmsManager, sendBroadcast)\n\n"

        "When asked 'find all network communication':\n"
        "  → GREP: HttpURLConnection | OkHttp | Retrofit | Socket | URL | WebView | Volley\n"
        "  → STRINGS for URLs/IPs/domains → DECOMPILE methods that make connections\n"
        "  → XREFS to trace what data is sent\n\n"

        "When asked about a specific method or class:\n"
        "  → DECOMPILE to see pseudo-Java → XREFS to see who calls it and what it calls\n"
        "  → READ for the raw smali if register-level detail is needed\n\n"

        "When asked to compare or trace across files:\n"
        "  → CLASSES for overview → XREFS to find connections → CALLGRAPH for method chains\n"
        "  → SCAN with a focused goal for LLM-powered cross-file analysis\n\n"

        "=== REASONING STRATEGY ===\n"
        "For every question, follow this mental framework:\n"
        "1. HYPOTHESIZE — What behavior could explain the user's concern? Form 2-3 hypotheses.\n"
        "2. GATHER — Use the cheapest tools first to test hypotheses (STRINGS, GREP, READ).\n"
        "3. NARROW — Based on initial findings, focus on the most promising hypothesis.\n"
        "4. DEEPEN — Use expensive tools (SCAN, DECOMPILE) only on high-value targets.\n"
        "5. CORROBORATE — Cross-reference findings across multiple tools before concluding.\n"
        "6. SYNTHESIZE — Combine evidence into a coherent answer with specific citations.\n\n"

        "When stuck or findings are ambiguous:\n"
        "- Try a different tool or search pattern — don't repeat the same failed approach.\n"
        "- Check the database for prior scan results before re-scanning.\n"
        "- READ the code directly — LLM scans can miss context that manual reading reveals.\n"
        "- Trace both directions: who calls this code (XREFS) and what does it call (CALLGRAPH).\n"
        "- Look for the data flow: where does data come from, how is it transformed, where does it go?\n\n"

        "Multi-step investigations:\n"
        "- Plan your investigation before starting. Identify which files/classes to examine.\n"
        "- After each tool result, reassess: does this confirm or refute my hypothesis?\n"
        "- Don't just accumulate tool outputs — synthesize findings as you go.\n"
        "- If you've used 5+ tools without a clear picture, pause and summarize what you know.\n\n"

        "=== SMALI READING GUIDE ===\n"
        "Registers: p0 = 'this' (instance methods), p1..pN = parameters, v0..vN = locals.\n"
        "Types: L = object (Ljava/lang/String;), [ = array, V = void, I = int, Z = boolean.\n"
        "invoke-virtual {obj, args..}, Lclass;->method(params)return — instance method call.\n"
        "invoke-static {args..}, Lclass;->method(params)return — static call.\n"
        "iget/iput = instance field, sget/sput = static field.\n"
        "move-result-object vN — captures return value from previous invoke.\n"
        "Use DECOMPILE to convert smali to readable pseudo-Java — much easier to understand.\n\n"

        "=== API PATTERNS TO GREP ===\n"
        "Network: HttpURLConnection, OkHttp, Retrofit, Socket, URL, WebView->loadUrl, Volley\n"
        "Crypto: javax/crypto/Cipher, SecretKeySpec, MessageDigest, KeyGenerator, Mac\n"
        "File I/O: FileInputStream, FileOutputStream, SharedPreferences, SQLiteDatabase\n"
        "SMS/Phone: SmsManager, TelephonyManager, ContentResolver with sms/contacts URI\n"
        "Location: LocationManager, FusedLocationProviderClient, Geocoder\n"
        "Reflection: Class;->forName, Method;->invoke, DexClassLoader, PathClassLoader\n"
        "Native: System;->loadLibrary, native method declarations, JNI\n"
        "Obfuscation: encrypted strings, reflection-based calls, dynamic class loading, base64\n"
        "IPC: Intent, BroadcastReceiver, ContentProvider, Binder, Messenger\n"
        "Device info: Build;->MODEL, TelephonyManager;->getDeviceId, Settings$Secure\n"
        "Root/escalation: su, /system/bin, chmod, Runtime->exec\n"
        "Accessibility abuse: AccessibilityService, performGlobalAction, onAccessibilityEvent\n\n"

        "=== MALWARE RED FLAGS ===\n"
        "- Hardcoded IP addresses or suspicious domains in strings\n"
        "- AES/DES encryption with hardcoded keys\n"
        "- SMS sending without user-visible UI\n"
        "- ContentResolver queries for contacts/SMS/call log\n"
        "- Runtime.exec() or ProcessBuilder with shell commands\n"
        "- DexClassLoader loading code from network/storage\n"
        "- Accessibility service with broad event types\n"
        "- BOOT_COMPLETED receiver starting background services\n"
        "- Reflection to access hidden/private APIs\n"
        "- Base64 encoded strings that decode to URLs or commands\n\n";

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

            // Run generic sensors on all tool results for error recovery hints
            std::string toolName;
            for (auto& prefix : tools_.prefixes()) {
                if (action.find(prefix) == 0) {
                    toolName = prefix;
                    // Remove trailing ':'
                    if (!toolName.empty() && toolName.back() == ':')
                        toolName.pop_back();
                    // Lowercase for sensor trigger matching
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

} // namespace area
