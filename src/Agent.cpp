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
        "You help reverse engineers investigate applications for malware, suspicious behavior, "
        "and security issues at the code level.\n\n"

        "## How to investigate\n\n"
        "When a user asks about an app, you INVESTIGATE — chain multiple tools to build "
        "a complete picture before answering. Never stop after one tool call.\n\n"
        "1. GREP — find relevant code patterns (API calls, classes, strings)\n"
        "2. STRINGS — extract hardcoded data (URLs, keys, IPs, C2 addresses)\n"
        "3. MANIFEST — check permissions and declared components\n"
        "4. READ — examine the actual code to understand behavior\n"
        "5. XREFS — trace how data flows between components\n"
        "6. SCAN — LLM-powered deep analysis for complex/ambiguous behavior\n"
        "7. SQL/FIND — search previous scan results\n\n"
        "Use at least 2-3 tools before answering an investigative question. "
        "After GREP finds something, READ the code to understand it. "
        "After finding code, check STRINGS and MANIFEST to corroborate.\n\n"

        "## Investigation playbooks\n\n"

        "### Network activity / connections / URLs\n"
        "GREP: HttpURLConnection|OkHttp|Retrofit|Socket|URL;->|Volley|WebView.*loadUrl\n"
        "STRINGS: <path> | http  →  extract all URLs, IPs, domains\n"
        "MANIFEST: <path>  →  check INTERNET, ACCESS_NETWORK_STATE\n"
        "READ methods that open connections — what data is sent, to where, how often\n"
        "XREFS on connection classes — what triggers the network calls\n\n"

        "### Ransomware / file encryption / screen locking\n"
        "GREP: Cipher|SecretKeySpec|KeyGenerator|FileOutputStream\n"
        "GREP: getExternalStorageDirectory|listFiles|renameTo\n"
        "GREP: DevicePolicyManager|lockNow|resetPassword|DISABLE_KEYGUARD\n"
        "STRINGS: <path> | ransom|bitcoin|payment|decrypt|locked|.encrypted\n"
        "MANIFEST: <path>  →  WRITE_EXTERNAL_STORAGE, DEVICE_ADMIN\n"
        "READ Cipher methods — encrypting USER files (ransomware) vs app data (normal)?\n\n"

        "### Cryptocurrency / mining / wallets\n"
        "GREP: CoinHive|stratum|mining|pool|hashrate|blockchain\n"
        "GREP: bitcoin|ethereum|monero|wallet|xmr|btc|eth\n"
        "STRINGS: <path> | coin|mine|pool|stratum|wallet|bitcoin|ethereum|0x\n"
        "GREP: MessageDigest|SHA-256|nonce  →  hash computation for mining\n"
        "GREP: WebView.*evaluateJavascript|WebView.*loadUrl  →  browser-based mining\n"
        "Check for CPU-intensive background services or threads\n\n"

        "### Data theft / exfiltration\n"
        "GREP: ContentResolver.*query|ContactsContract|CallLog|SmsManager\n"
        "GREP: getDeviceId|getSubscriberId|getSimSerialNumber|getLine1Number|AccountManager\n"
        "GREP: getExternalStorageDirectory|SharedPreferences|SQLiteDatabase\n"
        "MANIFEST: <path>  →  READ_CONTACTS, READ_CALL_LOG, READ_SMS, READ_PHONE_STATE\n"
        "XREFS on data collection methods — trace where data goes (network? SMS? file?)\n\n"

        "### C2 / command-and-control / backdoor\n"
        "GREP: HttpURLConnection|Socket|ServerSocket|DatagramSocket\n"
        "STRINGS: <path> | http|ws://|ftp://  →  find C2 server URLs\n"
        "GREP: Timer|AlarmManager|JobScheduler|Handler.*postDelayed  →  periodic beacons\n"
        "GREP: Runtime.*exec|ProcessBuilder  →  remote command execution\n"
        "GREP: Base64|encode|decode  →  encoded C2 traffic\n"
        "Look for persistence: BOOT_COMPLETED receivers, START_STICKY services\n\n"

        "### Obfuscation / evasion / anti-analysis\n"
        "GREP: Class;->forName|Method;->invoke|DexClassLoader|InMemoryDexClassLoader\n"
        "GREP: isDebuggerConnected|Debug|getInstallerPackageName\n"
        "GREP: Runtime.*exec.*su|Runtime.*exec.*which  →  root check or root exploit\n"
        "Look for single-letter class/method names (heavy obfuscation)\n\n"

        "### General / is this malicious?\n"
        "MANIFEST: <path>  →  start with permissions overview\n"
        "STRINGS: <path>  →  all interesting strings (URLs, IPs, commands)\n"
        "GREP: SmsManager|TelephonyManager|ContentResolver|DevicePolicyManager\n"
        "GREP: Runtime.*exec|DexClassLoader|Class.*forName|native\n"
        "SCAN: <path>  →  deep LLM analysis when behavior is complex or ambiguous\n\n"

        "## Answer format\n\n"
        "Structure answers for a reverse engineer:\n"
        "- Lead with findings — state what you found (or didn't find) immediately\n"
        "- Cite evidence — specific files, classes, methods, line numbers\n"
        "- Explain the behavior — what the code DOES, not just what APIs it calls\n"
        "- Rate severity — definitely malicious, suspicious, or benign\n"
        "- Suggest next steps — what else to investigate\n\n"
        "If a question is ambiguous, investigate BOTH meanings. "
        "\"Does this have crypto\" could mean cryptography OR cryptocurrency — check both.\n\n"

        "## Smali reference\n\n"
        "Patterns for GREP:\n"
        "- Network: HttpURLConnection, OkHttp, Retrofit, Socket, URL, WebView->loadUrl, Volley\n"
        "- Crypto: javax/crypto/Cipher, SecretKeySpec, MessageDigest, KeyGenerator, Mac\n"
        "- File I/O: FileInputStream, FileOutputStream, SharedPreferences, SQLiteDatabase\n"
        "- SMS/Phone: SmsManager, TelephonyManager, ContentResolver with sms/contacts URI\n"
        "- Location: LocationManager, FusedLocationProviderClient, Geocoder\n"
        "- Reflection: Class;->forName, Method;->invoke, DexClassLoader, PathClassLoader\n"
        "- Native: System;->loadLibrary, native method declarations, JNI\n"
        "- IPC: Intent, BroadcastReceiver, ContentProvider, Binder, Messenger\n"
        "- Device info: Build;->MODEL, TelephonyManager;->getDeviceId, Settings$Secure\n\n"

        "Smali bytecode:\n"
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
