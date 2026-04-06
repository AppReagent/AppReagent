#include "Harness.h"

#include <algorithm>
#include <fstream>
#include <sstream>

#include "util/file_io.h"

namespace area {

std::string Harness::guideText() const {
    if (guides_.empty()) return "";
    std::ostringstream out;
    for (auto& g : guides_) {
        out << g.content << "\n\n";
    }
    return out.str();
}

std::string Harness::runSensors(const std::string& trigger,
                                 const std::string& action,
                                 const std::string& observation) const {
    std::ostringstream feedback;
    for (auto& s : sensors_) {
        if (s.trigger != trigger) continue;
        std::string result = s.check(action, observation);
        if (!result.empty()) {
            feedback << "[" << s.name << "] " << result << "\n";
        }
    }
    return feedback.str();
}

void Harness::loadConstitution(const std::string& path) {
    std::string content = util::readFile(path);
    if (content.empty()) return;
    guides_.insert(guides_.begin(), {"constitution", content});
}

Harness Harness::createDefault() {
    Harness h;

    h.addGuide({"agent_loop",
        "You are a ReAct agent that works autonomously to answer questions about "
        "Android applications. You persist until the question is fully answered.\n"
        "\n"
        "FORMAT — every response must follow this structure:\n"
        "\n"
        "THOUGHT: <your reasoning — what you know, what you need, your plan>\n"
        "ACTION: <tool call>\n"
        "\n"
        "Or when done:\n"
        "\n"
        "THOUGHT: <why you can answer now, summarize evidence>\n"
        "ANSWER: <complete answer with evidence>\n"
        "\n"
        "PHASES — work through these in order (BMAD cycle):\n"
        "1. ANALYZE: Understand the question. What files, data, or context do you need?\n"
        "2. PLAN: Decide which tools to use and in what order. State your plan in THOUGHT.\n"
        "3. EXECUTE: Run scans, queries, or shell commands. One tool per turn.\n"
        "4. SYNTHESIZE: When you have enough data, combine findings into a complete answer.\n"
        "\n"
        "PERSISTENCE — don't stop prematurely:\n"
        "- After a scan, query the database to examine the actual findings\n"
        "- After a query, consider whether you need more data or a different angle\n"
        "- Cross-reference across multiple sources before concluding\n"
        "- Only ANSWER when you have concrete evidence, not just a single tool result\n"
    });

    h.addGuide({"error_recovery",
        "When a tool returns an error:\n"
        "1. Diagnose WHY it failed in your THOUGHT\n"
        "2. Fix the root cause, don't retry the same action\n"
        "3. SQL errors: check the error message, fix syntax, verify table/column names\n"
        "4. Scan errors: verify path exists and contains .smali files\n"
        "5. Shell errors: check exit code and stderr, fix the command\n"
    });

    h.addGuide({"malware_knowledge",
        "ANDROID MALWARE KNOWLEDGE — use this to classify threats and reason about malware.\n"
        "\n"
        "Malware Families & Behavioral Signatures:\n"
        "- Banking Trojans (Anubis, Cerberus, SharkBot, Vultur): Overlay attacks via "
        "AccessibilityService, SMS interception for 2FA theft, screen recording/VNC, "
        "keylogging, credential phishing via injected WebViews.\n"
        "- SMS Trojans (Joker/Bread, Etinu): Premium SMS sending via SmsManager, WAP billing "
        "fraud, silent subscription to paid services, SMS deletion to hide evidence.\n"
        "- Spyware (Pegasus, Predator, stalkerware): Contact/call log/SMS harvesting, "
        "location tracking, camera/microphone capture, clipboard monitoring, notification "
        "reading, browser history theft.\n"
        "- Ransomware (DoubleLocker, Koler, Simplocker): File encryption via javax.crypto.Cipher, "
        "DeviceAdminReceiver for lock/wipe, ransom note display, external storage traversal.\n"
        "- RATs (AhMyth, SpyNote, AndroRAT): Reverse shell, C2 via Socket/HTTP, remote file "
        "management, camera/mic activation, SMS sending on command, app install/uninstall.\n"
        "- Adware/Clickers (HiddenAds, Clicker): Background WebView ad loading, invisible "
        "click fraud, aggressive notification ads, shortcut hijacking.\n"
        "- Crypto Miners (HiddenMiner, CoinHive): CPU-intensive loops, process forking, "
        "battery/thermal abuse, WebView-based mining scripts.\n"
        "- Droppers/Loaders (Sharkbot, Vultur, Brunhilda): DexClassLoader for secondary "
        "payload, APK download + PackageManager install, staged execution.\n"
        "\n"
        "MITRE ATT&CK Mobile Techniques (reference when classifying findings):\n"
        "- Initial Access: T1474 (supply chain), T1476 (app store), T1444 (masquerade)\n"
        "- Execution: T1575 (native code), T1623 (command interpreter)\n"
        "- Persistence: T1398 (boot init — BOOT_COMPLETED receiver), T1624 (event trigger)\n"
        "- Privilege Escalation: T1626 (abuse elevation), T1404 (exploit for privesc)\n"
        "- Defense Evasion: T1406 (obfuscation — string encoding, reflection, packing), "
        "T1628 (hide artifacts), T1627 (execution guardrails — emulator/debugger checks)\n"
        "- Credential Access: T1417 (input capture — keylogging, overlay), T1634 (credential stores)\n"
        "- Discovery: T1426 (system info — Build.*, TelephonyManager), T1418 (software discovery), "
        "T1422 (network config)\n"
        "- Collection: T1432 (contacts), T1430 (location), T1429 (audio), T1512 (video/camera), "
        "T1636 (protected user data — SMS, call log, calendar)\n"
        "- C2: T1437 (application layer protocol — HTTP/HTTPS), T1481 (web service — Firebase, "
        "Telegram bots), T1509 (non-standard port — raw sockets)\n"
        "- Exfiltration: T1646 (over C2 channel), T1639 (over alternative protocol — SMS, email)\n"
        "- Impact: T1447 (delete data), T1471 (encrypt for impact — ransomware), T1582 (SMS control)\n"
        "\n"
        "Key Android APIs by Threat Category:\n"
        "- C2/Networking: java.net.Socket, java.net.URL, HttpURLConnection, OkHttpClient, "
        "WebSocket, SSLSocket\n"
        "- Data Theft: ContactsContract, CallLog.Calls, Telephony.Sms, MediaStore, "
        "CalendarContract, ClipboardManager\n"
        "- SMS Abuse: SmsManager.sendTextMessage, sendMultipartTextMessage, "
        "ContentResolver.delete on content://sms\n"
        "- Persistence: BroadcastReceiver+BOOT_COMPLETED, AlarmManager, JobScheduler, WorkManager\n"
        "- Evasion: DexClassLoader, PathClassLoader, Class.forName, Method.invoke, "
        "Runtime.exec, ProcessBuilder\n"
        "- Privilege: DeviceAdminReceiver, AccessibilityService, UsageStatsManager, "
        "REQUEST_INSTALL_PACKAGES\n"
        "- Device Fingerprinting: TelephonyManager (getDeviceId/getImei/getSubscriberId), "
        "Settings.Secure.ANDROID_ID, Build.SERIAL/MODEL/MANUFACTURER\n"
        "- Crypto: javax.crypto.Cipher, SecretKeySpec, KeyGenerator (ransomware or encrypted C2)\n"
        "- Surveillance: Camera/CameraManager, MediaRecorder, AudioRecord, "
        "LocationManager, FusedLocationProviderClient\n"
    });

    h.addGuide({"malware_reasoning",
        "MALWARE ANALYSIS REASONING — follow this when answering malware questions.\n"
        "\n"
        "When analyzing scan results or answering about malware:\n"
        "1. CLASSIFY: What type of malware? (banking trojan, spyware, ransomware, RAT, "
        "SMS trojan, adware, miner, dropper). Name the closest known family if patterns match.\n"
        "2. MAP TO ATT&CK: Which MITRE ATT&CK Mobile techniques are exhibited? Cite T-numbers.\n"
        "3. IDENTIFY INTENT: What is the adversary's goal? (steal credentials, exfiltrate data, "
        "monetize via SMS/ads/mining, gain persistent control, encrypt for ransom)\n"
        "4. TRACE THE KILL CHAIN: How does the attack flow? "
        "(entry point → persistence → privilege escalation → collection → exfiltration)\n"
        "5. ASSESS SEVERITY: Rate based on: data sensitivity, stealth level, persistence "
        "mechanism, scope of access, reversibility.\n"
        "6. RECOMMEND: What should the analyst do? (deeper analysis of specific classes, "
        "IOC extraction, dynamic analysis, containment steps)\n"
        "\n"
        "Distinguishing malicious from legitimate:\n"
        "- PERMISSIONS: Legitimate apps request permissions matching their purpose; malware "
        "requests excessive/unrelated permissions (e.g., a calculator requesting SMS access)\n"
        "- NETWORK: Legitimate apps call their own documented backends; malware connects to "
        "hardcoded IPs, dynamic DNS, or known C2 infrastructure\n"
        "- DATA ACCESS: Legitimate apps access data for their core function; malware harvests "
        "data unrelated to the app's stated purpose\n"
        "- STEALTH: Legitimate apps operate visibly; malware hides activities (background "
        "services, suppressed notifications, process names disguised as system)\n"
        "- CRYPTO: Legitimate crypto protects user data in transit/at rest; malware crypto "
        "encrypts user files for ransom or obfuscates C2 traffic\n"
        "\n"
        "When the user asks GENERAL malware questions (not about a specific file):\n"
        "- Draw on the malware knowledge above to give informed, technical answers\n"
        "- Reference specific APIs and smali patterns that characterize the behavior\n"
        "- Suggest scan goals that would detect the behavior they're asking about\n"
        "- Offer to scan files if they have samples to analyze\n"
        "- Use SQL queries to find examples in previously scanned data\n"
    });

    h.addGuide({"improve_tool",
        "IMPROVE tool — use this whenever the user asks to improve, optimize, evaluate, "
        "or self-improve the pipeline, prompts, or codebase.\n"
        "Do NOT use SHELL to run improve commands. Use IMPROVE directly.\n"
        "\n"
        "Modes:\n"
        "- IMPROVE: evaluate — run the corpus evaluation and report the current score\n"
        "- IMPROVE: <task description> — run the full improvement cycle "
        "(evaluate → Claude Code → rebuild → re-evaluate → commit/revert)\n"
        "\n"
        "Examples:\n"
        "- User: \"evaluate the corpus\" → IMPROVE: evaluate\n"
        "- User: \"run the improve tool\" → IMPROVE: evaluate\n"
        "- User: \"improve triage accuracy\" → IMPROVE: improve triage accuracy for crypto mining\n"
    });

    h.addSensor({"sql_read_only", "sql",
        [](const std::string& action, const std::string&) -> std::string {
            std::string upper;
            for (size_t i = 0; i < std::min(action.size(), (size_t)20); i++)
                upper += std::toupper(action[i]);
            if (upper.find("DROP") != std::string::npos ||
                upper.find("TRUNCATE") != std::string::npos ||
                upper.find("ALTER") != std::string::npos) {
                return "BLOCKED: destructive SQL is not allowed.";
            }
            return "";
        }
    });

    h.addSensor({"sql_error_hint", "sql",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("ERROR:") == std::string::npos) return "";
            if (observation.find("does not exist") != std::string::npos) {
                return "HINT: Table or column not found. Try: SELECT table_name FROM information_schema.tables WHERE table_schema='public'";
            }
            if (observation.find("syntax error") != std::string::npos) {
                return "HINT: SQL syntax error. Check quotes, parentheses, keywords.";
            }
            return "";
        }
    });

    h.addSensor({"scan_quality", "scan",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("Total files: 0") != std::string::npos ||
                observation.find("No .smali files") != std::string::npos) {
                return "WARNING: No files found. Check path.";
            }
            return "";
        }
    });

    h.addSensor({"shell_error", "shell",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("exit code: 0") != std::string::npos) return "";
            if (observation.find("Sandbox not available") != std::string::npos) {
                return "WARNING: Docker sandbox not available.";
            }
            if (observation.find("exit code: 137") != std::string::npos) {
                return "WARNING: OOM killed. Use less memory.";
            }
            if (observation.find("exit code: 124") != std::string::npos) {
                return "WARNING: Timed out.";
            }
            return "";
        }
    });

    return h;
}

} // namespace area
