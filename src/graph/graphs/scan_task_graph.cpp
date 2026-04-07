#include "graph/graphs/scan_task_graph.h"
#include "graph/util/json_extract.h"
#include "util/file_io.h"
#include "Embedding.h"

#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>

using area::graph::extractJson;
namespace fs = std::filesystem;

#include "elf/disassembler.h"
#include "graph/nodes/code_node.h"
#include "graph/nodes/llm_call_node.h"
#include "graph/nodes/splitter_node.h"
#include "graph/nodes/supervised_llm_call_node.h"
#include "smali/parser.h"

namespace area::graph {

area::LLMBackend* TierBackends::at(int tier) const {
    auto it = backends.find(tier);
    if (it != backends.end()) return it->second;
    // fall back to nearest available tier
    area::LLMBackend* best = nullptr;
    int bestDist = 999;
    for (auto& [t, b] : backends) {
        int dist = std::abs(t - tier);
        if (dist < bestDist) { bestDist = dist; best = b; }
    }
    if (!best) throw std::runtime_error("no backends configured");
    return best;
}

std::string loadPrompt(const std::string& path) {
    return area::util::readFileOrThrow(path);
}

static bool validateJsonKeys(const std::string& response, const TaskContext&,
                             std::initializer_list<const char*> keys) {
    try {
        auto j = nlohmann::json::parse(extractJson(response));
        for (auto* key : keys) {
            if (!j.contains(key)) return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

// ── Static analysis helpers ──────────────────────────────────────────

struct ThreatPattern {
    std::string name;
    std::vector<std::string> required_apis; // ALL must be present
    std::string category;
    int risk_boost; // added to static risk score
};

static const std::vector<ThreatPattern> kThreatPatterns = {
    {"SMS exfiltration",
     {"SmsManager", "ContentResolver"},
     "sms_abuse", 40},
    {"SMS exfiltration (contacts)",
     {"SmsManager", "ContactsContract"},
     "data_theft", 45},
    {"Dynamic code loading from network",
     {"DexClassLoader", "HttpURLConnection"},
     "dropper", 50},
    {"Dynamic code loading from network",
     {"DexClassLoader", "URL"},
     "dropper", 45},
    {"Root exploit",
     {"Runtime", "exec"},
     "evasion", 35},
    {"Ransomware pattern",
     {"Cipher", "Environment;->getExternalStorage"},
     "ransomware", 50},
    {"Surveillance (camera)",
     {"Camera", "MediaRecorder"},
     "surveillance", 35},
    {"Surveillance (microphone + network)",
     {"MediaRecorder", "HttpURLConnection"},
     "surveillance", 45},
    {"Credential theft (overlay)",
     {"WindowManager", "TYPE_APPLICATION_OVERLAY"},
     "credential_theft", 40},
    {"Persistence (boot + alarm)",
     {"BOOT_COMPLETED", "AlarmManager"},
     "persistence", 30},
    {"Reflection-based evasion",
     {"Class;->forName", "Method;->invoke"},
     "evasion", 30},
    {"Dynamic class loading",
     {"DexClassLoader"},
     "dropper", 25},
    {"Accessibility abuse",
     {"AccessibilityService", "performGlobalAction"},
     "credential_theft", 40},
};

// Suspicious API calls to flag individually
struct SuspiciousApi {
    std::string pattern;
    std::string category;
    int risk;
};

static const std::vector<SuspiciousApi> kSuspiciousApis = {
    {"SmsManager;->sendTextMessage", "sms_abuse", 20},
    {"SmsManager;->sendMultipartTextMessage", "sms_abuse", 20},
    {"ContentResolver;->query", "data_theft", 10},
    {"ContactsContract", "data_theft", 15},
    {"CallLog", "data_theft", 15},
    {"Telephony;->getDeviceId", "data_theft", 15},
    {"TelephonyManager;->getLine1Number", "data_theft", 15},
    {"LocationManager;->getLastKnownLocation", "surveillance", 15},
    {"LocationManager;->requestLocationUpdates", "surveillance", 15},
    {"Camera;->open", "surveillance", 15},
    {"MediaRecorder;->setAudioSource", "surveillance", 15},
    {"DexClassLoader", "dropper", 20},
    {"PathClassLoader", "dropper", 15},
    {"Runtime;->exec", "evasion", 20},
    {"ProcessBuilder;->start", "evasion", 15},
    {"Class;->forName", "evasion", 10},
    {"Method;->invoke", "evasion", 10},
    {"Cipher;->getInstance", "ransomware", 10},
    {"SecretKeySpec", "ransomware", 10},
    {"AccessibilityService", "credential_theft", 15},
    {"WindowManager;->addView", "credential_theft", 10},
    {"KeyEvent", "credential_theft", 10},
    {"PackageManager;->setComponentEnabledSetting", "persistence", 10},
    {"AlarmManager;->setRepeating", "persistence", 10},
    {"DevicePolicyManager", "persistence", 15},
    {"HttpURLConnection;->connect", "c2", 10},
    {"URL;->openConnection", "c2", 10},
    {"Socket;-><init>", "c2", 15},
    {"DataOutputStream;->write", "c2", 10},
    {"Base64;->decode", "evasion", 8},
    {"Base64;->encode", "evasion", 5},
    // Security-relevant but potentially legitimate APIs
    {"DownloadManager;->enqueue", "dropper", 15},
    {"NotificationManager;->notify", "surveillance", 10},
    {"NotificationCompat", "surveillance", 8},
    {"FirebaseMessagingService", "surveillance", 10},
};

// Check for obfuscation indicators in raw code
struct ObfuscationIndicator {
    std::string pattern;
    std::string description;
    int risk;
};

static const std::vector<ObfuscationIndicator> kObfuscationIndicators = {
    {"xor-int", "XOR byte manipulation (string/data obfuscation)", 15},
    {"const-string v", "String constant (check for encoded data)", 0}, // scored separately
    {"Ljava/lang/reflect/Method;", "Reflection API usage", 10},
    {"Ljava/lang/reflect/Field;", "Reflection field access", 8},
    {"Ldalvik/system/DexClassLoader;", "Dynamic DEX loading", 20},
    {"Ljava/lang/ClassLoader;->loadClass", "Dynamic class loading", 15},
    {"Ljava/util/zip/ZipInputStream;", "ZIP extraction (possible payload unpacking)", 10},
    {"Landroid/util/Base64;", "Base64 encoding/decoding", 8},
};

// Scan file contents for all invoke-* targets, return set of API strings
static std::set<std::string> extractAllApiCalls(const std::string& contents) {
    std::set<std::string> apis;
    std::istringstream stream(contents);
    std::string line;
    while (std::getline(stream, line)) {
        // Match invoke-* instructions
        auto pos = line.find("invoke-");
        if (pos == std::string::npos) continue;
        // Extract the target: everything after }, which is the class->method
        auto bracePos = line.find('}', pos);
        if (bracePos == std::string::npos) continue;
        auto comma = line.find(',', bracePos);
        if (comma == std::string::npos) continue;
        std::string target = line.substr(comma + 1);
        // Trim whitespace
        while (!target.empty() && (target.front() == ' ' || target.front() == '\t'))
            target.erase(0, 1);
        while (!target.empty() && (target.back() == ' ' || target.back() == '\n' || target.back() == '\r'))
            target.pop_back();
        if (!target.empty()) apis.insert(target);
    }
    return apis;
}

// Check for suspicious const-string values (IPs, base64, encoded data)
static std::vector<std::string> extractSuspiciousStrings(const std::string& contents) {
    std::vector<std::string> suspicious;
    std::istringstream stream(contents);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.find("const-string") == std::string::npos) continue;
        auto commaPos = line.find(',');
        if (commaPos == std::string::npos) continue;
        auto q1 = line.find('"', commaPos);
        if (q1 == std::string::npos) continue;
        std::string val;
        for (size_t i = q1 + 1; i < line.size(); i++) {
            if (line[i] == '\\' && i + 1 < line.size()) { val += line[i]; val += line[i+1]; i++; }
            else if (line[i] == '"') break;
            else val += line[i];
        }
        if (val.empty()) continue;

        // Check for IP addresses
        int dots = 0, digits = 0;
        for (char c : val) { if (c == '.') dots++; if (std::isdigit(c)) digits++; }
        if (dots == 3 && digits >= 4 && val.size() <= 15) { suspicious.push_back("IP: " + val); continue; }

        // Check for phone numbers
        if (val.size() >= 7) {
            int dcount = 0;
            for (char c : val) if (std::isdigit(c)) dcount++;
            if (dcount >= 7 && val.find_first_of("+-() ") != std::string::npos) {
                suspicious.push_back("Phone: " + val); continue;
            }
        }

        // Check for URLs
        std::string lower = val;
        for (auto& c : lower) c = std::tolower(static_cast<unsigned char>(c));
        if (lower.starts_with("http://") || lower.starts_with("https://") ||
            lower.starts_with("ftp://") || lower.starts_with("ws://")) {
            suspicious.push_back("URL: " + val); continue;
        }

        // Check for base64-like long strings
        if (val.size() > 30) {
            bool allB64 = true;
            for (char c : val) {
                if (!std::isalnum(c) && c != '+' && c != '/' && c != '=') { allB64 = false; break; }
            }
            if (allB64) { suspicious.push_back("Base64: " + val.substr(0, 60) + "..."); continue; }
        }

        // Shell commands
        if (lower == "su" || lower.find("/bin/") != std::string::npos ||
            lower.find("chmod") != std::string::npos || lower.starts_with("pm ") ||
            lower.starts_with("am ")) {
            suspicious.push_back("Shell: " + val); continue;
        }
    }
    return suspicious;
}

// Build file-level threat signals from all API calls found in the file
static nlohmann::json computeFileThreatSignals(const std::set<std::string>& allApis,
                                                const std::string& contents) {
    nlohmann::json signals;
    signals["matched_patterns"] = nlohmann::json::array();
    signals["suspicious_apis"] = nlohmann::json::array();
    signals["obfuscation_indicators"] = nlohmann::json::array();
    signals["file_risk_score"] = 0;
    int totalRisk = 0;

    // Flatten APIs to a single searchable string
    std::string apiBlob;
    for (auto& a : allApis) apiBlob += a + "\n";

    // Check compound threat patterns
    std::set<std::string> categories;
    for (auto& tp : kThreatPatterns) {
        bool allFound = true;
        for (auto& req : tp.required_apis) {
            if (apiBlob.find(req) == std::string::npos &&
                contents.find(req) == std::string::npos) {
                allFound = false;
                break;
            }
        }
        if (allFound) {
            nlohmann::json entry;
            entry["name"] = tp.name;
            entry["category"] = tp.category;
            entry["risk"] = tp.risk_boost;
            signals["matched_patterns"].push_back(entry);
            totalRisk += tp.risk_boost;
            categories.insert(tp.category);
        }
    }

    // Check individual suspicious APIs
    for (auto& sa : kSuspiciousApis) {
        if (apiBlob.find(sa.pattern) != std::string::npos ||
            contents.find(sa.pattern) != std::string::npos) {
            nlohmann::json entry;
            entry["api"] = sa.pattern;
            entry["category"] = sa.category;
            entry["risk"] = sa.risk;
            signals["suspicious_apis"].push_back(entry);
            totalRisk += sa.risk;
            categories.insert(sa.category);
        }
    }

    // Check obfuscation indicators
    for (auto& oi : kObfuscationIndicators) {
        if (contents.find(oi.pattern) != std::string::npos && oi.risk > 0) {
            nlohmann::json entry;
            entry["pattern"] = oi.pattern;
            entry["description"] = oi.description;
            entry["risk"] = oi.risk;
            signals["obfuscation_indicators"].push_back(entry);
            totalRisk += oi.risk;
        }
    }

    // Suspicious strings
    auto susStrings = extractSuspiciousStrings(contents);
    if (!susStrings.empty()) {
        signals["suspicious_strings"] = susStrings;
        totalRisk += static_cast<int>(susStrings.size()) * 5;
    }

    signals["threat_categories"] = nlohmann::json::array();
    for (auto& c : categories) signals["threat_categories"].push_back(c);

    // Cap at 100
    signals["file_risk_score"] = std::min(totalRisk, 100);

    return signals;
}

// Compute method-level static analysis
static nlohmann::json computeMethodStaticAnalysis(const std::string& methodBody) {
    nlohmann::json analysis;
    analysis["api_calls"] = nlohmann::json::array();
    analysis["risk_indicators"] = nlohmann::json::array();
    int methodRisk = 0;

    // Extract API calls from this method
    auto apis = extractAllApiCalls(methodBody);
    for (auto& api : apis) {
        analysis["api_calls"].push_back(api);
    }

    std::string apiBlob;
    for (auto& a : apis) apiBlob += a + "\n";

    // Check against suspicious API list
    for (auto& sa : kSuspiciousApis) {
        if (apiBlob.find(sa.pattern) != std::string::npos ||
            methodBody.find(sa.pattern) != std::string::npos) {
            nlohmann::json ri;
            ri["api"] = sa.pattern;
            ri["category"] = sa.category;
            ri["risk"] = sa.risk;
            analysis["risk_indicators"].push_back(ri);
            methodRisk += sa.risk;
        }
    }

    // Check for obfuscation in this method
    bool hasXor = methodBody.find("xor-int") != std::string::npos;
    bool hasArrayLoop = methodBody.find("aget-byte") != std::string::npos &&
                        methodBody.find("aput-byte") != std::string::npos;
    if (hasXor && hasArrayLoop) {
        nlohmann::json ri;
        ri["pattern"] = "xor_byte_loop";
        ri["description"] = "XOR loop over byte array — obfuscation/cipher";
        ri["risk"] = 20;
        analysis["risk_indicators"].push_back(ri);
        methodRisk += 20;
    } else if (hasXor) {
        nlohmann::json ri;
        ri["pattern"] = "xor_operation";
        ri["description"] = "XOR operation on data";
        ri["risk"] = 8;
        analysis["risk_indicators"].push_back(ri);
        methodRisk += 8;
    }

    // Reflection chain in a single method
    if (methodBody.find("Class;->forName") != std::string::npos &&
        methodBody.find("Method;->invoke") != std::string::npos) {
        nlohmann::json ri;
        ri["pattern"] = "reflection_chain";
        ri["description"] = "Full reflection chain: forName -> getMethod -> invoke";
        ri["risk"] = 25;
        analysis["risk_indicators"].push_back(ri);
        methodRisk += 25;
    }

    // Native method declaration
    if (methodBody.find(".method public native") != std::string::npos ||
        methodBody.find(".method private native") != std::string::npos) {
        nlohmann::json ri;
        ri["pattern"] = "native_method";
        ri["description"] = "Native method (JNI) — hides behavior in native code";
        ri["risk"] = 10;
        analysis["risk_indicators"].push_back(ri);
        methodRisk += 10;
    }

    analysis["static_risk_score"] = std::min(methodRisk, 100);
    return analysis;
}

TaskGraph buildScanTaskGraph(const TierBackends& backends,
                             const std::string& prompts_dir,
                             area::EmbeddingStore* embeddingStore) {
    TaskGraph g("ScanTask");

    // 1. Read file (binary-safe for ELF support)
    auto read_file = g.add<CodeNode>("read_file", [](TaskContext ctx) {
        std::string path = ctx.get("file_path").get<std::string>();
        std::string contents = area::util::readFile(path);
        if (contents.empty()) {
            ctx.set("error", "could not open file: " + path);
            ctx.discarded = true;
            return ctx;
        }
        ctx.set("file_contents", contents);

        // Detect format by magic bytes and extension
        if (area::elf::isElf(contents)) {
            ctx.set("file_format", "elf");
        } else if (path.ends_with(".smali")) {
            ctx.set("file_format", "smali");
        } else {
            ctx.set("file_format", "unsupported");
        }
        return ctx;
    });

    // 2. Format routing
    auto detect_format = g.add<DecisionCodeNode>("detect_format", [](const TaskContext& ctx) -> std::string {
        if (ctx.has("file_format")) {
            return ctx.get("file_format").get<std::string>();
        }
        return "unsupported";
    });

    auto unsupported = g.add<ExitNode>("unsupported", [](TaskContext& ctx) {
        ctx.discard_reason = "unsupported_format";
    });

    // 2b. File-level threat signal extraction (before split, so all methods inherit)
    auto file_signals = g.add<CodeNode>("file_signals", [](TaskContext ctx) {
        if (!ctx.has("file_contents")) return ctx;
        auto contents = ctx.get("file_contents").get<std::string>();
        auto format = ctx.has("file_format") ? ctx.get("file_format").get<std::string>() : "";

        if (format == "smali") {
            auto allApis = extractAllApiCalls(contents);
            auto signals = computeFileThreatSignals(allApis, contents);
            ctx.set("file_threat_signals", signals);

            // Build a human-readable summary for the LLM
            std::ostringstream summary;
            int score = signals.value("file_risk_score", 0);
            if (score > 0) {
                summary << "FILE-LEVEL THREAT SIGNALS (risk=" << score << "):\n";
                if (signals.contains("matched_patterns") && !signals["matched_patterns"].empty()) {
                    summary << "  Compound patterns detected:\n";
                    for (auto& p : signals["matched_patterns"]) {
                        summary << "    - " << p["name"].get<std::string>()
                                << " [" << p["category"].get<std::string>() << "]\n";
                    }
                }
                if (signals.contains("threat_categories") && !signals["threat_categories"].empty()) {
                    summary << "  Threat categories: ";
                    for (size_t i = 0; i < signals["threat_categories"].size(); i++) {
                        if (i > 0) summary << ", ";
                        summary << signals["threat_categories"][i].get<std::string>();
                    }
                    summary << "\n";
                }
                if (signals.contains("suspicious_strings") && !signals["suspicious_strings"].empty()) {
                    summary << "  Suspicious strings found:\n";
                    for (auto& s : signals["suspicious_strings"]) {
                        summary << "    - " << s.get<std::string>() << "\n";
                    }
                }
                if (signals.contains("obfuscation_indicators") && !signals["obfuscation_indicators"].empty()) {
                    summary << "  Obfuscation indicators:\n";
                    for (auto& o : signals["obfuscation_indicators"]) {
                        summary << "    - " << o["description"].get<std::string>() << "\n";
                    }
                }
            }
            ctx.set("file_signals_summary", summary.str());
        }
        return ctx;
    });

    // 3. Code splitter — handles both smali methods and ELF functions
    auto split_methods = g.add<SplitterNode>("split_methods", [prompts_dir](TaskContext ctx) {
        auto contents = ctx.get("file_contents").get<std::string>();
        auto format = ctx.has("file_format") ? ctx.get("file_format").get<std::string>() : "smali";
        std::string scanGoal = ctx.has("scan_goal") ? ctx.get("scan_goal").get<std::string>() : "";

        std::vector<TaskContext> items;

        if (format == "elf") {
            std::string filePath = ctx.has("file_path") ? ctx.get("file_path").get<std::string>() : "";
            auto info = area::elf::disassemble(contents, fs::path(filePath).filename().string());

            std::string className = info.filename;

            // Build imports summary (analogous to fields_summary)
            std::ostringstream importsSummary;
            importsSummary << "Architecture: " << info.arch << "\n";
            importsSummary << "Type: " << info.type << "\n";
            if (!info.imports.empty()) {
                importsSummary << "Imported functions:\n";
                for (auto& imp : info.imports) {
                    importsSummary << "  " << imp << "\n";
                }
            }
            std::string imports = importsSummary.str();

            std::string elfFmtTmpl = loadPrompt(prompts_dir + "/elf_format_context.prompt");
            TaskContext archCtx;
            archCtx.set("arch", info.arch);
            std::string formatCtx = resolveTemplate(elfFmtTmpl, archCtx);

            for (auto& func : info.functions) {
                TaskContext item;
                if (ctx.has("file_path")) item.set("file_path", ctx.get("file_path"));
                if (ctx.has("file_hash")) item.set("file_hash", ctx.get("file_hash"));
                item.set("class_name", className);
                item.set("source_file", className);
                item.set("scan_goal", scanGoal);
                item.set("method_name", func.name);
                char addrBuf[32];
                snprintf(addrBuf, sizeof(addrBuf), "0x%" PRIx64, func.address);
                item.set("method_signature",
                    std::string(addrBuf) + " (" + std::to_string(func.size) + " bytes)");
                item.set("method_body", func.disassembly);
                item.set("fields_summary", imports);
                item.set("format_context", formatCtx);
                items.push_back(std::move(item));
            }

            if (items.empty()) {
                TaskContext empty;
                empty.discarded = true;
                empty.discard_reason = "no_functions";
                items.push_back(std::move(empty));
            }
        } else {
            // Smali path
            auto parsed = area::smali::parse(contents);

            std::string className = parsed.class_name;
            std::string sourceFile = parsed.source_file;

            std::ostringstream fieldsSummary;
            for (auto& f : parsed.fields) {
                fieldsSummary << f.access << " " << f.name << ":" << f.type << "\n";
            }
            std::string fields = fieldsSummary.str();

            std::string formatCtx = loadPrompt(prompts_dir + "/smali_format_context.prompt");

            // Propagate file-level threat signals to each method item
            bool hasFileSignals = ctx.has("file_threat_signals");
            nlohmann::json fileSignals;
            std::string fileSignalsSummary;
            if (hasFileSignals) {
                fileSignals = ctx.get("file_threat_signals");
            }
            if (ctx.has("file_signals_summary")) {
                fileSignalsSummary = ctx.get("file_signals_summary").get<std::string>();
            }

            for (auto& m : parsed.methods) {
                TaskContext item;
                if (ctx.has("file_path")) item.set("file_path", ctx.get("file_path"));
                if (ctx.has("file_hash")) item.set("file_hash", ctx.get("file_hash"));
                item.set("class_name", className);
                item.set("source_file", sourceFile);
                item.set("scan_goal", scanGoal);
                item.set("method_name", m.name);
                item.set("method_signature", m.signature);
                item.set("method_body", m.body);
                item.set("fields_summary", fields);
                item.set("format_context", formatCtx);

                // Inherit file-level signals
                if (hasFileSignals) {
                    item.set("file_threat_signals", fileSignals);
                    item.set("file_signals_summary", fileSignalsSummary);
                }

                // Extract call graph edges from this method
                auto calls = area::smali::extractCalls(m.body);
                if (!calls.empty()) {
                    nlohmann::json callsJson = nlohmann::json::array();
                    for (auto& c : calls) {
                        callsJson.push_back({
                            {"invoke_type", c.invoke_type},
                            {"target_class", c.target_class},
                            {"target_method", c.target_method},
                            {"target_signature", c.target_signature}
                        });
                    }
                    item.set("method_calls", callsJson);
                }

                items.push_back(std::move(item));
            }
        }
        return items;
    });

    // 3b. Per-method static analysis enrichment (runs on each split item before LLM)
    auto static_enrich = g.add<CodeNode>("static_enrich", [](TaskContext ctx) {
        if (!ctx.has("method_body")) return ctx;
        auto methodBody = ctx.get("method_body").get<std::string>();

        auto analysis = computeMethodStaticAnalysis(methodBody);
        ctx.set("static_analysis", analysis);

        // Build human-readable summary for the LLM prompt
        std::ostringstream summary;
        int score = analysis.value("static_risk_score", 0);
        if (score > 0) {
            summary << "STATIC ANALYSIS (method risk=" << score << "):\n";
            if (analysis.contains("api_calls") && !analysis["api_calls"].empty()) {
                summary << "  API calls found: ";
                int count = 0;
                for (auto& api : analysis["api_calls"]) {
                    if (count > 0) summary << ", ";
                    std::string a = api.get<std::string>();
                    // Shorten for readability
                    auto arrow = a.find("->");
                    if (arrow != std::string::npos) {
                        auto semi = a.rfind(';', arrow);
                        if (semi != std::string::npos && semi > 0) {
                            auto slash = a.rfind('/', semi);
                            if (slash != std::string::npos)
                                a = a.substr(slash + 1);
                        }
                    }
                    summary << a;
                    if (++count >= 10) { summary << " (+" << (analysis["api_calls"].size() - 10) << " more)"; break; }
                }
                summary << "\n";
            }
            if (analysis.contains("risk_indicators") && !analysis["risk_indicators"].empty()) {
                summary << "  Risk indicators:\n";
                for (auto& ri : analysis["risk_indicators"]) {
                    std::string desc;
                    if (ri.contains("description")) desc = ri["description"].get<std::string>();
                    else if (ri.contains("api")) desc = ri["api"].get<std::string>();
                    else desc = "unknown";
                    summary << "    - " << desc
                            << " [" << ri["category"].get<std::string>() << ", +" << ri["risk"] << "]\n";
                }
            }
        }
        // Also include file-level signals if present
        if (ctx.has("file_signals_summary")) {
            auto fileSummary = ctx.get("file_signals_summary").get<std::string>();
            if (!fileSummary.empty()) {
                summary << fileSummary;
            }
        }
        ctx.set("static_analysis_summary", summary.str());
        return ctx;
    });

    std::string triagePrompt = loadPrompt(prompts_dir + "/triage.prompt");
    std::string triageSupervisorPrompt = loadPrompt(prompts_dir + "/triage_supervisor.prompt");
    std::string triageSystemPrompt = loadPrompt(prompts_dir + "/triage_system.prompt");

    auto triage = g.add<SupervisedLLMCallNode>("triage",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = triagePrompt,
            .system_prompt = triageSystemPrompt,
            .supervisor_prompt = triageSupervisorPrompt,
            .max_retries = 1,
        },
        backends.at(1),
        backends.at(0),
        nullptr);

    auto filter = g.add<PredicateCodeNode>("filter_irrelevant", [](const TaskContext& ctx) -> bool {
        // Always pass if no LLM response (let downstream handle it)
        if (!ctx.has("llm_response")) return true;

        // Check static analysis — high static risk overrides LLM dismissal
        int staticRisk = 0;
        if (ctx.has("static_analysis")) {
            try {
                auto sa = ctx.get("static_analysis");
                if (sa.is_object()) staticRisk = sa.value("static_risk_score", 0);
                else staticRisk = nlohmann::json::parse(sa.get<std::string>()).value("static_risk_score", 0);
            } catch (...) {}
        }

        // Check file-level risk
        int fileRisk = 0;
        if (ctx.has("file_threat_signals")) {
            try {
                auto fs = ctx.get("file_threat_signals");
                if (fs.is_object()) fileRisk = fs.value("file_risk_score", 0);
                else fileRisk = nlohmann::json::parse(fs.get<std::string>()).value("file_risk_score", 0);
            } catch (...) {}
        }

        // If static analysis found significant risk, always pass through
        if (staticRisk >= 15 || fileRisk >= 30) return true;

        try {
            auto j = nlohmann::json::parse(extractJson(ctx.get("llm_response").get<std::string>()));
            bool relevant = j.value("relevant", false);
            auto confidence = j.value("confidence", 0.0);

            // Always pass through if marked relevant
            if (relevant) return true;

            // Pass through if triage found a non-trivial threat category
            std::string category = j.value("threat_category", "none");
            if (category != "none" && !category.empty()) return true;

            // Pass through if triage found API calls worth investigating
            // Methods with API calls need HIGHER confidence to discard (they're more likely relevant)
            if (j.contains("api_calls") && j["api_calls"].is_array() && !j["api_calls"].empty()) {
                return confidence < 0.95;
            }

            // No API calls: moderate confidence is enough to discard
            return confidence < 0.85;
        } catch (...) {
            return true;
        }
    });

    auto discard_irrelevant = g.add<ExitNode>("discard_irrelevant", [](TaskContext& ctx) {
        ctx.discard_reason = "not_relevant";
    });

    // RAG enrichment: query embedding DB for similar methods from past scans
    auto rag_enrich = g.add<CodeNode>("rag_enrich", [embeddingStore](TaskContext ctx) {
        // Build call graph context from extracted method_calls
        if (ctx.has("method_calls")) {
            try {
                auto calls = ctx.get("method_calls");
                if (calls.is_array() && !calls.empty()) {
                    std::ostringstream cg;
                    cg << "Methods called by this function:\n";
                    for (auto& c : calls) {
                        cg << "  " << c.value("invoke_type", "")
                           << " " << c.value("target_class", "")
                           << "->" << c.value("target_method", "")
                           << c.value("target_signature", "") << "\n";
                    }
                    ctx.set("call_graph_context", cg.str());
                } else {
                    ctx.set("call_graph_context", "");
                }
            } catch (...) {
                ctx.set("call_graph_context", "");
            }
        } else {
            ctx.set("call_graph_context", "");
        }

        if (!embeddingStore || !embeddingStore->hasBackend()) return ctx;

        std::string methodBody = ctx.has("method_body") ? ctx.get("method_body").get<std::string>() : "";
        std::string methodName = ctx.has("method_name") ? ctx.get("method_name").get<std::string>() : "";
        if (methodBody.empty()) return ctx;

        // Build query from method body (truncated) + triage findings
        std::string query = methodBody.substr(0, 1000);
        if (ctx.has("llm_response")) {
            try {
                auto j = nlohmann::json::parse(extractJson(ctx.get("llm_response").get<std::string>()));
                if (j.contains("findings")) {
                    for (auto& f : j["findings"]) {
                        query += "\n" + f.get<std::string>();
                    }
                }
            } catch (...) {}
        }

        try {
            auto results = embeddingStore->searchByText(query, 3);
            if (!results.empty()) {
                std::ostringstream rag;
                for (size_t i = 0; i < results.size(); i++) {
                    auto& r = results[i];
                    rag << "--- Similar method " << (i + 1)
                        << " (similarity=" << std::fixed << std::setprecision(2)
                        << r.similarity << ") ---\n"
                        << "Class: " << r.class_name << "\n"
                        << "Method: " << r.method_name << "\n"
                        << r.content.substr(0, 500) << "\n\n";
                }
                ctx.set("rag_context", rag.str());
            }
        } catch (...) {
            // Embedding search failure is non-fatal
        }
        return ctx;
    });

    std::string deepPrompt = loadPrompt(prompts_dir + "/deep_analysis.prompt");
    std::string deepSupervisorPrompt = loadPrompt(prompts_dir + "/deep_analysis_supervisor.prompt");
    std::string deepSystemPrompt = loadPrompt(prompts_dir + "/deep_analysis_system.prompt");

    auto deep_analysis = g.add<SupervisedLLMCallNode>("deep_analysis",
        SupervisedLLMCallConfig{
            .tier = 1,
            .prompt_template = deepPrompt,
            .system_prompt = deepSystemPrompt,
            .supervisor_prompt = deepSupervisorPrompt,
            .max_retries = 2,
        },
        backends.at(2),
        backends.at(1),
        nullptr);

    auto collector = g.add<CollectorNode>("collect_results", [](std::vector<TaskContext> items) {
        TaskContext result;
        nlohmann::json collected = nlohmann::json::array();
        for (auto& item : items) {
            nlohmann::json entry;
            entry["method_name"] = item.has("method_name") ? item.get("method_name") : "";
            if (item.has("llm_response")) {
                try {
                    entry["analysis"] = nlohmann::json::parse(extractJson(item.get("llm_response").get<std::string>()));
                } catch (...) {
                    entry["analysis"] = item.get("llm_response");
                }
            }
            collected.push_back(std::move(entry));
        }
        result.set("collected", collected);
        if (!items.empty()) {
            if (items[0].has("class_name")) result.set("class_name", items[0].get("class_name"));
            if (items[0].has("source_file")) result.set("source_file", items[0].get("source_file"));
            if (items[0].has("scan_goal")) result.set("scan_goal", items[0].get("scan_goal"));
            if (items[0].has("format_context")) result.set("format_context", items[0].get("format_context"));
            if (items[0].has("file_signals_summary")) result.set("file_signals_summary", items[0].get("file_signals_summary"));
            if (items[0].has("file_threat_signals")) result.set("file_threat_signals", items[0].get("file_threat_signals"));
        }
        return result;
    });

    std::string synthesisPrompt = loadPrompt(prompts_dir + "/synthesis.prompt");
    std::string synthesisSupervisorPrompt = loadPrompt(prompts_dir + "/synthesis_supervisor.prompt");
    std::string synthesisSystemPrompt = loadPrompt(prompts_dir + "/synthesis_system.prompt");

    auto synthesize = g.add<SupervisedLLMCallNode>("synthesize",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = synthesisPrompt,
            .system_prompt = synthesisSystemPrompt,
            .supervisor_prompt = synthesisSupervisorPrompt,
            .max_retries = 1,
        },
        backends.at(2),
        backends.at(0),
        nullptr);

    auto risk_calc = g.add<CodeNode>("compute_risk", [](TaskContext ctx) {
        if (ctx.has("llm_response")) {
            try {
                auto j = nlohmann::json::parse(extractJson(ctx.get("llm_response").get<std::string>()));
                ctx.set("risk_profile", j);
            } catch (...) {
                ctx.set("risk_profile", ctx.get("llm_response"));
            }
        }
        return ctx;
    });

    g.edge(read_file, detect_format);
    g.branch(detect_format, "smali", file_signals);
    g.branch(detect_format, "elf", split_methods);  // ELF skips file_signals (smali-specific)
    g.branch(detect_format, "unsupported", unsupported);

    g.edge(file_signals, split_methods);
    g.edge(split_methods, static_enrich);
    g.branch(split_methods, "collect", collector);
    g.edge(static_enrich, triage);

    g.edge(triage, filter);
    g.branch(filter, "pass", rag_enrich);
    g.branch(filter, "fail", discard_irrelevant);
    g.edge(rag_enrich, deep_analysis);
    g.edge(collector, synthesize);
    g.edge(synthesize, risk_calc);

    g.setEntry(read_file);
    g.setOutput(risk_calc);

    return g;
}

} // namespace area::graph
