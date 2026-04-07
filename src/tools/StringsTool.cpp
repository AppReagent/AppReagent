#include "tools/StringsTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace area {

// Base64 decode (returns empty string on invalid input)
static std::string base64Decode(const std::string& encoded) {
    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (encoded.size() < 8) return "";

    // Validate
    for (char c : encoded) {
        if (c != '=' && chars.find(c) == std::string::npos) return "";
    }

    std::string result;
    int val = 0, bits = -8;
    for (char c : encoded) {
        if (c == '=') break;
        auto pos = chars.find(c);
        if (pos == std::string::npos) return "";
        val = (val << 6) | (int)pos;
        bits += 6;
        if (bits >= 0) {
            result += char((val >> bits) & 0xFF);
            bits -= 8;
        }
    }

    // Validate decoded output is printable text
    for (char c : result) {
        if (c != '\n' && c != '\r' && c != '\t' && (c < 0x20 || c > 0x7e))
            return ""; // binary content, not useful as decoded string
    }
    return result;
}

// Detect obfuscation-related smali patterns in a line
struct ObfuscationIndicator {
    std::string type;   // "xor_cipher", "string_building", "reflection_setup", "native_bridge", "anti_analysis"
    std::string detail;
    int line;
};

static std::string toLowerST(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

static bool shouldSkipDirST(const std::string& name) {
    return name == ".git" || name == "node_modules" || name == ".cache" ||
           name == "__pycache__" || name == ".gradle" || name == "build" ||
           name == ".idea" || name == ".vscode";
}

struct ExtractedString {
    std::string file;
    int line;
    std::string value;
    std::string context; // what kind of string (const-string, field, xml attr, etc.)
};

// Extract string from smali const-string line:
//   const-string v0, "hello world"
//   const-string/jumbo v0, "hello world"
static std::string extractConstString(const std::string& line) {
    // Find the opening quote after the comma
    auto commaPos = line.find(',');
    if (commaPos == std::string::npos) return "";

    auto quoteStart = line.find('"', commaPos);
    if (quoteStart == std::string::npos) return "";

    // Find matching close quote (handle escaped quotes)
    std::string result;
    for (size_t i = quoteStart + 1; i < line.size(); i++) {
        if (line[i] == '\\' && i + 1 < line.size()) {
            result += line[i];
            result += line[i + 1];
            i++;
        } else if (line[i] == '"') {
            return result;
        } else {
            result += line[i];
        }
    }
    return result;
}

// Extract string from XML android:name="..." or similar attributes
static std::vector<std::string> extractXmlStrings(const std::string& line) {
    std::vector<std::string> results;
    size_t pos = 0;
    while (pos < line.size()) {
        auto qStart = line.find('"', pos);
        if (qStart == std::string::npos) break;
        auto qEnd = line.find('"', qStart + 1);
        if (qEnd == std::string::npos) break;
        std::string val = line.substr(qStart + 1, qEnd - qStart - 1);
        if (!val.empty() && val.size() > 2) { // skip very short strings
            results.push_back(val);
        }
        pos = qEnd + 1;
    }
    return results;
}

// Classify a string for interest
static bool isInteresting(const std::string& s) {
    if (s.size() < 3) return false;
    std::string lower = toLowerST(s);

    // URLs (including mining pool protocols)
    if (lower.starts_with("http://") || lower.starts_with("https://") ||
        lower.starts_with("ftp://") || lower.starts_with("ws://") ||
        lower.starts_with("wss://") || lower.starts_with("stratum://") ||
        lower.starts_with("stratum+tcp://") || lower.starts_with("stratum+ssl://")) return true;

    // Telegram bot API URLs
    if (lower.find("api.telegram.org/bot") != std::string::npos) return true;

    // IP addresses (rough check)
    if (s.find('.') != std::string::npos) {
        int dots = 0, digits = 0;
        for (char c : s) {
            if (c == '.') dots++;
            if (std::isdigit(c)) digits++;
        }
        if (dots == 3 && digits >= 4) return true;
    }

    // File paths
    if (lower.find('/') != std::string::npos && lower.size() > 5) return true;

    // Domain-like strings
    if (lower.find(".com") != std::string::npos || lower.find(".net") != std::string::npos ||
        lower.find(".org") != std::string::npos || lower.find(".io") != std::string::npos ||
        lower.find(".ru") != std::string::npos || lower.find(".cn") != std::string::npos ||
        lower.find(".top") != std::string::npos || lower.find(".xyz") != std::string::npos ||
        lower.find(".onion") != std::string::npos) return true;

    // Dynamic DNS domains (common in malware C2)
    if (lower.find(".duckdns.org") != std::string::npos ||
        lower.find(".no-ip.com") != std::string::npos ||
        lower.find(".no-ip.org") != std::string::npos ||
        lower.find(".ddns.net") != std::string::npos ||
        lower.find(".hopto.org") != std::string::npos ||
        lower.find(".zapto.org") != std::string::npos ||
        lower.find(".sytes.net") != std::string::npos) return true;

    // Content URIs
    if (lower.starts_with("content://")) return true;

    // Bitcoin addresses (bc1, 1, 3 prefixed, 26-62 chars)
    if ((s.starts_with("bc1") || s.starts_with("1") || s.starts_with("3")) && s.size() >= 26 && s.size() <= 62) {
        bool validBtc = true;
        for (char c : s) {
            if (!std::isalnum(c)) { validBtc = false; break; }
        }
        if (validBtc) return true;
    }

    // Ethereum addresses (0x followed by 40 hex chars)
    if (s.starts_with("0x") && s.size() == 42) {
        bool validEth = true;
        for (size_t i = 2; i < s.size(); i++) {
            if (!std::isxdigit(s[i])) { validEth = false; break; }
        }
        if (validEth) return true;
    }

    // Monero addresses (start with 4, 95 chars)
    if (s.starts_with("4") && s.size() == 95) {
        bool validXmr = true;
        for (char c : s) {
            if (!std::isalnum(c)) { validXmr = false; break; }
        }
        if (validXmr) return true;
    }

    // Package names
    if (std::count(lower.begin(), lower.end(), '.') >= 2 && lower.find(' ') == std::string::npos) return true;

    // Crypto/encoding keywords
    if (lower.find("aes") != std::string::npos || lower.find("rsa") != std::string::npos ||
        lower.find("sha") != std::string::npos || lower.find("md5") != std::string::npos ||
        lower.find("base64") != std::string::npos || lower.find("cipher") != std::string::npos ||
        lower.find("hmac") != std::string::npos || lower.find("pkcs") != std::string::npos) return true;

    // SQL
    if (lower.find("select ") != std::string::npos || lower.find("insert ") != std::string::npos ||
        lower.find("create table") != std::string::npos) return true;

    // Commands/shell
    if (lower.starts_with("su") || lower.find("/bin/") != std::string::npos ||
        lower.find("chmod") != std::string::npos || lower.find("/system/") != std::string::npos ||
        lower.find("runtime.exec") != std::string::npos) return true;

    // Suspicious file extensions
    if (lower.ends_with(".dex") || lower.ends_with(".apk") || lower.ends_with(".jar") ||
        lower.ends_with(".so") || lower.ends_with(".locked") || lower.ends_with(".encrypted") ||
        lower.ends_with(".enc")) return true;

    // Base64-like (long alphanumeric strings)
    if (s.size() > 20) {
        bool allAlnum = true;
        for (char c : s) {
            if (!std::isalnum(c) && c != '+' && c != '/' && c != '=') {
                allAlnum = false;
                break;
            }
        }
        if (allAlnum) return true;
    }

    // Hex-encoded strings (potential encrypted payloads or keys)
    if (s.size() >= 16 && s.size() % 2 == 0) {
        bool allHex = true;
        for (char c : s) {
            if (!std::isxdigit(c)) { allHex = false; break; }
        }
        if (allHex) return true;
    }

    // Any string longer than 10 chars could be interesting
    if (s.size() > 10) return true;

    return false;
}

std::optional<ToolResult> StringsTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("STRINGS:") != 0)
        return std::nullopt;

    std::string args = action.substr(8);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a path after STRINGS:"};
    }

    // Parse: path | filter
    std::string path, filter;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        path = args.substr(0, pipePos);
        filter = args.substr(pipePos + 1);
        while (!path.empty() && path.back() == ' ') path.pop_back();
        while (!filter.empty() && filter[0] == ' ') filter.erase(0, 1);
        while (!filter.empty() && filter.back() == ' ') filter.pop_back();
    } else {
        path = args;
    }

    if (!path.empty() && path[0] == '~') {
        if (auto home = std::getenv("HOME")) {
            path = std::string(home) + path.substr(1);
        }
    }

    if (!fs::exists(path)) {
        return ToolResult{"OBSERVATION: Path not found: " + path};
    }

    ctx.cb({AgentMessage::THINKING, "Extracting strings from " + path + "..."});

    std::string filterLower = toLowerST(filter);
    std::vector<ExtractedString> strings;
    std::set<std::string> seen; // deduplicate
    int filesProcessed = 0;
    static constexpr int MAX_FILES = 50000;
    static constexpr int MAX_STRINGS = 200;
    static constexpr int MAX_MS = 10000;
    auto startTime = std::chrono::steady_clock::now();
    bool truncated = false;

    std::vector<ObfuscationIndicator> obfuscationIndicators;

    auto processFile = [&](const fs::path& filePath) {
        if ((int)strings.size() >= MAX_STRINGS) { truncated = true; return; }

        std::string ext = filePath.extension().string();
        for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));

        std::error_code ec;
        auto fsize = fs::file_size(filePath, ec);
        if (ec || fsize > 2 * 1024 * 1024) return;

        filesProcessed++;

        std::ifstream file(filePath);
        if (!file.is_open()) return;

        std::string line;
        int lineNum = 0;
        while (std::getline(file, line)) {
            lineNum++;
            if ((int)strings.size() >= MAX_STRINGS) { truncated = true; return; }

            std::string lineLower = toLowerST(line);

            if (ext == ".smali") {
                // Detect obfuscation patterns in smali
                if (lineLower.find("xor-int") != std::string::npos) {
                    obfuscationIndicators.push_back({"xor_cipher",
                        "XOR operation: " + line, lineNum});
                }
                if (lineLower.find("invoke-virtual") != std::string::npos &&
                    (lineLower.find("class;->forname") != std::string::npos ||
                     lineLower.find("method;->invoke") != std::string::npos ||
                     lineLower.find("->setaccessible") != std::string::npos)) {
                    obfuscationIndicators.push_back({"reflection_setup",
                        "Reflection call: " + line, lineNum});
                }
                if (lineLower.find("invoke-static") != std::string::npos &&
                    lineLower.find("class;->forname") != std::string::npos) {
                    obfuscationIndicators.push_back({"reflection_setup",
                        "Dynamic class loading via forName: " + line, lineNum});
                }
                if (lineLower.find(".method") != std::string::npos &&
                    lineLower.find("native") != std::string::npos) {
                    obfuscationIndicators.push_back({"native_bridge",
                        "Native method declaration: " + line, lineNum});
                }
                if (lineLower.find("loadlibrary") != std::string::npos ||
                    lineLower.find("dexclassloader") != std::string::npos ||
                    lineLower.find("inmemorydexclassloader") != std::string::npos) {
                    obfuscationIndicators.push_back({"dynamic_loading",
                        "Dynamic code loading: " + line, lineNum});
                }
                if (lineLower.find("build;->fingerprint") != std::string::npos ||
                    lineLower.find("isdebuggerconnected") != std::string::npos ||
                    lineLower.find("tracerpid") != std::string::npos) {
                    obfuscationIndicators.push_back({"anti_analysis",
                        "Anti-analysis check: " + line, lineNum});
                }
                if (lineLower.find("stringbuilder") != std::string::npos &&
                    lineLower.find("append") != std::string::npos) {
                    obfuscationIndicators.push_back({"string_building",
                        "String construction via StringBuilder: " + line, lineNum});
                }

                // Extract const-string values
                if (lineLower.find("const-string") != std::string::npos) {
                    std::string val = extractConstString(line);
                    if (!val.empty() && seen.insert(val).second) {
                        if (!filter.empty() && toLowerST(val).find(filterLower) == std::string::npos)
                            continue;
                        if (filter.empty() && !isInteresting(val)) continue;
                        strings.push_back({filePath.string(), lineNum, val, "const-string"});
                    }
                }
            } else if (ext == ".xml") {
                auto xmlStrings = extractXmlStrings(line);
                for (auto& val : xmlStrings) {
                    if (!val.empty() && seen.insert(val).second) {
                        if (!filter.empty() && toLowerST(val).find(filterLower) == std::string::npos)
                            continue;
                        if (filter.empty() && !isInteresting(val)) continue;
                        strings.push_back({filePath.string(), lineNum, val, "xml-attr"});
                    }
                }
            } else {
                // For other files, extract quoted strings
                size_t pos = 0;
                while (pos < line.size()) {
                    char q = 0;
                    if (line[pos] == '"') q = '"';
                    else if (line[pos] == '\'') q = '\'';

                    if (q) {
                        auto end = line.find(q, pos + 1);
                        if (end != std::string::npos) {
                            std::string val = line.substr(pos + 1, end - pos - 1);
                            if (!val.empty() && val.size() > 2 && seen.insert(val).second) {
                                if (!filter.empty() && toLowerST(val).find(filterLower) == std::string::npos) {
                                    pos = end + 1;
                                    continue;
                                }
                                if (filter.empty() && !isInteresting(val)) {
                                    pos = end + 1;
                                    continue;
                                }
                                strings.push_back({filePath.string(), lineNum, val, "string-literal"});
                            }
                            pos = end + 1;
                            continue;
                        }
                    }
                    pos++;
                }
            }
        }
    };

    if (fs::is_regular_file(path)) {
        processFile(path);
    } else {
        std::error_code ec;
        auto it = fs::recursive_directory_iterator(
            path, fs::directory_options::skip_permission_denied, ec);
        for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (truncated || filesProcessed > MAX_FILES) { truncated = true; break; }
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed > MAX_MS) { truncated = true; break; }

            if (it->is_directory(ec) && !ec && shouldSkipDirST(it->path().filename().string())) {
                it.disable_recursion_pending();
                continue;
            }
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec) || ec) { ec.clear(); continue; }

            std::string ext = it->path().extension().string();
            for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));
            if (ext != ".smali" && ext != ".xml" && ext != ".java" && ext != ".kt" &&
                ext != ".json" && ext != ".properties" && ext != ".txt") continue;

            processFile(it->path());
        }
    }

    if (strings.empty()) {
        std::string obs = "OBSERVATION: No strings found in " + path;
        if (!filter.empty()) obs += " matching \"" + filter + "\"";
        return ToolResult{obs + "."};
    }

    // Categorize strings
    struct Category {
        std::string name;
        std::vector<ExtractedString*> items;
    };
    std::vector<Category> categories;
    auto addToCategory = [&](const std::string& name, ExtractedString* s) {
        for (auto& cat : categories) {
            if (cat.name == name) { cat.items.push_back(s); return; }
        }
        categories.push_back({name, {s}});
    };

    for (auto& s : strings) {
        std::string lower = toLowerST(s.value);
        if (lower.starts_with("stratum://") || lower.starts_with("stratum+tcp://") ||
            lower.starts_with("stratum+ssl://")) {
            addToCategory("Mining Pool URLs", &s);
        } else if (lower.starts_with("http://") || lower.starts_with("https://") ||
            lower.starts_with("ftp://") || lower.starts_with("ws://")) {
            // Sub-categorize URLs
            if (lower.find("api.telegram.org/bot") != std::string::npos) {
                addToCategory("Telegram Bot APIs", &s);
            } else {
                addToCategory("URLs", &s);
            }
        } else if (lower.starts_with("content://")) {
            addToCategory("Content URIs", &s);
        } else if (lower.find("/bin/") != std::string::npos || lower == "su" ||
                   lower.find("chmod") != std::string::npos || lower.find("/system/") != std::string::npos) {
            addToCategory("Shell/Commands", &s);
        } else if (lower.find("select ") != std::string::npos ||
                   lower.find("insert ") != std::string::npos ||
                   lower.find("create table") != std::string::npos) {
            addToCategory("SQL", &s);
        } else if ([&]() {
            // Bitcoin addresses
            if ((s.value.starts_with("bc1") || s.value.starts_with("1") || s.value.starts_with("3"))
                && s.value.size() >= 26 && s.value.size() <= 62) {
                bool valid = true;
                for (char c : s.value) if (!std::isalnum(c)) { valid = false; break; }
                if (valid) return true;
            }
            // Ethereum addresses
            if (s.value.starts_with("0x") && s.value.size() == 42) {
                bool valid = true;
                for (size_t i = 2; i < s.value.size(); i++) if (!std::isxdigit(s.value[i])) { valid = false; break; }
                if (valid) return true;
            }
            // Monero addresses
            if (s.value.starts_with("4") && s.value.size() == 95) {
                bool valid = true;
                for (char c : s.value) if (!std::isalnum(c)) { valid = false; break; }
                if (valid) return true;
            }
            return false;
        }()) {
            addToCategory("Crypto Wallets", &s);
        } else if ([&]() {
            int digits = 0;
            for (char c : s.value) if (std::isdigit(c)) digits++;
            if (digits < 7) return false;
            for (char c : s.value)
                if (!std::isdigit(c) && c != '+' && c != '-' && c != '(' && c != ')' && c != ' ')
                    return false;
            return true;
        }()) {
            addToCategory("Phone Numbers", &s);
        } else if (lower.find(".duckdns.org") != std::string::npos ||
                   lower.find(".no-ip.com") != std::string::npos ||
                   lower.find(".ddns.net") != std::string::npos ||
                   lower.find(".hopto.org") != std::string::npos ||
                   lower.find(".zapto.org") != std::string::npos ||
                   lower.find(".sytes.net") != std::string::npos ||
                   lower.find(".onion") != std::string::npos) {
            addToCategory("Dynamic DNS / Suspicious Domains", &s);
        } else if (lower.find("java.lang.runtime") != std::string::npos ||
                   lower.find("java.lang.processbuilder") != std::string::npos ||
                   lower.find("java.lang.class") != std::string::npos ||
                   lower.find("java.lang.reflect") != std::string::npos ||
                   lower.find("dalvik.system.dexclassloader") != std::string::npos ||
                   lower.find("dalvik.system.pathclassloader") != std::string::npos ||
                   lower.find("dalvik.system.inmemorydexclassloader") != std::string::npos) {
            addToCategory("Reflection Targets", &s);
        } else if (lower.find("aes") != std::string::npos || lower.find("rsa") != std::string::npos ||
                   lower.find("des/") != std::string::npos || lower.find("pkcs") != std::string::npos ||
                   lower.find("hmac") != std::string::npos || lower.find("sha1") != std::string::npos ||
                   lower.find("sha256") != std::string::npos || lower.find("md5") != std::string::npos ||
                   lower.find("cipher") != std::string::npos) {
            addToCategory("Crypto/Encoding", &s);
        } else if (lower.ends_with(".dex") || lower.ends_with(".apk") || lower.ends_with(".jar") ||
                   lower.ends_with(".so") || lower.ends_with(".locked") || lower.ends_with(".encrypted")) {
            addToCategory("Suspicious File Extensions", &s);
        } else {
            // Try Base64 decode for long alphanumeric strings
            bool categorized = false;
            if (s.value.size() >= 12) {
                bool looksBase64 = true;
                for (char c : s.value) {
                    if (!std::isalnum(c) && c != '+' && c != '/' && c != '=') {
                        looksBase64 = false;
                        break;
                    }
                }
                if (looksBase64) {
                    std::string decoded = base64Decode(s.value);
                    if (!decoded.empty() && decoded.size() >= 4) {
                        s.context += " [Base64 decoded: \"" + decoded.substr(0, 120) + "\"]";
                        // Re-check if decoded content reveals a URL, IP, or other indicator
                        std::string decodedLower = toLowerST(decoded);
                        if (decodedLower.starts_with("http://") || decodedLower.starts_with("https://") ||
                            decodedLower.find(".com") != std::string::npos ||
                            decodedLower.find(".net") != std::string::npos) {
                            addToCategory("Encoded URLs (Base64)", &s);
                        } else if (decodedLower.find("/bin/") != std::string::npos ||
                                   decodedLower.find("chmod") != std::string::npos ||
                                   decodedLower == "su") {
                            addToCategory("Encoded Commands (Base64)", &s);
                        } else {
                            addToCategory("Encoded Strings (Base64)", &s);
                        }
                        categorized = true;
                    }
                }
            }

            // Check for hex-encoded strings (potential keys, encrypted payloads)
            if (!categorized && s.value.size() >= 32 && s.value.size() % 2 == 0) {
                bool allHex = true;
                for (char c : s.value) {
                    if (!std::isxdigit(c)) { allHex = false; break; }
                }
                if (allHex) {
                    addToCategory("Hex-Encoded Data", &s);
                    categorized = true;
                }
            }

            if (!categorized) {
                addToCategory("Other", &s);
            }
        }
    }

    std::ostringstream out;
    out << strings.size() << " string(s) extracted from " << filesProcessed << " file(s)";
    if (!filter.empty()) out << " matching \"" << filter << "\"";
    out << ":\n\n";

    for (auto& cat : categories) {
        out << "== " << cat.name << " (" << cat.items.size() << ") ==\n";
        for (auto* s : cat.items) {
            std::string display = s->value;
            if (display.size() > 150) display = display.substr(0, 150) + "...";
            out << "  \"" << display << "\"\n";
            out << "    " << s->file << ":" << s->line << " (" << s->context << ")\n";
        }
        out << "\n";
    }

    // Output obfuscation indicators if any were found
    if (!obfuscationIndicators.empty()) {
        // Deduplicate by type
        std::map<std::string, std::vector<ObfuscationIndicator*>> byType;
        for (auto& ind : obfuscationIndicators) {
            byType[ind.type].push_back(&ind);
        }
        out << "== Obfuscation Indicators ==\n";
        for (auto& [type, indicators] : byType) {
            std::string label = type;
            if (type == "xor_cipher") label = "XOR Cipher Operations";
            else if (type == "reflection_setup") label = "Reflection/Dynamic Dispatch";
            else if (type == "native_bridge") label = "Native Method Bridges";
            else if (type == "dynamic_loading") label = "Dynamic Code Loading";
            else if (type == "anti_analysis") label = "Anti-Analysis Checks";
            else if (type == "string_building") label = "Runtime String Construction";

            out << "  " << label << " (" << indicators.size() << " occurrence"
                << (indicators.size() > 1 ? "s" : "") << "):\n";
            int shown = 0;
            for (auto* ind : indicators) {
                if (shown >= 5) {
                    out << "    ... and " << (indicators.size() - shown) << " more\n";
                    break;
                }
                std::string detail = ind->detail;
                if (detail.size() > 120) detail = detail.substr(0, 120) + "...";
                out << "    line " << ind->line << ": " << detail << "\n";
                shown++;
            }
        }
        out << "\n";
    }

    if (truncated) {
        out << "(results truncated at " << MAX_STRINGS << " strings)\n";
    }

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{"OBSERVATION: " + result};
}

} // namespace area
