#include "features/ghidra/GhidraTool.h"

#include <unistd.h>

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <system_error>
#include <vector>

#include "infra/agent/Agent.h"
#include "infra/tools/ToolContext.h"
#include "nlohmann/detail/iterators/iter_impl.hpp"
#include <nlohmann/json.hpp>
#include "util/file_io.h"
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace area {
namespace {
bool isValidMode(const std::string& mode) {
    return mode == "overview" || mode == "decompile" || mode == "disasm" || mode == "strings" ||
           mode == "imports" || mode == "xrefs" || mode == "function_at" ||
           mode == "data_at" || mode == "all";
}

bool isNamedFunction(const json& f) {
    auto name = f.value("name", "");
    return !name.empty() && !name.starts_with("FUN_") && !name.starts_with("thunk_") &&
           !name.starts_with("Ordinal_");
}

std::string joinCallsites(const json& refs) {
    if (!refs.is_array() || refs.empty()) return "none";

    std::ostringstream out;
    bool first = true;
    for (const auto& ref : refs) {
        if (!first) out << ", ";
        first = false;
        out << ref.value("function", "?") << " @ " << ref.value("from", "?");
        auto type = ref.value("type", "");
        if (!type.empty()) out << " [" << type << "]";
    }
    return out.str();
}

std::string joinNamedAddresses(const json& items, const char* nameKey, const char* addressKey) {
    if (!items.is_array() || items.empty()) return "none";

    std::ostringstream out;
    bool first = true;
    for (const auto& item : items) {
        if (!first) out << ", ";
        first = false;
        out << item.value(nameKey, "?") << " @ " << item.value(addressKey, "?");
    }
    return out.str();
}

void appendReferenceFunctionSummaries(std::ostringstream& out,
                                      const std::string& title,
                                      const json& summaries) {
    if (!summaries.is_array() || summaries.empty()) return;

    out << "\n--- " << title << " (" << summaries.size() << ") ---\n";
    for (const auto& summary : summaries) {
        out << "  " << summary.value("function", "?")
            << " @ " << summary.value("address", "?");
        auto signature = summary.value("signature", "");
        if (!signature.empty()) out << " - " << signature;
        out << "\n";

        auto callsites = summary.value("callsites", json::array());
        if (callsites.is_array() && !callsites.empty()) {
            out << "    callsites (" << summary.value("callsite_count", callsites.size())
                << "): ";
            bool first = true;
            for (const auto& callsite : callsites) {
                if (!first) out << ", ";
                first = false;
                out << callsite.get<std::string>();
            }
            out << "\n";
        }

        auto callees = summary.value("callees", json::array());
        if (callees.is_array() && !callees.empty()) {
            out << "    direct callees: "
                << joinNamedAddresses(callees, "name", "address") << "\n";
        }
    }
}

std::vector<unsigned char> parseHexBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    std::istringstream stream(hex);
    std::string token;
    while (stream >> token) {
        char* end = nullptr;
        unsigned int value = std::strtoul(token.c_str(), &end, 16);
        if (end == token.c_str() || *end != '\0' || value > 0xFF) continue;
        bytes.push_back(static_cast<unsigned char>(value));
    }
    return bytes;
}

bool isMostlyPrintableByte(unsigned char c) {
    return (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t';
}

std::string printablePreview(const std::vector<unsigned char>& bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (unsigned char c : bytes) {
        if (c >= 32 && c <= 126) out.push_back(static_cast<char>(c));
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out.push_back('.');
    }
    return out;
}

std::string trimPreview(std::string s) {
    while (!s.empty() && (s.back() == '.' || std::isspace(static_cast<unsigned char>(s.back())))) {
        s.pop_back();
    }
    return s;
}

double xorCandidateScore(const std::vector<unsigned char>& decoded) {
    if (decoded.size() < 6) return -1.0;

    int printable = 0;
    int letters = 0;
    int spaces = 0;
    int bad = 0;
    for (unsigned char c : decoded) {
        if (isMostlyPrintableByte(c)) {
            printable++;
            if (std::isalpha(c)) letters++;
            if (c == ' ' || c == '_' || c == '-' || c == '/' || c == ':' || c == '.') spaces++;
        } else {
            bad++;
        }
    }

    double printableRatio = static_cast<double>(printable) / decoded.size();
    if (printableRatio < 0.85) return -1.0;

    std::string lower = printablePreview(decoded);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });

    double score = printableRatio * 100.0;
    score += static_cast<double>(letters) / decoded.size() * 20.0;
    score += static_cast<double>(spaces) / decoded.size() * 10.0;
    score -= bad * 5.0;

    for (const std::string& needle : {
             "http", "ftp", "cmd", ".dll", ".exe", "this is", "plug_", "host:",
             "user-agent", "mutex", "service", "system"
         }) {
        if (lower.find(needle) != std::string::npos) score += 20.0;
    }

    return score;
}

struct XorDecodeCandidate {
    double score = -1.0;
    std::vector<int> key;
    std::string preview;
};

void considerXorCandidate(const std::vector<unsigned char>& bytes,
                          const std::vector<int>& key,
                          XorDecodeCandidate& best) {
    std::vector<unsigned char> decoded;
    decoded.reserve(bytes.size());
    for (size_t i = 0; i < bytes.size(); i++) {
        decoded.push_back(static_cast<unsigned char>(bytes[i] ^ key[i % key.size()]));
    }

    double score = xorCandidateScore(decoded);
    if (score <= best.score) return;

    std::string preview = trimPreview(printablePreview(decoded));
    if (preview.size() < 6) return;

    best.score = score;
    best.key = key;
    best.preview = preview;
}

std::string detectSingleByteXor(const std::string& hex) {
    auto bytes = parseHexBytes(hex);
    if (bytes.size() < 6) return "";

    XorDecodeCandidate bestSingle;
    XorDecodeCandidate bestRepeating;

    for (int key = 1; key < 256; key++) {
        considerXorCandidate(bytes, {key}, bestSingle);
    }
    for (int key0 = 1; key0 < 256; key0++) {
        for (int key1 = 1; key1 < 256; key1++) {
            considerXorCandidate(bytes, {key0, key1}, bestRepeating);
        }
    }

    XorDecodeCandidate best = bestSingle;
    if (bestRepeating.score >= 120.0 && bestRepeating.score > bestSingle.score + 15.0) {
        best = bestRepeating;
    }
    if (best.key.empty()) return "";

    if (best.preview.size() > 80) {
        best.preview.erase(80);
        best.preview += "...";
    }

    std::ostringstream out;
    if (best.key.size() == 1) {
        out << "Likely single-byte XOR decode: key 0x";
    } else {
        out << "Likely repeating-key XOR decode: key";
    }
    out << std::hex << std::uppercase;
    for (size_t i = 0; i < best.key.size(); i++) {
        if (best.key.size() > 1) out << " 0x";
        if (best.key[i] < 0x10) out << '0';
        out << best.key[i];
    }
    out << std::dec << " -> \"" << best.preview << "\"";
    return out.str();
}

bool looksLikeRecoveredString(const std::string& text) {
    if (text.size() < 4) return false;
    int printable = 0;
    int letters = 0;
    for (unsigned char c : text) {
        if (c >= 32 && c <= 126) printable++;
        if (std::isalpha(c)) letters++;
    }
    if (printable != static_cast<int>(text.size())) return false;
    if (letters < 3) return false;
    return text.find('/') != std::string::npos
        || text.find('\\') != std::string::npos
        || text.find('.') != std::string::npos
        || text.find(':') != std::string::npos
        || text.find('_') != std::string::npos
        || text.size() >= 6;
}

std::vector<std::string> extractStackStrings(const std::string& code) {
    std::map<std::string, std::map<int, unsigned char>> fragments;
    std::regex wideAssign(R"(([A-Za-z0-9_]+)(?:\._([0-9]+)_[0-9]+_)?\s*=\s*0x([0-9A-Fa-f]{2,16}))");
    std::smatch match;
    std::istringstream stream(code);
    std::string line;

    while (std::getline(stream, line)) {
        if (!std::regex_search(line, match, wideAssign)) continue;
        std::string name = match[1].str();
        int offset = match[2].matched ? std::stoi(match[2].str()) : 0;
        std::string hex = match[3].str();
        if (hex.size() % 2 != 0) hex = "0" + hex;

        for (size_t i = 0; i < hex.size() / 2; i++) {
            size_t pos = hex.size() - ((i + 1) * 2);
            unsigned int value = std::stoul(hex.substr(pos, 2), nullptr, 16);
            fragments[name][offset + static_cast<int>(i)] = static_cast<unsigned char>(value);
        }
    }

    std::vector<std::string> recovered;
    std::set<std::string> seen;
    for (const auto& [name, bytesByOffset] : fragments) {
        if (bytesByOffset.empty()) continue;
        int start = bytesByOffset.begin()->first;
        int end = bytesByOffset.rbegin()->first;
        std::string text;
        for (int offset = start; offset <= end; offset++) {
            auto it = bytesByOffset.find(offset);
            if (it == bytesByOffset.end()) break;
            unsigned char byte = it->second;
            if (byte == 0) break;
            text.push_back(static_cast<char>(byte));
        }
        if (!looksLikeRecoveredString(text)) continue;
        if (seen.insert(text).second) {
            recovered.push_back(text);
        }
    }
    return recovered;
}

int64_t parseIntegerLiteral(const std::string& text, bool& ok) {
    ok = false;
    if (text.empty()) return 0;
    try {
        size_t consumed = 0;
        int base = 10;
        if (text.starts_with("0x") || text.starts_with("0X")) base = 16;
        int64_t value = std::stoll(text, &consumed, base);
        if (consumed != text.size()) return 0;
        ok = true;
        return value;
    } catch (...) {
        return 0;
    }
}

std::vector<std::string> extractSleepInsights(const std::string& code) {
    std::vector<std::string> notes;
    std::map<std::string, int64_t> atoiValues;
    std::regex atoiPattern(R"((\w+)\s*=\s*atoi\(([^)]*)\);)");
    std::regex embeddedNumber(R"(_([0-9]+)(?:_[0-9A-Fa-f]+)?(?:\s*\+\s*0x?[0-9A-Fa-f]+)?)");
    std::regex sleepMulPattern(R"(Sleep\((\w+)\s*\*\s*(0x[0-9A-Fa-f]+|[0-9]+)\);)");
    std::regex sleepConstPattern(R"(Sleep\((0x[0-9A-Fa-f]+|[0-9]+)\);)");
    std::smatch match;
    std::istringstream stream(code);
    std::string line;

    while (std::getline(stream, line)) {
        if (std::regex_search(line, match, atoiPattern)) {
            std::smatch numMatch;
            std::string source = match[2].str();
            if (std::regex_search(source, numMatch, embeddedNumber)) {
                atoiValues[match[1].str()] = std::stoll(numMatch[1].str());
            }
        } else if (std::regex_search(line, match, sleepMulPattern)) {
            auto it = atoiValues.find(match[1].str());
            bool ok = false;
            int64_t multiplier = parseIntegerLiteral(match[2].str(), ok);
            if (it != atoiValues.end() && ok) {
                notes.push_back("Likely sleep duration: "
                    + std::to_string(it->second * multiplier) + " ms");
            }
        } else if (std::regex_search(line, match, sleepConstPattern)) {
            bool ok = false;
            int64_t value = parseIntegerLiteral(match[1].str(), ok);
            if (ok) {
                notes.push_back("Likely sleep duration: " + std::to_string(value) + " ms");
            }
        }
    }

    return notes;
}

std::string joinPreviewList(const std::vector<std::string>& items, size_t limit) {
    std::ostringstream out;
    bool first = true;
    for (size_t i = 0; i < items.size() && i < limit; i++) {
        if (!first) out << ", ";
        first = false;
        out << items[i];
    }
    if (items.size() > limit) out << ", ...";
    return out.str();
}

std::string cleanSymbolToken(std::string token) {
    while (!token.empty() && token.back() == '_') token.pop_back();
    while (!token.empty() && token.front() == '_') token.erase(0, 1);
    return token;
}

std::vector<std::string> extractComparedCommandNames(const std::string& code) {
    std::vector<std::string> commands;
    std::set<std::string> seen;
    std::regex cmpPattern(
        R"((?:strn?cmp\([^,]+,\s*s_|memcmp\([^,]+,\s*s_)([A-Za-z0-9_]+)_[0-9A-Fa-f]{6,}\s*,)");
    std::smatch match;
    std::istringstream stream(code);
    std::string line;

    while (std::getline(stream, line)) {
        if (!std::regex_search(line, match, cmpPattern)) continue;
        std::string token = cleanSymbolToken(match[1].str());
        if (token.size() < 4) continue;
        if (seen.insert(token).second) commands.push_back(token);
    }

    return commands;
}

std::vector<std::string> extractBehaviorInsights(const std::string& code) {
    std::vector<std::string> notes;
    auto commands = extractComparedCommandNames(code);
    if (code.find(" - DAT_") != std::string::npos
        && code.find("strncmp((char *)") != std::string::npos
        && !commands.empty()) {
        notes.push_back("Likely decoded command loop: " + joinPreviewList(commands, 6));
    }
    if (!commands.empty() && code.find("CreatePipe(") != std::string::npos) {
        notes.push_back("Likely command dispatcher: " + joinPreviewList(commands, 8));
    }

    if ((code.find("LoadLibraryA(") != std::string::npos
         || code.find("LoadLibrary(") != std::string::npos)
        && code.find("GetProcAddress(") != std::string::npos) {
        std::regex procPattern(R"(GetProcAddress\([^,]+,\s*s_([A-Za-z0-9_]+)_[0-9A-Fa-f]{6,}\))");
        std::smatch match;
        if (std::regex_search(code, match, procPattern)) {
            notes.push_back("Dynamic API/plugin load: LoadLibraryA + GetProcAddress(\""
                + cleanSymbolToken(match[1].str()) + "\")");
        } else {
            notes.push_back("Dynamic API/plugin load: LoadLibraryA + GetProcAddress");
        }
    }

    if (code.find("Ordinal_23()") != std::string::npos
        && code.find("printf(s_socket___GetLastError_reports") != std::string::npos) {
        notes.push_back("Likely socket command channel: socket creation path with command recv/send loop");
    }
    if (code.find("CreatePipe(") != std::string::npos
        && code.find("CreateProcessA(") != std::string::npos) {
        if (code.find("s__cmd_exe__c_") != std::string::npos
            || code.find("s__command_exe__c_") != std::string::npos) {
            notes.push_back("Likely command shell launcher: CreatePipe + CreateProcessA via \"\\\\cmd.exe /c \"");
        } else {
            notes.push_back("Likely command shell launcher: CreatePipe + CreateProcessA");
        }
    }
    if (code.find("s_iexplore_exe_") != std::string::npos) {
        notes.push_back("Default injection target: iexplore.exe");
    }

    return notes;
}

std::vector<std::string> extractDisassemblyInsights(const json& instructions) {
    std::vector<std::string> notes;
    if (!instructions.is_array() || instructions.empty()) return notes;

    int targetIndex = -1;
    for (size_t i = 0; i < instructions.size(); i++) {
        if (instructions[i].value("is_target", false)) {
            targetIndex = static_cast<int>(i);
            break;
        }
    }

    std::regex pushPattern(R"(^PUSH (0x[0-9A-Fa-f]+|[0-9]+)$)");
    std::regex imulPattern(R"(^IMUL ([A-Z]+),[A-Z]+,(0x[0-9A-Fa-f]+|[0-9]+)$)");
    std::smatch match;
    auto appendImmediateArgs = [&](int callIndex) {
        std::vector<int64_t> args;
        std::string pushedRegister;

        for (int i = callIndex - 1; i >= 0 && callIndex - i <= 8; i--) {
            std::string text = instructions[i].value("text", "");
            if (std::regex_match(text, match, pushPattern)) {
                bool ok = false;
                int64_t value = parseIntegerLiteral(match[1].str(), ok);
                if (!ok) break;
                args.push_back(value);
                continue;
            }
            if (text.starts_with("PUSH ")) {
                pushedRegister = text.substr(5);
                break;
            }
            if (!args.empty()) break;
        }

        if (!args.empty()) {
            std::ostringstream out;
            out << "Immediate call arguments: ";
            for (size_t i = 0; i < args.size(); i++) {
                if (i > 0) out << ", ";
                out << "0x" << std::hex << std::uppercase << args[i] << std::dec;
            }
            notes.push_back(out.str());
            if (args.size() == 3 && args[0] == 2 && args[1] == 1 && args[2] == 6) {
                notes.push_back("Likely socket constants: AF_INET, SOCK_STREAM, IPPROTO_TCP");
            }
        }

        if (!pushedRegister.empty()) {
            for (int i = callIndex - 1; i >= 0 && callIndex - i <= 6; i--) {
                std::string text = instructions[i].value("text", "");
                if (!std::regex_match(text, match, imulPattern)) continue;
                if (match[1].str() != pushedRegister) continue;
                bool ok = false;
                int64_t value = parseIntegerLiteral(match[2].str(), ok);
                if (!ok) continue;
                notes.push_back("Computed call argument multiplier: 0x"
                    + [&]() {
                        std::ostringstream out;
                        out << std::hex << std::uppercase << value;
                        return out.str();
                    }() + " (" + std::to_string(value) + ")");
                break;
            }
        }
    };

    if (targetIndex >= 0) {
        appendImmediateArgs(targetIndex);
    }

    for (size_t i = 0; i < instructions.size(); i++) {
        if (static_cast<int>(i) == targetIndex) continue;
        std::string text = instructions[i].value("text", "");
        if (!text.starts_with("CALL ")) continue;

        std::vector<int64_t> args;
        for (int j = static_cast<int>(i) - 1; j >= 0 && static_cast<int>(i) - j <= 8; j--) {
            std::string prev = instructions[j].value("text", "");
            if (std::regex_match(prev, match, pushPattern)) {
                bool ok = false;
                int64_t value = parseIntegerLiteral(match[1].str(), ok);
                if (!ok) break;
                args.push_back(value);
                continue;
            }
            if (!args.empty()) break;
        }

        if (args.size() == 3 && args[0] == 2 && args[1] == 1 && args[2] == 6) {
            notes.push_back("Likely socket call @ "
                + instructions[i].value("address", "?")
                + ": AF_INET, SOCK_STREAM, IPPROTO_TCP");
            break;
        }
    }

    return notes;
}
}  // namespace

static std::string ghidraHome() {
    if (auto env = std::getenv("GHIDRA_HOME")) return env;

    std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/home/builder";

    std::string optDir = home + "/.local/opt";
    if (!fs::is_directory(optDir)) return "";
    for (auto& entry : fs::directory_iterator(optDir)) {
        auto name = entry.path().filename().string();
        if (name.starts_with("ghidra_") && entry.is_directory()) {
            return entry.path().string();
        }
    }
    return "";
}

static std::string javaHome() {
    if (auto env = std::getenv("JAVA_HOME")) return env;
    std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/home/builder";
    std::string optDir = home + "/.local/opt";
    if (!fs::is_directory(optDir)) return "";
    for (auto& entry : fs::directory_iterator(optDir)) {
        auto name = entry.path().filename().string();
        if (name.starts_with("jdk-") && entry.is_directory()) {
            return entry.path().string();
        }
    }
    return "";
}

static std::string scriptDir() {
    auto exe = util::selfExe();
    if (!exe.empty()) {
        auto dir = fs::path(exe).parent_path() / "scripts" / "ghidra";
        if (fs::exists(dir / "AreaAnalyze.java")) return dir.string();
    }
    if (fs::exists("/workspace/scripts/ghidra/AreaAnalyze.java"))
        return "/workspace/scripts/ghidra";
    return "";
}

static std::string runCmd(const std::string& cmd, int* exitCode = nullptr) {
    std::string result;
    std::string wrapped = cmd + " 2>&1";
    FILE* pipe = popen(wrapped.c_str(), "r");
    if (!pipe) {
        if (exitCode) *exitCode = -1;
        return "failed to execute command";
    }
    std::array<char, 4096> buf;
    while (fgets(buf.data(), buf.size(), pipe)) {
        result += buf.data();
    }
    int status = pclose(pipe);
    if (exitCode) *exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

static std::string truncate(const std::string& s, size_t maxLen) {
    if (s.size() <= maxLen) return s;
    return s.substr(0, maxLen) + "\n... (truncated, " + std::to_string(s.size()) + " bytes total)";
}

std::optional<ToolResult> GhidraTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("GHIDRA:"))
        return std::nullopt;

    std::string args = action.substr(7);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a file path.\n"
                          "Usage: GHIDRA: <path> [| <mode> [| <filter>]]\n"
                          "Modes: overview (default), decompile, disasm, strings, imports, xrefs, "
                          "function_at, data_at, all"};
    }

    std::string path, mode = "overview", filter;
    {
        auto p1 = args.find('|');
        if (p1 != std::string::npos) {
            path = args.substr(0, p1);
            std::string rest = args.substr(p1 + 1);
            while (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
            while (!rest.empty() && rest.back() == ' ') rest.pop_back();

            auto p2 = rest.find('|');
            if (p2 != std::string::npos) {
                mode = rest.substr(0, p2);
                filter = rest.substr(p2 + 1);
            } else {
                mode = rest;
            }
        } else {
            path = args;
        }
        while (!path.empty() && path.back() == ' ') path.pop_back();
        while (!mode.empty() && mode[0] == ' ') mode.erase(0, 1);
        while (!mode.empty() && mode.back() == ' ') mode.pop_back();
        while (!filter.empty() && filter[0] == ' ') filter.erase(0, 1);
        while (!filter.empty() && filter.back() == ' ') filter.pop_back();

        for (auto& c : mode) c = std::tolower(static_cast<unsigned char>(c));
    }

    if (!fs::exists(path)) {
        return ToolResult{"OBSERVATION: Error — file not found: " + path};
    }

    if (!isValidMode(mode)) {
        return ToolResult{"OBSERVATION: Error — unknown mode '" + mode + "'.\n"
                          "Valid modes: overview, decompile, disasm, strings, imports, xrefs, "
                          "function_at, data_at, all"};
    }

    if (auto envErr = checkEnvironment()) {
        return ToolResult{"OBSERVATION: Error — " + *envErr};
    }

    ctx.cb({AgentMessage::THINKING, "Running Ghidra " + mode + " analysis on " +
            fs::path(path).filename().string() + "..."});

    std::string tmpDir = "/tmp/area-ghidra-" + std::to_string(getpid());
    fs::create_directories(tmpDir);
    std::string outputPath = tmpDir + "/output.json";

    std::string ghidraLog;
    std::string err = runGhidra(path, mode, filter, outputPath, ghidraLog);
    if (!err.empty()) {
        std::error_code ec;
        fs::remove_all(tmpDir, ec);
        return ToolResult{"OBSERVATION: Ghidra analysis failed: " + err};
    }

    if (!fs::exists(outputPath)) {
        std::error_code ec;
        fs::remove_all(tmpDir, ec);
        return ToolResult{"OBSERVATION: Ghidra analysis produced no output. Log:\n" +
                          truncate(ghidraLog, 2000)};
    }

    std::string formatted;
    if (mode == "overview")        formatted = formatOverview(outputPath);
    else if (mode == "decompile")  formatted = formatDecompile(outputPath);
    else if (mode == "disasm")     formatted = formatDisasm(outputPath);
    else if (mode == "strings")    formatted = formatStrings(outputPath);
    else if (mode == "imports")    formatted = formatImports(outputPath);
    else if (mode == "xrefs")      formatted = formatXrefs(outputPath);
    else if (mode == "function_at") formatted = formatFunctionAt(outputPath);
    else if (mode == "data_at")    formatted = formatDataAt(outputPath);
    else if (mode == "all")        formatted = formatAll(outputPath);

    std::error_code ec;
    fs::remove_all(tmpDir, ec);

    formatted = truncate(formatted, 12000);
    ctx.cb({AgentMessage::RESULT, formatted});
    return ToolResult{"OBSERVATION: " + formatted};
}

std::string GhidraTool::runGhidra(const std::string& binaryPath,
                                   const std::string& mode,
                                   const std::string& filter,
                                   const std::string& outputPath,
                                   std::string& ghidraLog) {
    std::string gh = ghidraHome();
    std::string sd = scriptDir();
    bool useDocker = gh.empty() || !fs::exists(gh + "/support/analyzeHeadless");

    if (!useDocker && sd.empty())
        return "Ghidra scripts not found (scripts/ghidra/AreaAnalyze.java)";

    std::string projDir = "/tmp/area-ghidra-proj-" + std::to_string(getpid());
    fs::create_directories(projDir);

    std::ostringstream cmd;

    if (useDocker) {
        auto absInput = fs::absolute(binaryPath).string();
        auto absOutput = fs::absolute(fs::path(outputPath).parent_path()).string();
        auto outputFile = fs::path(outputPath).filename().string();

        if (sd.empty()) {
            auto exe = util::selfExe();
            if (!exe.empty()) {
                auto d = fs::path(exe).parent_path() / "scripts" / "ghidra";
                if (fs::exists(d / "AreaAnalyze.java")) sd = d.string();
            }
        }
        if (sd.empty()) return "Ghidra scripts not found (scripts/ghidra/AreaAnalyze.java)";

        cmd << "sudo docker run --rm"
            << " --user " << getuid() << ":" << getgid()
            << " -e HOME=/tmp"
            << " -v " << absInput << ":/input/" << fs::path(binaryPath).filename().string()
            << " -v " << sd << ":/scripts"
            << " -v " << absOutput << ":/output"
            << " -v " << projDir << ":/proj"
            << " area-ghidra"
            << " /proj AreaProject"
            << " -import /input/" << fs::path(binaryPath).filename().string()
            << " -postScript AreaAnalyze.java /output/" << outputFile << " " << mode;

        if (!filter.empty()) {
            std::string escaped;
            for (char c : filter) {
                if (c == '\'') escaped += "'\\''";
                else escaped += c;
            }
            cmd << " '" << escaped << "'";
        }

        cmd << " -scriptPath /scripts"
            << " -deleteproject"
            << " -analysisTimeoutPerFile 180";
    } else {
        std::string jh = javaHome();
        if (!jh.empty()) {
            cmd << "JAVA_HOME=" << jh << " PATH=" << jh << "/bin:$PATH ";
        }

        cmd << gh << "/support/analyzeHeadless"
            << " " << projDir << " AreaProject"
            << " -import " << binaryPath
            << " -postScript AreaAnalyze.java " << outputPath << " " << mode;

        if (!filter.empty()) {
            std::string escaped;
            for (char c : filter) {
                if (c == '\'') escaped += "'\\''";
                else escaped += c;
            }
            cmd << " '" << escaped << "'";
        }

        cmd << " -scriptPath " << sd
            << " -deleteproject"
            << " -analysisTimeoutPerFile 180";
    }

    int exitCode;
    ghidraLog = runCmd(cmd.str(), &exitCode);

    std::error_code ec;
    fs::remove_all(projDir, ec);

    if (ghidraLog.find("SCRIPT ERROR") != std::string::npos &&
        ghidraLog.find("AreaAnalyze: wrote") == std::string::npos) {
        return "Ghidra script error:\n" + truncate(ghidraLog, 2000);
    }

    if (ghidraLog.find("Import succeeded") == std::string::npos &&
        ghidraLog.find("Processing succeeded") == std::string::npos) {
        if (exitCode != 0) {
            return "Ghidra exited with code " + std::to_string(exitCode) +
                   ":\n" + truncate(ghidraLog, 2000);
        }
    }

    return "";
}

std::optional<std::string> GhidraTool::checkEnvironment() const {
    std::string gh = ghidraHome();
    bool useDocker = gh.empty() || !fs::exists(gh + "/support/analyzeHeadless");
    if (!useDocker) return std::nullopt;

    int rc;
    runCmd("sudo docker image inspect area-ghidra >/dev/null 2>&1", &rc);
    if (rc == 0) return std::nullopt;

    return "Ghidra not found locally and area-ghidra Docker image not available. "
           "Set GHIDRA_HOME, install Ghidra to ~/.local/opt/ghidra_*, or build "
           "the Docker image with: sudo docker build -t area-ghidra docker/ghidra/";
}

static json loadJson(const std::string& path) {
    std::ifstream f(path);
    if (!f) return json::object();
    try {
        return json::parse(f);
    } catch (...) {
        return json::object();
    }
}

std::string GhidraTool::formatOverview(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Analysis: " << meta.value("name", "?") << " ===\n"
        << "Format: " << meta.value("executable_format", "?") << "\n"
        << "Architecture: " << meta.value("language", "?") << "\n"
        << "Compiler: " << meta.value("compiler", "?") << "\n"
        << "Image base: " << meta.value("image_base", "?") << "\n"
        << "Functions: " << meta.value("function_count", 0) << "\n"
        << "Memory: " << meta.value("memory_size", 0) << " bytes\n";
    if (meta.contains("coff_timestamp_utc") && !meta.value("coff_timestamp_utc", "").empty()) {
        out << "PE timestamp: " << meta.value("coff_timestamp_utc", "?");
        if (meta.contains("coff_timestamp")) {
            out << " (" << meta.value("coff_timestamp", 0) << ")";
        }
        out << "\n";
    }
    if (meta.contains("packer_hint") && !meta.value("packer_hint", "").empty()) {
        out << "Packer hint: " << meta.value("packer_hint", "?") << "\n";
    }
    if (meta.contains("entry_point")) {
        out << "Entry point: " << meta.value("entry_point", "?");
        if (meta.value("is_dll", false)) out << " (DLL entry)";
        if (meta.contains("entry_function")) {
            out << " -> " << meta.value("entry_function", "?");
        }
        out << "\n";
        if (meta.contains("entry_signature")) {
            out << "Entry signature: " << meta.value("entry_signature", "") << "\n";
        }
        if (meta.contains("entry_callees") && meta["entry_callees"].is_array() &&
            !meta["entry_callees"].empty()) {
            out << "Entry direct callees:";
            bool first = true;
            for (const auto& callee : meta["entry_callees"]) {
                out << (first ? " " : ", ")
                    << callee.value("name", "?") << " @ " << callee.value("address", "?");
                first = false;
            }
            out << "\n";
        }
        if (meta.contains("likely_dllmain") && meta["likely_dllmain"].is_object()) {
            const auto& dllMain = meta["likely_dllmain"];
            out << "Likely DllMain: " << dllMain.value("name", "?")
                << " @ " << dllMain.value("address", "?")
                << " (direct callee of PE entry stub)\n";
        }
    }
    if (meta.contains("section_names") && meta["section_names"].is_array() &&
        !meta["section_names"].empty()) {
        out << "Sections:";
        bool first = true;
        for (const auto& section : meta["section_names"]) {
            out << (first ? " " : ", ") << section.get<std::string>();
            first = false;
        }
        out << "\n";
    }
    out << "\n";

    if (data.contains("functions") && data["functions"].is_array()) {
        std::vector<json> namedFuncs;
        for (const auto& f : data["functions"]) {
            if (isNamedFunction(f)) namedFuncs.push_back(f);
        }
        std::sort(namedFuncs.begin(), namedFuncs.end(), [](const json& a, const json& b) {
            auto scoreA = a.value("caller_count", 0) + a.value("callee_count", 0);
            auto scoreB = b.value("caller_count", 0) + b.value("callee_count", 0);
            if (scoreA != scoreB) return scoreA > scoreB;
            return a.value("name", "") < b.value("name", "");
        });

        if (!namedFuncs.empty()) {
            out << "--- Named Functions / Exports (" << namedFuncs.size() << ") ---\n";
            int shown = 0;
            for (const auto& f : namedFuncs) {
                if (shown++ >= 20) {
                    out << "  ... and " << (namedFuncs.size() - 20) << " more\n";
                    break;
                }
                out << "  " << f.value("name", "?")
                    << " @ " << f.value("address", "?")
                    << " — " << f.value("signature", "")
                    << " [callers:" << f.value("caller_count", 0)
                    << " callees:" << f.value("callee_count", 0) << "]\n";
            }
            out << "\n";
        }
    }

    if (data.contains("functions") && data["functions"].is_array()) {
        auto& funcs = data["functions"];
        out << "--- Functions (" << funcs.size() << " shown) ---\n";
        for (auto& f : funcs) {
            out << "  " << f.value("name", "?")
                << " @ " << f.value("address", "?")
                << " (" << f.value("size", 0) << " bytes)"
                << " — " << f.value("signature", "")
                << " [callers:" << f.value("caller_count", 0)
                << " callees:" << f.value("callee_count", 0) << "]\n";
        }
        out << "\n";
    }

    if (data.contains("imports") && data["imports"].is_array() && !data["imports"].empty()) {
        std::vector<json> imps;
        for (const auto& imp : data["imports"]) imps.push_back(imp);
        std::sort(imps.begin(), imps.end(), [](const json& a, const json& b) {
            if (a.value("caller_count", 0) != b.value("caller_count", 0)) {
                return a.value("caller_count", 0) > b.value("caller_count", 0);
            }
            return a.value("name", "") < b.value("name", "");
        });

        out << "--- Imports (" << imps.size() << ") ---\n";
        int shown = 0;
        for (const auto& imp : imps) {
            if (shown++ >= 50) {
                out << "  ... and " << (imps.size() - 50) << " more\n";
                break;
            }
            out << "  " << imp.value("name", "?");
            auto lib = imp.value("library", "");
            if (!lib.empty()) out << " [" << lib << "]";
            out << " @ " << imp.value("address", "?")
                << " [callers:" << imp.value("caller_count", 0) << "]\n";
        }
        out << "\n";
    }

    if (data.contains("exports") && data["exports"].is_array() && !data["exports"].empty()) {
        auto& exps = data["exports"];
        out << "--- Exports (" << exps.size() << ") ---\n";
        int shown = 0;
        for (auto& exp : exps) {
            if (shown++ >= 50) {
                out << "  ... and " << (exps.size() - 50) << " more\n";
                break;
            }
            out << "  " << exp.value("name", "?")
                << " @ " << exp.value("address", "?");
            auto sig = exp.value("signature", "");
            if (!sig.empty()) out << " — " << sig;
            out << "\n";
        }
    }

    out << "\nUse GHIDRA: <path> | function_at | 0xADDR to resolve a code address.\n"
        << "Use GHIDRA: <path> | data_at | 0xADDR to resolve a data address.\n"
        << "Use GHIDRA: <path> | disasm | 0xADDR for assembly around a code address.\n"
        << "Use GHIDRA: <path> | decompile [| funcname_or_0xADDR] for decompiled C code.\n";
    return out.str();
}

std::string GhidraTool::formatDecompile(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Decompilation: " << meta.value("name", "?") << " ===\n"
        << "Architecture: " << meta.value("language", "?") << "\n\n";

    if (data.contains("functions") && data["functions"].is_array()) {
        for (auto& f : data["functions"]) {
            out << "--- " << f.value("name", "?")
                << " @ " << f.value("address", "?")
                << " (" << f.value("size", 0) << " bytes) ---\n";

            auto code = f.value("decompiled", "");
            if (code.empty()) {
                out << "  (decompilation unavailable)\n";
            } else {
                auto stackStrings = extractStackStrings(code);
                for (const auto& stackString : stackStrings) {
                    out << "Likely stack string: \"" << stackString << "\"\n";
                }
                auto sleepInsights = extractSleepInsights(code);
                for (const auto& note : sleepInsights) {
                    out << note << "\n";
                }
                auto behaviorInsights = extractBehaviorInsights(code);
                for (const auto& note : behaviorInsights) {
                    out << note << "\n";
                }
                if (!stackStrings.empty() || !sleepInsights.empty() || !behaviorInsights.empty()) {
                    out << "\n";
                }
                out << code << "\n";
            }
            out << "\n";
        }
    }

    return out.str();
}

std::string GhidraTool::formatDisasm(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Disassembly: " << meta.value("name", "?") << " ===\n\n";

    if (!data.contains("disassembly") || !data["disassembly"].is_object()) {
        out << "Error: disassembly missing from Ghidra output\n";
        return out.str();
    }

    auto& dis = data["disassembly"];
    if (dis.contains("error")) {
        out << "Error: " << dis["error"].get<std::string>() << "\n";
        return out.str();
    }

    auto kind = dis.value("kind", "function");
    if (dis.contains("requested_address")) {
        out << "Requested address: " << dis.value("requested_address", "?") << "\n";
    }
    if (kind == "function") {
        out << "Function: " << dis.value("function", "?")
            << " @ " << dis.value("address", "?") << "\n";
        auto sig = dis.value("signature", "");
        if (!sig.empty()) out << "Signature: " << sig << "\n";
        if (dis.contains("offset_from_entry")) {
            out << "Offset from entry: " << dis.value("offset_from_entry", 0) << "\n";
        }
        out << "Instructions shown: " << dis.value("instruction_count", 0);
        if (dis.contains("function_instruction_count")) {
            out << " / " << dis.value("function_instruction_count", 0);
        }
        out << "\n";
    } else {
        out << "Window: " << dis.value("window_start", "?")
            << " .. " << dis.value("window_end", "?") << "\n"
            << "Instructions shown: " << dis.value("instruction_count", 0) << "\n";
    }

    auto insights = extractDisassemblyInsights(dis.value("instructions", json::array()));
    for (const auto& note : insights) {
        out << note << "\n";
    }

    out << "\n";
    if (dis.contains("instructions") && dis["instructions"].is_array()) {
        for (const auto& ins : dis["instructions"]) {
            out << (ins.value("is_target", false) ? "=> " : "   ")
                << ins.value("address", "?") << ": "
                << ins.value("text", "");
            auto flow = ins.value("flow_type", "");
            if (!flow.empty()) out << " [" << flow << "]";
            out << "\n";
        }
    }

    return out.str();
}

std::string GhidraTool::formatStrings(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Strings: " << meta.value("name", "?") << " ===\n\n";

    if (data.contains("strings") && data["strings"].is_array()) {
        auto& strings = data["strings"];
        out << strings.size() << " strings found:\n\n";
        for (auto& s : strings) {
            out << "  [" << s.value("address", "?") << "] \""
                << s.value("value", "") << "\"";
            int xrefs = s.value("xref_count", 0);
            if (xrefs > 0) out << " (xrefs: " << xrefs << ")";
            if (s.contains("referenced_by") && s["referenced_by"].is_array()) {
                out << " - used by:";
                for (auto& fn : s["referenced_by"]) {
                    out << " " << fn.get<std::string>();
                }
            }
            out << "\n";
        }
    }

    return out.str();
}

std::string GhidraTool::formatImports(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Imports/Exports: " << meta.value("name", "?") << " ===\n\n";

    if (data.contains("imports") && data["imports"].is_array()) {
        auto& imps = data["imports"];
        out << "--- Imports (" << imps.size() << ") ---\n";
        for (auto& imp : imps) {
            out << "  " << imp.value("name", "?");
            auto lib = imp.value("library", "");
            if (!lib.empty()) out << " [" << lib << "]";
            if (imp.contains("ordinal")) out << " (ordinal " << imp.value("ordinal", 0) << ")";
            out << " @ " << imp.value("address", "?") << "\n";
            if (imp.contains("original_name")) {
                out << "    original: " << imp.value("original_name", "") << "\n";
            }
            if (imp.contains("iat_slots") && imp["iat_slots"].is_array() && !imp["iat_slots"].empty()) {
                out << "    IAT slot";
                if (imp["iat_slots"].size() > 1) out << "s";
                out << ":";
                for (const auto& slot : imp["iat_slots"]) {
                    out << " " << slot.get<std::string>();
                }
                out << "\n";
            }
            out << "    callers: " << imp.value("caller_count", 0);
            if (imp.contains("callsite_count")) {
                out << " | call sites: " << imp.value("callsite_count", 0);
            }
            if (imp.contains("referenced_by") && imp["referenced_by"].is_array() &&
                !imp["referenced_by"].empty()) {
                out << " — referenced by:";
                for (auto& fn : imp["referenced_by"]) {
                    out << " " << fn.get<std::string>();
                }
            }
            out << "\n";
        }
        out << "\n";
    }

    if (data.contains("exports") && data["exports"].is_array()) {
        auto& exps = data["exports"];
        out << "--- Exports (" << exps.size() << ") ---\n";
        for (auto& exp : exps) {
            out << "  " << exp.value("name", "?")
                << " @ " << exp.value("address", "?");
            auto sig = exp.value("signature", "");
            if (!sig.empty()) out << " — " << sig;
            out << "\n";
        }
    }

    return out.str();
}

std::string GhidraTool::formatXrefs(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Cross-References: " << meta.value("name", "?") << " ===\n\n";

    if (data.contains("xrefs") && data["xrefs"].is_object()) {
        auto& xr = data["xrefs"];
        if (xr.contains("error")) {
            out << "Error: " << xr["error"].get<std::string>() << "\n";
            return out.str();
        }

        auto kind = xr.value("kind", "function");
        if (xr.contains("requested_address")) {
            out << "Requested address: " << xr.value("requested_address", "?") << "\n";
        }
        if (kind == "data") {
            out << "Data: " << xr.value("address", "?");
            if (xr.contains("max_address")) {
                out << " .. " << xr.value("max_address", "?");
            }
            out << "\n"
                << "Type: " << xr.value("data_type", "?")
                << " (" << xr.value("length", 0) << " bytes)\n";
            auto value = xr.value("value", "");
            if (!value.empty()) out << "Value: \"" << value << "\"\n";
            auto block = xr.value("memory_block", "");
            if (!block.empty()) out << "Memory block: " << block << "\n";
            auto hexBytes = xr.value("hex_bytes", "");
            if (!hexBytes.empty()) out << "Bytes: " << hexBytes << "\n";
            auto ascii = xr.value("ascii_preview", "");
            if (!ascii.empty()) out << "ASCII: \"" << ascii << "\"\n";
            auto xorDecode = detectSingleByteXor(hexBytes);
            if (!xorDecode.empty()) out << xorDecode << "\n";
            if (xr.contains("offset_from_start")) {
                out << "Offset from start: " << xr.value("offset_from_start", 0) << "\n";
            }
            out << "\n--- References (" << xr.value("xref_count", 0) << ") ---\n"
                << "  " << joinCallsites(xr.value("references", json::array())) << "\n";
            appendReferenceFunctionSummaries(
                out, "Referencing Functions", xr.value("reference_functions", json::array()));
            return out.str();
        }
        if (kind == "import") {
            out << "Import: " << xr.value("function", "?");
            auto lib = xr.value("library", "");
            if (!lib.empty()) out << " [" << lib << "]";
            out << " @ " << xr.value("address", "?") << "\n";
            if (xr.contains("ordinal")) {
                out << "Ordinal: " << xr.value("ordinal", 0) << "\n";
            }
            if (xr.contains("original_name")) {
                out << "Original name: " << xr.value("original_name", "") << "\n";
            }
            if (xr.contains("iat_slots") && xr["iat_slots"].is_array() && !xr["iat_slots"].empty()) {
                out << "IAT slot";
                if (xr["iat_slots"].size() > 1) out << "s";
                out << ":";
                for (const auto& slot : xr["iat_slots"]) {
                    out << " " << slot.get<std::string>();
                }
                out << "\n";
            }
            if (xr.contains("caller_count")) {
                out << "Functions calling: " << xr.value("caller_count", 0);
                if (xr.contains("callsite_count")) {
                    out << " | Call sites: " << xr.value("callsite_count", 0);
                }
                out << "\n";
            }
            out << "\n";

            if (xr.contains("callers") && xr["callers"].is_array()) {
                out << "--- Callers (" << xr["callers"].size() << ") ---\n";
                for (auto& c : xr["callers"]) {
                    out << "  " << c.value("function", "?")
                        << " @ " << c.value("from", "?")
                        << " [" << c.value("type", "?") << "]\n";
                }
            }
            appendReferenceFunctionSummaries(
                out, "Caller Functions", xr.value("caller_summaries", json::array()));
            return out.str();
        }

        out << "Function: " << xr.value("function", "?")
            << " @ " << xr.value("address", "?") << "\n";
        if (xr.contains("offset_from_entry")) {
            out << "Offset from entry: " << xr.value("offset_from_entry", 0) << "\n";
        }
        out << "\n";

        if (xr.contains("callers") && xr["callers"].is_array()) {
            out << "--- Callers (" << xr["callers"].size() << ") ---\n";
            for (auto& c : xr["callers"]) {
                out << "  " << c.value("function", "?")
                    << " @ " << c.value("from", "?")
                    << " [" << c.value("type", "?") << "]\n";
            }
            out << "\n";
        }

        appendReferenceFunctionSummaries(
            out, "Caller Functions", xr.value("caller_summaries", json::array()));
        if (xr.contains("caller_summaries") && xr["caller_summaries"].is_array()
            && !xr["caller_summaries"].empty()) {
            out << "\n";
        }

        if (xr.contains("callees") && xr["callees"].is_array()) {
            out << "--- Callees (" << xr["callees"].size() << ") ---\n";
            for (auto& c : xr["callees"]) {
                out << "  " << c.value("name", "?")
                    << " @ " << c.value("address", "?") << "\n";
            }
        }
    }

    return out.str();
}

std::string GhidraTool::formatFunctionAt(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Function Lookup: " << meta.value("name", "?") << " ===\n\n";

    if (!data.contains("function_at") || !data["function_at"].is_object()) {
        out << "Error: function lookup missing from Ghidra output\n";
        return out.str();
    }

    auto& fn = data["function_at"];
    if (fn.contains("error")) {
        out << "Error: " << fn["error"].get<std::string>() << "\n";
        return out.str();
    }

    if (fn.contains("requested_address")) {
        out << "Requested address: " << fn.value("requested_address", "?") << "\n";
    }
    out << "Function: " << fn.value("name", "?")
        << " @ " << fn.value("address", "?") << "\n"
        << "Signature: " << fn.value("signature", "") << "\n"
        << "Calling convention: " << fn.value("calling_convention", "?") << "\n"
        << "Size: " << fn.value("size", 0) << " bytes\n";
    if (fn.contains("offset_from_entry")) {
        out << "Offset from entry: " << fn.value("offset_from_entry", 0) << "\n";
    }
    out << "Callers: " << fn.value("caller_count", 0)
        << " | Callees: " << fn.value("callee_count", 0) << "\n"
        << "Thunk: " << (fn.value("is_thunk", false) ? "yes" : "no") << "\n";
    return out.str();
}

std::string GhidraTool::formatDataAt(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Data Lookup: " << meta.value("name", "?") << " ===\n\n";

    if (!data.contains("data_at") || !data["data_at"].is_object()) {
        out << "Error: data lookup missing from Ghidra output\n";
        return out.str();
    }

    auto& item = data["data_at"];
    if (item.contains("error")) {
        out << "Error: " << item["error"].get<std::string>() << "\n";
        return out.str();
    }

    if (item.contains("requested_address")) {
        out << "Requested address: " << item.value("requested_address", "?") << "\n";
    }
    out << "Data: " << item.value("address", "?");
    if (item.contains("max_address")) {
        out << " .. " << item.value("max_address", "?");
    }
    out << "\n"
        << "Type: " << item.value("data_type", "?")
        << " (" << item.value("length", 0) << " bytes)\n";
    auto value = item.value("value", "");
    if (!value.empty()) out << "Value: \"" << value << "\"\n";
    auto block = item.value("memory_block", "");
    if (!block.empty()) out << "Memory block: " << block << "\n";
    auto hexBytes = item.value("hex_bytes", "");
    if (!hexBytes.empty()) out << "Bytes: " << hexBytes << "\n";
    auto ascii = item.value("ascii_preview", "");
    if (!ascii.empty()) out << "ASCII: \"" << ascii << "\"\n";
    auto xorDecode = detectSingleByteXor(hexBytes);
    if (!xorDecode.empty()) out << xorDecode << "\n";
    if (item.contains("offset_from_start")) {
        out << "Offset from start: " << item.value("offset_from_start", 0) << "\n";
    }
    out << "References: " << item.value("xref_count", 0) << "\n";
    if (item.contains("references")) {
        out << "Referenced by: " << joinCallsites(item["references"]) << "\n";
    }
    return out.str();
}

std::string GhidraTool::formatAll(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Full Analysis: " << meta.value("name", "?") << " ===\n"
        << "Format: " << meta.value("executable_format", "?") << "\n"
        << "Architecture: " << meta.value("language", "?") << "\n"
        << "Functions: " << meta.value("function_count", 0) << "\n\n";

    if (data.contains("functions") && data["functions"].is_array()) {
        out << "--- Decompiled Functions (" << data["functions"].size() << " shown) ---\n\n";
        for (auto& f : data["functions"]) {
            auto code = f.value("decompiled", "");
            if (code.empty()) continue;
            out << "// " << f.value("name", "?")
                << " @ " << f.value("address", "?")
                << " (" << f.value("size", 0) << " bytes)\n"
                << code << "\n\n";
        }
    }

    if (data.contains("imports") && data["imports"].is_array() && !data["imports"].empty()) {
        auto& imps = data["imports"];
        out << "--- Imports (" << imps.size() << ") ---\n";
        for (auto& imp : imps) {
            out << "  " << imp.value("name", "?");
            auto lib = imp.value("library", "");
            if (!lib.empty()) out << " [" << lib << "]";
            out << "\n";
        }
        out << "\n";
    }

    if (data.contains("strings") && data["strings"].is_array() && !data["strings"].empty()) {
        auto& strs = data["strings"];
        out << "--- Strings (" << strs.size() << ") ---\n";
        int shown = 0;
        for (auto& s : strs) {
            if (shown++ >= 100) {
                out << "  ... and " << (strs.size() - 100) << " more\n";
                break;
            }
            out << "  \"" << s.value("value", "") << "\"";
            if (s.contains("referenced_by") && s["referenced_by"].is_array()) {
                out << " — ";
                for (auto& fn : s["referenced_by"]) {
                    out << fn.get<std::string>() << " ";
                }
            }
            out << "\n";
        }
    }

    return out.str();
}
}  // namespace area
