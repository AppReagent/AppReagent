#include "tools/GhidraTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"
#include "util/file_io.h"

#include <nlohmann/json.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace area {

// ── helpers ────────────────────────────────────────────────────────

static std::string ghidraHome() {
    if (auto env = std::getenv("GHIDRA_HOME")) return env;
    // Default install location
    std::string home = std::getenv("HOME") ? std::getenv("HOME") : "/home/builder";
    // Glob for any ghidra version under ~/.local/opt
    std::string optDir = home + "/.local/opt";
    if (!fs::is_directory(optDir)) return "";
    for (auto& entry : fs::directory_iterator(optDir)) {
        auto name = entry.path().filename().string();
        if (name.find("ghidra_") == 0 && entry.is_directory()) {
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
        if (name.find("jdk-") == 0 && entry.is_directory()) {
            return entry.path().string();
        }
    }
    return "";
}

static std::string scriptDir() {
    // Look for scripts/ghidra relative to executable, or from workspace
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

// ── tryExecute ─────────────────────────────────────────────────────

std::optional<ToolResult> GhidraTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("GHIDRA:") != 0)
        return std::nullopt;

    std::string args = action.substr(7);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a file path.\n"
                          "Usage: GHIDRA: <path> [| <mode> [| <filter>]]\n"
                          "Modes: overview (default), decompile, strings, imports, xrefs, all"};
    }

    // Parse: path | mode | filter
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

        // Normalize mode
        for (auto& c : mode) c = std::tolower(static_cast<unsigned char>(c));
    }

    if (!fs::exists(path)) {
        return ToolResult{"OBSERVATION: Error — file not found: " + path};
    }

    // Validate mode
    if (mode != "overview" && mode != "decompile" && mode != "strings" &&
        mode != "imports" && mode != "xrefs" && mode != "all") {
        return ToolResult{"OBSERVATION: Error — unknown mode '" + mode + "'.\n"
                          "Valid modes: overview, decompile, strings, imports, xrefs, all"};
    }

    // Check Ghidra availability
    std::string gh = ghidraHome();
    if (gh.empty() || !fs::exists(gh + "/support/analyzeHeadless")) {
        return ToolResult{"OBSERVATION: Error — Ghidra not found. Set GHIDRA_HOME or "
                          "install Ghidra to ~/.local/opt/ghidra_*"};
    }

    ctx.cb({AgentMessage::THINKING, "Running Ghidra " + mode + " analysis on " +
            fs::path(path).filename().string() + "..."});

    // Create temp output path
    std::string tmpDir = "/tmp/area-ghidra-" + std::to_string(getpid());
    fs::create_directories(tmpDir);
    std::string outputPath = tmpDir + "/output.json";

    std::string ghidraLog;
    std::string err = runGhidra(path, mode, filter, outputPath, ghidraLog);
    if (!err.empty()) {
        // Clean up
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

    // Format output based on mode
    std::string formatted;
    if (mode == "overview")        formatted = formatOverview(outputPath);
    else if (mode == "decompile")  formatted = formatDecompile(outputPath);
    else if (mode == "strings")    formatted = formatStrings(outputPath);
    else if (mode == "imports")    formatted = formatImports(outputPath);
    else if (mode == "xrefs")      formatted = formatXrefs(outputPath);
    else if (mode == "all")        formatted = formatAll(outputPath);

    // Clean up
    std::error_code ec;
    fs::remove_all(tmpDir, ec);

    formatted = truncate(formatted, 12000);
    ctx.cb({AgentMessage::RESULT, formatted});
    return ToolResult{"OBSERVATION: " + formatted};
}

// ── runGhidra ──────────────────────────────────────────────────────

std::string GhidraTool::runGhidra(const std::string& binaryPath,
                                   const std::string& mode,
                                   const std::string& filter,
                                   const std::string& outputPath,
                                   std::string& ghidraLog) {
    std::string gh = ghidraHome();
    std::string jh = javaHome();
    std::string sd = scriptDir();

    if (sd.empty()) return "Ghidra scripts not found (scripts/ghidra/AreaAnalyze.java)";

    std::string projDir = "/tmp/area-ghidra-proj-" + std::to_string(getpid());
    fs::create_directories(projDir);

    std::ostringstream cmd;

    // Set environment
    if (!jh.empty()) {
        cmd << "JAVA_HOME=" << jh << " PATH=" << jh << "/bin:$PATH ";
    }

    cmd << gh << "/support/analyzeHeadless"
        << " " << projDir << " AreaProject"
        << " -import " << binaryPath
        << " -postScript AreaAnalyze.java " << outputPath << " " << mode;

    if (!filter.empty()) {
        // Shell-escape the filter
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

    int exitCode;
    ghidraLog = runCmd(cmd.str(), &exitCode);

    // Clean up project dir
    std::error_code ec;
    fs::remove_all(projDir, ec);

    // Check for script errors in log
    if (ghidraLog.find("SCRIPT ERROR") != std::string::npos &&
        ghidraLog.find("AreaAnalyze: wrote") == std::string::npos) {
        return "Ghidra script error:\n" + truncate(ghidraLog, 2000);
    }

    // The analyzeHeadless often returns non-zero even on success (e.g., demangler warnings)
    // So check for actual success indicators
    if (ghidraLog.find("Import succeeded") == std::string::npos &&
        ghidraLog.find("Processing succeeded") == std::string::npos) {
        if (exitCode != 0) {
            return "Ghidra exited with code " + std::to_string(exitCode) +
                   ":\n" + truncate(ghidraLog, 2000);
        }
    }

    return "";
}

// ── formatters ─────────────────────────────────────────────────────

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
        << "Memory: " << meta.value("memory_size", 0) << " bytes\n\n";

    // Functions
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

    // Imports
    if (data.contains("imports") && data["imports"].is_array() && !data["imports"].empty()) {
        auto& imps = data["imports"];
        out << "--- Imports (" << imps.size() << ") ---\n";
        int shown = 0;
        for (auto& imp : imps) {
            if (shown++ >= 50) {
                out << "  ... and " << (imps.size() - 50) << " more\n";
                break;
            }
            out << "  " << imp.value("name", "?");
            auto lib = imp.value("library", "");
            if (!lib.empty()) out << " [" << lib << "]";
            out << "\n";
        }
        out << "\n";
    }

    // Exports
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

    out << "\nUse GHIDRA: <path> | decompile [| funcname] for decompiled C code.\n";
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
                out << code << "\n";
            }
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
                out << " — used by:";
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
            out << " @ " << imp.value("address", "?") << "\n";
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

        out << "Function: " << xr.value("function", "?")
            << " @ " << xr.value("address", "?") << "\n\n";

        if (xr.contains("callers") && xr["callers"].is_array()) {
            out << "--- Callers (" << xr["callers"].size() << ") ---\n";
            for (auto& c : xr["callers"]) {
                out << "  " << c.value("function", "?")
                    << " @ " << c.value("from", "?")
                    << " [" << c.value("type", "?") << "]\n";
            }
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

std::string GhidraTool::formatAll(const std::string& jsonPath) {
    auto data = loadJson(jsonPath);
    if (data.empty()) return "Error: could not parse Ghidra output";

    // Combine overview + decompile + strings
    std::ostringstream out;
    auto& meta = data["metadata"];
    out << "=== Ghidra Full Analysis: " << meta.value("name", "?") << " ===\n"
        << "Format: " << meta.value("executable_format", "?") << "\n"
        << "Architecture: " << meta.value("language", "?") << "\n"
        << "Functions: " << meta.value("function_count", 0) << "\n\n";

    // Decompiled functions (most valuable for malware analysis)
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

    // Imports (security-relevant)
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

    // Strings (IOCs)
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

} // namespace area
