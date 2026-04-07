#include "tools/XrefsTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>

namespace fs = std::filesystem;

namespace area {

static std::string toLowerXR(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

static bool shouldSkipDirXR(const std::string& name) {
    return name == ".git" || name == "node_modules" || name == ".cache" ||
           name == "__pycache__" || name == ".gradle" || name == "build" ||
           name == ".idea" || name == ".vscode";
}

struct XrefEntry {
    std::string file;
    int line;
    std::string content;
    std::string type; // "invoke", "field-read", "field-write", "new-instance", "const-class", "const-string", "type-ref"
};

static std::string classifyXref(const std::string& lineLower) {
    if (lineLower.find("invoke-") != std::string::npos) return "invoke";
    if (lineLower.find("sget") != std::string::npos ||
        lineLower.find("iget") != std::string::npos) return "field-read";
    if (lineLower.find("sput") != std::string::npos ||
        lineLower.find("iput") != std::string::npos) return "field-write";
    if (lineLower.find("new-instance") != std::string::npos) return "new-instance";
    if (lineLower.find("const-class") != std::string::npos) return "const-class";
    if (lineLower.find("const-string") != std::string::npos) return "const-string";
    if (lineLower.find("check-cast") != std::string::npos ||
        lineLower.find("instance-of") != std::string::npos) return "type-ref";
    if (lineLower.find(".super") != std::string::npos ||
        lineLower.find(".implements") != std::string::npos) return "inheritance";
    if (lineLower.find(".field") != std::string::npos) return "field-decl";
    if (lineLower.find(".method") != std::string::npos) return "method-decl";
    return "reference";
}

// Find which method a line belongs to in a smali file
static std::string enclosingMethod(const std::vector<std::string>& lines, int lineIdx) {
    for (int i = lineIdx; i >= 0; i--) {
        if (lines[i].find(".method") == 0 ||
            (lines[i].find(".method") != std::string::npos &&
             lines[i].find(".end method") == std::string::npos &&
             lines[i].find('#') > lines[i].find(".method"))) {
            // Extract method signature
            auto pos = lines[i].find(".method");
            std::string sig = lines[i].substr(pos);
            if (sig.size() > 80) sig = sig.substr(0, 80) + "...";
            return sig;
        }
    }
    return "(class scope)";
}

std::optional<ToolResult> XrefsTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("XREFS:") != 0)
        return std::nullopt;

    std::string args = action.substr(6);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide an identifier after XREFS:"};
    }

    // Parse: identifier | path
    std::string identifier, root;
    auto pipePos = args.rfind('|');
    if (pipePos != std::string::npos) {
        std::string after = args.substr(pipePos + 1);
        while (!after.empty() && after[0] == ' ') after.erase(0, 1);
        while (!after.empty() && after.back() == ' ') after.pop_back();
        if (!after.empty() && (after[0] == '/' || after[0] == '~' || after[0] == '.')) {
            identifier = args.substr(0, pipePos);
            root = after;
            while (!identifier.empty() && identifier.back() == ' ') identifier.pop_back();
        } else {
            identifier = args;
        }
    } else {
        identifier = args;
    }

    if (!root.empty() && root[0] == '~') {
        if (auto home = std::getenv("HOME")) {
            root = std::string(home) + root.substr(1);
        }
    }

    // Determine search roots
    std::vector<std::string> roots;
    if (!root.empty()) {
        roots.push_back(root);
    } else {
        auto addRoot = [&](const std::string& p) {
            if (p.empty() || !fs::exists(p)) return;
            for (auto& r : roots) {
                if (p.starts_with(r) || r.starts_with(p)) return;
            }
            roots.push_back(p);
        };
        if (auto home = std::getenv("HOME")) addRoot(home);
        if (fs::exists("/opt/area")) addRoot("/opt/area");
        addRoot("/tmp");
        {
            std::error_code ec;
            auto exePath = fs::read_symlink("/proc/self/exe", ec);
            if (!ec) addRoot(exePath.parent_path().string());
        }
        addRoot(fs::current_path().string());
    }

    ctx.cb({AgentMessage::THINKING, "Finding cross-references to \"" + identifier + "\"..."});

    std::string identLower = toLowerXR(identifier);
    std::vector<XrefEntry> xrefs;
    int filesSearched = 0;
    static constexpr int MAX_FILES = 100000;
    static constexpr int MAX_XREFS = 150;
    static constexpr int MAX_MS = 10000;
    auto startTime = std::chrono::steady_clock::now();
    bool truncated = false;

    for (auto& searchRoot : roots) {
        if (truncated || (int)xrefs.size() >= MAX_XREFS) break;
        if (!fs::exists(searchRoot)) continue;

        std::error_code ec;
        auto it = fs::recursive_directory_iterator(
            searchRoot, fs::directory_options::skip_permission_denied, ec);

        for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if ((int)xrefs.size() >= MAX_XREFS || filesSearched > MAX_FILES) {
                truncated = true; break;
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed > MAX_MS) { truncated = true; break; }

            auto& entry = *it;
            if (entry.is_directory(ec) && !ec && shouldSkipDirXR(entry.path().filename().string())) {
                it.disable_recursion_pending();
                continue;
            }
            if (ec) { ec.clear(); continue; }
            if (!entry.is_regular_file(ec) || ec) { ec.clear(); continue; }

            std::string ext = entry.path().extension().string();
            for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));
            if (ext != ".smali" && ext != ".java" && ext != ".kt" && ext != ".xml") continue;

            auto fsize = fs::file_size(entry.path(), ec);
            if (ec || fsize > 2 * 1024 * 1024) continue;

            filesSearched++;

            // Read file and search
            std::ifstream file(entry.path());
            if (!file.is_open()) continue;

            std::vector<std::string> lines;
            std::string line;
            while (std::getline(file, line)) {
                lines.push_back(line);
            }

            for (int i = 0; i < (int)lines.size(); i++) {
                std::string lineLower = toLowerXR(lines[i]);
                if (lineLower.find(identLower) != std::string::npos) {
                    // Skip the definition itself (.class line defining this class)
                    if (lineLower.find(".class") != std::string::npos &&
                        lineLower.find(identLower) != std::string::npos) {
                        // This is the class definition — include it but mark it
                        xrefs.push_back({
                            entry.path().string(), i + 1,
                            lines[i].size() > 200 ? lines[i].substr(0, 200) + "..." : lines[i],
                            "definition"
                        });
                    } else {
                        xrefs.push_back({
                            entry.path().string(), i + 1,
                            lines[i].size() > 200 ? lines[i].substr(0, 200) + "..." : lines[i],
                            classifyXref(lineLower)
                        });
                    }
                    if ((int)xrefs.size() >= MAX_XREFS) break;
                }
            }
        }
    }

    if (xrefs.empty()) {
        std::string obs = "OBSERVATION: No cross-references found for \"" + identifier + "\"";
        if (!root.empty()) obs += " in " + root;
        obs += " (" + std::to_string(filesSearched) + " files searched).";
        return ToolResult{obs};
    }

    // Group by type
    std::map<std::string, std::vector<XrefEntry*>> byType;
    for (auto& x : xrefs) {
        byType[x.type].push_back(&x);
    }

    std::ostringstream out;
    out << xrefs.size() << " cross-reference(s) to \"" << identifier
        << "\" across " << filesSearched << " files:\n\n";

    // Print in a logical order
    std::vector<std::string> typeOrder = {
        "definition", "inheritance", "new-instance", "invoke",
        "field-read", "field-write", "field-decl", "method-decl",
        "const-class", "const-string", "type-ref", "reference"
    };

    for (auto& type : typeOrder) {
        auto it = byType.find(type);
        if (it == byType.end()) continue;

        out << "== " << type << " (" << it->second.size() << ") ==\n";
        for (auto* x : it->second) {
            out << "  " << x->file << ":" << x->line << "\n";
            out << "    " << x->content << "\n";
        }
        out << "\n";
    }

    if (truncated) {
        out << "(results truncated at " << MAX_XREFS << " references)\n";
    }

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{
        "OBSERVATION: " + result +
        "Use READ: to view full context, or CALLGRAPH: to trace call chains."};
}

} // namespace area
