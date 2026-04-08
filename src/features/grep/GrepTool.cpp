#include "features/grep/GrepTool.h"

#include <bits/chrono.h>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <cctype>
#include <functional>
#include <system_error>
#include <utility>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"

namespace fs = std::filesystem;

namespace area {
static std::string toLowerStr(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

static bool isSearchableFile(const fs::path& p) {
    static const std::vector<std::string> exts = {
        ".smali", ".xml", ".java", ".kt", ".json", ".txt",
        ".properties", ".cfg", ".yaml", ".yml", ".gradle",
        ".pro", ".html", ".js", ".css", ".sh", ".py", ".rb",
        ".c", ".h", ".cpp", ".hpp", ".rs", ".go", ".swift",
        ".plist", ".strings"
    };
    std::string ext = p.extension().string();
    for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));
    for (auto& e : exts) {
        if (ext == e) return true;
    }

    if (ext.empty()) {
        std::error_code ec;
        auto sz = fs::file_size(p, ec);
        if (!ec && sz < 100 * 1024) return true;
    }
    return false;
}

static bool shouldSkipDir(const std::string& name) {
    return name == ".git" || name == "node_modules" || name == ".cache" ||
           name == "__pycache__" || name == ".gradle" || name == "build" ||
           name == ".idea" || name == ".vscode";
}

struct GrepMatch {
    std::string file;
    int line;
    std::string content;
};

std::optional<ToolResult> GrepTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("GREP:"))
        return std::nullopt;

    std::string args = action.substr(5);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a search pattern after GREP:"};
    }

    std::string pattern, root;
    for (size_t i = args.size(); i-- > 0;) {
        if (args[i] == '|') {
            std::string after = args.substr(i + 1);
            while (!after.empty() && after[0] == ' ') after.erase(0, 1);
            while (!after.empty() && after.back() == ' ') after.pop_back();
            if (!after.empty() && (after[0] == '/' || after[0] == '~' || after[0] == '.')) {
                pattern = args.substr(0, i);
                root = after;
                break;
            }
        }
    }
    if (pattern.empty()) pattern = args;
    while (!pattern.empty() && pattern.back() == ' ') pattern.pop_back();
    while (!pattern.empty() && pattern[0] == ' ') pattern.erase(0, 1);

    if (!root.empty() && root[0] == '~') {
        if (auto home = std::getenv("HOME")) {
            root = std::string(home) + root.substr(1);
        }
    }

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

    ctx.cb({AgentMessage::THINKING, "Searching for \"" + pattern + "\"..."});

    std::string patternLower = toLowerStr(pattern);
    std::vector<std::string> terms;
    {
        std::istringstream ss(patternLower);
        std::string tok;

        bool hasRegex = pattern.find('\\') != std::string::npos ||
                        pattern.find('(') != std::string::npos;
        if (!hasRegex && patternLower.find('|') != std::string::npos) {
            size_t pos = 0;
            while (pos < patternLower.size()) {
                auto pipe = patternLower.find('|', pos);
                if (pipe == std::string::npos) {
                    std::string t = patternLower.substr(pos);
                    while (!t.empty() && t[0] == ' ') t.erase(0, 1);
                    while (!t.empty() && t.back() == ' ') t.pop_back();
                    if (!t.empty()) terms.push_back(t);
                    break;
                }
                std::string t = patternLower.substr(pos, pipe - pos);
                while (!t.empty() && t[0] == ' ') t.erase(0, 1);
                while (!t.empty() && t.back() == ' ') t.pop_back();
                if (!t.empty()) terms.push_back(t);
                pos = pipe + 1;
            }
        } else {
            terms.push_back(patternLower);
        }
    }

    std::vector<GrepMatch> matches;
    int filesSearched = 0;
    static constexpr int MAX_FILES = 100000;
    static constexpr int MAX_MATCHES = 100;
    static constexpr int MAX_MS = 10000;
    auto startTime = std::chrono::steady_clock::now();
    bool truncated = false;

    for (auto& searchRoot : roots) {
        if (truncated || static_cast<int>(matches.size()) >= MAX_MATCHES) break;
        if (!fs::exists(searchRoot)) continue;

        std::error_code ec;
        auto it = fs::recursive_directory_iterator(
            searchRoot, fs::directory_options::skip_permission_denied, ec);

        for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear(); continue;
            }
            if (static_cast<int>(matches.size()) >= MAX_MATCHES) {
                truncated = true; break;
            }
            if (filesSearched > MAX_FILES) {
                truncated = true; break;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed > MAX_MS) {
                truncated = true; break;
            }

            auto& entry = *it;
            std::string fname = entry.path().filename().string();

            if (entry.is_directory(ec) && !ec && shouldSkipDir(fname)) {
                it.disable_recursion_pending();
                continue;
            }
            if (ec) {
                ec.clear(); continue;
            }

            if (!entry.is_regular_file(ec) || ec) {
                ec.clear(); continue;
            }
            if (!isSearchableFile(entry.path())) continue;

            auto fsize = fs::file_size(entry.path(), ec);
            if (ec || fsize > 2 * 1024 * 1024) continue;

            filesSearched++;

            std::ifstream file(entry.path());
            if (!file.is_open()) continue;

            std::string line;
            int lineNum = 0;
            while (std::getline(file, line)) {
                lineNum++;
                std::string lineLower = toLowerStr(line);

                bool matched = false;
                for (auto& term : terms) {
                    if (lineLower.find(term) != std::string::npos) {
                        matched = true;
                        break;
                    }
                }

                if (matched) {
                    std::string display = line;
                    if (display.size() > 200) {
                        display.resize(200);
                        display += "...";
                    }
                    matches.push_back({entry.path().string(), lineNum, display});
                    if (static_cast<int>(matches.size()) >= MAX_MATCHES) break;
                }
            }
        }
    }

    if (matches.empty()) {
        std::string obs = "OBSERVATION: No matches for \"" + pattern + "\"";
        if (!root.empty()) obs += " in " + root;
        obs += " (" + std::to_string(filesSearched) + " files searched).";
        if (truncated) obs += " Search was truncated — try a more specific path.";
        obs += "\nTip: Try different search terms, or use FIND_FILES to locate the code first.";
        return ToolResult{obs};
    }

    struct FileGroup {
        std::string path;
        std::vector<std::pair<int, std::string>> lines;
    };
    std::vector<FileGroup> groups;
    std::string lastFile;
    for (auto& m : matches) {
        if (m.file != lastFile) {
            groups.push_back({m.file, {}});
            lastFile = m.file;
        }
        groups.back().lines.push_back({m.line, m.content});
    }

    std::ostringstream out;
    out << matches.size() << " match(es) across " << groups.size()
        << " file(s) (" << filesSearched << " files searched):\n\n";

    for (auto& g : groups) {
        out << g.path << ":\n";
        for (auto& [lineNum, content] : g.lines) {
            out << "  " << lineNum << ": " << content << "\n";
        }
        out << "\n";
    }

    if (truncated) {
        out << "(results truncated — " << MAX_MATCHES << " match limit. "
            << "Narrow your search or specify a more specific path.)\n";
    }

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{
        "OBSERVATION: " + result +
        "Use READ: to view full file contents, or XREFS: to trace cross-references."};
}
}  // namespace area
