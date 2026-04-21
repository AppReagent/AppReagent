#include "features/find/FindFilesTool.h"

#include <chrono>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <sstream>
#include <vector>
#include <functional>
#include <system_error>
#include <utility>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"

namespace fs = std::filesystem;

namespace area {

static std::string toLower(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

static bool globMatch(const std::string& text, const std::string& pattern) {
    std::string tl = toLower(text);
    std::string pl = toLower(pattern);

    int n = static_cast<int>(tl.size()), m = static_cast<int>(pl.size());

    if (pl.find('*') == std::string::npos) {
        return tl.find(pl) != std::string::npos;
    }

    std::vector<std::vector<bool>> dp(n + 1, std::vector<bool>(m + 1, false));
    dp[0][0] = true;
    for (int j = 1; j <= m; j++) {
        if (pl[j - 1] == '*') dp[0][j] = dp[0][j - 1];
    }
    for (int i = 1; i <= n; i++) {
        for (int j = 1; j <= m; j++) {
            if (pl[j - 1] == '*') {
                dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
            } else if (pl[j - 1] == '?' || pl[j - 1] == tl[i - 1]) {
                dp[i][j] = dp[i - 1][j - 1];
            }
        }
    }
    return dp[n][m];
}

static bool matchesQuery(const std::string& filename, const std::string& query) {
    if (query.find('*') != std::string::npos || query.find('?') != std::string::npos) {
        return globMatch(filename, query);
    }

    return toLower(filename).find(toLower(query)) != std::string::npos;
}

static bool isScannable(const fs::path& p) {
    return p.extension() == ".smali" || p.extension() == ".so";
}

static bool shouldSkipDir(const std::string& name) {
    return name == ".git" || name == "node_modules" || name == ".cache" ||
           name == "__pycache__" || name == ".gradle";
}

struct DirInfo {
    std::vector<std::string> matchedFiles;
    int scannableCount = 0;
};

std::optional<ToolResult> FindFilesTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("FIND_FILES:"))
        return std::nullopt;

    std::string args = action.substr(11);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);

    std::string query, root;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        query = args.substr(0, pipePos);
        root = args.substr(pipePos + 1);
        while (!query.empty() && query.back() == ' ') query.pop_back();
        while (!root.empty() && root[0] == ' ') root.erase(0, 1);
        while (!root.empty() && root.back() == ' ') root.pop_back();
    } else {
        query = args;
        while (!query.empty() && query.back() == ' ') query.pop_back();
    }

    if (query.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a search query.\n"
                          "Usage: FIND_FILES: <name-or-pattern> [| <root-directory>]"};
    }

    std::vector<std::string> roots;
    auto addRoot = [&](const std::string& p) {
        if (p.empty() || !fs::exists(p)) return;
        for (auto& r : roots) {
            if (p.starts_with(r) || r.starts_with(p)) return;
        }
        roots.push_back(p);
    };
    if (!root.empty()) {
        roots.push_back(root);
    } else {
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

    ctx.cb({AgentMessage::THINKING, "Searching for \"" + query + "\"..."});

    std::map<std::string, DirInfo> dirs;
    int filesVisited = 0;
    static constexpr int MAX_FILES = 200000;
    static constexpr int MAX_MS = 8000;
    auto startTime = std::chrono::steady_clock::now();
    bool truncated = false;

    for (auto& searchRoot : roots) {
        if (truncated) break;
        if (!fs::exists(searchRoot)) continue;

        std::error_code ec;
        auto it = fs::recursive_directory_iterator(
            searchRoot, fs::directory_options::skip_permission_denied, ec);

        for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear(); continue;
            }

            filesVisited++;
            if (filesVisited > MAX_FILES) {
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

            if (matchesQuery(fname, query) ||
                matchesQuery(entry.path().string(), query)) {
                std::string dir;
                if (entry.is_directory(ec) && !ec) {
                    dir = entry.path().string();
                } else {
                    dir = entry.path().parent_path().string();
                }
                if (ec) ec.clear();
                dirs[dir].matchedFiles.push_back(entry.path().string());
            }
        }
    }

    for (auto& [dirPath, info] : dirs) {
        std::error_code ec;
        if (!fs::is_directory(dirPath, ec)) continue;
        for (auto dit = fs::directory_iterator(dirPath, fs::directory_options::skip_permission_denied, ec);
             dit != fs::directory_iterator(); dit.increment(ec)) {
            if (ec) {
                ec.clear(); continue;
            }
            if (dit->is_regular_file(ec) && !ec && isScannable(dit->path())) {
                info.scannableCount++;
            }
            if (ec) ec.clear();
        }
    }

    if (dirs.empty()) {
        std::string obs = "OBSERVATION: No files matching \"" + query + "\" found";
        if (!root.empty()) obs += " under " + root;
        obs += ".";
        if (truncated) obs += " (search was truncated — try a more specific root directory)";
        return ToolResult{obs};
    }

    std::vector<std::pair<std::string, DirInfo>> sorted(dirs.begin(), dirs.end());
    std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) {
        if (a.second.matchedFiles.size() != b.second.matchedFiles.size())
            return a.second.matchedFiles.size() > b.second.matchedFiles.size();
        return a.second.scannableCount > b.second.scannableCount;
    });

    std::ostringstream out;
    int totalMatches = 0;
    for (auto& [_, info] : sorted) totalMatches += static_cast<int>(info.matchedFiles.size());
    out << "Found " << totalMatches << " match(es) across " << dirs.size() << " directory(ies):\n\n";

    int shown = 0;
    for (auto& [dirPath, info] : sorted) {
        if (shown >= 15) {
            out << "... and " << (sorted.size() - shown) << " more location(s)\n";
            break;
        }
        out << dirPath << "/\n";
        out << "  " << info.matchedFiles.size() << " match(es)";
        if (info.scannableCount > 0) {
            out << ", " << info.scannableCount << " scannable file(s) in this directory";
        }
        out << "\n";

        int fileShown = 0;
        for (auto& f : info.matchedFiles) {
            if (fileShown >= 5) {
                out << "    ... and " << (info.matchedFiles.size() - fileShown) << " more\n";
                break;
            }
            out << "    " << f << "\n";
            fileShown++;
        }
        out << "\n";
        shown++;
    }

    if (truncated) {
        out << "(search truncated — specify a narrower root directory for complete results)\n";
    }

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{"OBSERVATION: " + result};
}

}  // namespace area
