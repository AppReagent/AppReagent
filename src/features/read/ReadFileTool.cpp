#include "features/read/ReadFileTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

namespace area {

static std::string toLowerRF(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

// Extract a named method from smali (between .method and .end method)
static std::string extractSmaliMethod(const std::vector<std::string>& lines,
                                       const std::string& methodName) {
    std::string nameLower = toLowerRF(methodName);
    std::ostringstream out;
    bool inMethod = false;
    int methodStart = 0;

    for (int i = 0; i < (int)lines.size(); i++) {
        std::string lineLower = toLowerRF(lines[i]);

        if (!inMethod && lineLower.find(".method") != std::string::npos) {
            if (lineLower.find(nameLower) != std::string::npos) {
                inMethod = true;
                methodStart = i + 1;
            }
        }

        if (inMethod) {
            out << (i + 1) << "\t" << lines[i] << "\n";
            if (lineLower.find(".end method") != std::string::npos) {
                return out.str();
            }
        }
    }

    if (inMethod) {
        return out.str(); // method without .end method (shouldn't happen)
    }

    // Method not found — list available methods
    std::ostringstream avail;
    avail << "Method \"" << methodName << "\" not found. Available methods:\n";
    for (int i = 0; i < (int)lines.size(); i++) {
        if (lines[i].find(".method") == 0 ||
            (lines[i].size() > 1 && lines[i].find(".method") != std::string::npos &&
             lines[i].find(".end method") == std::string::npos)) {
            // Extract method name from .method line
            avail << "  line " << (i + 1) << ": " << lines[i] << "\n";
        }
    }
    return avail.str();
}

std::optional<ToolResult> ReadFileTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("READ:") != 0)
        return std::nullopt;

    std::string args = action.substr(5);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a file path after READ:"};
    }

    // Parse: path | range_or_method
    std::string filePath, modifier;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        filePath = args.substr(0, pipePos);
        modifier = args.substr(pipePos + 1);
        while (!filePath.empty() && filePath.back() == ' ') filePath.pop_back();
        while (!modifier.empty() && modifier[0] == ' ') modifier.erase(0, 1);
        while (!modifier.empty() && modifier.back() == ' ') modifier.pop_back();
    } else {
        filePath = args;
    }

    // Expand ~
    if (!filePath.empty() && filePath[0] == '~') {
        if (auto home = std::getenv("HOME")) {
            filePath = std::string(home) + filePath.substr(1);
        }
    }

    if (!fs::exists(filePath)) {
        return ToolResult{"OBSERVATION: File not found: " + filePath};
    }

    if (fs::is_directory(filePath)) {
        std::ostringstream out;
        out << "Directory: " << filePath << "\n\n";
        std::vector<std::string> entries;
        std::error_code ec;
        for (auto dit = fs::directory_iterator(filePath, fs::directory_options::skip_permission_denied, ec);
             dit != fs::directory_iterator(); dit.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            std::string name = dit->path().filename().string();
            if (dit->is_directory(ec) && !ec) name += "/";
            if (ec) ec.clear();
            entries.push_back(name);
        }
        std::sort(entries.begin(), entries.end());
        for (auto& e : entries) {
            out << "  " << e << "\n";
        }
        out << "\n" << entries.size() << " entries\n";
        std::string result = out.str();
        ctx.cb({AgentMessage::RESULT, result});
        return ToolResult{"OBSERVATION: " + result};
    }

    std::error_code ec;
    auto fsize = fs::file_size(filePath, ec);
    if (ec) {
        return ToolResult{"OBSERVATION: Cannot read file: " + ec.message()};
    }
    if (fsize > 5 * 1024 * 1024) {
        return ToolResult{"OBSERVATION: File too large (" + std::to_string(fsize / 1024) +
                          " KB). Use a line range: READ: " + filePath + " | 1-100"};
    }

    std::ifstream file(filePath);
    if (!file.is_open()) {
        return ToolResult{"OBSERVATION: Cannot open file: " + filePath};
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }
    file.close();

    // Handle "method <name>" modifier for smali files
    if (!modifier.empty() && toLowerRF(modifier).starts_with("method")) {
        std::string methodName = modifier.substr(6);
        while (!methodName.empty() && methodName[0] == ' ') methodName.erase(0, 1);

        if (methodName.empty()) {
            std::ostringstream out;
            out << "Methods in " << filePath << ":\n\n";
            for (int i = 0; i < (int)lines.size(); i++) {
                if (lines[i].find(".method") == 0) {
                    out << "  line " << (i + 1) << ": " << lines[i] << "\n";
                }
            }
            std::string result = out.str();
            ctx.cb({AgentMessage::RESULT, result});
            return ToolResult{"OBSERVATION: " + result};
        }

        std::string result = extractSmaliMethod(lines, methodName);
        ctx.cb({AgentMessage::RESULT, result});
        return ToolResult{"OBSERVATION: " + result};
    }

    // Handle line range modifier: "start-end" or just "start"
    int startLine = 1;
    int endLine = (int)lines.size();

    if (!modifier.empty()) {
        auto dashPos = modifier.find('-');
        if (dashPos != std::string::npos) {
            try {
                startLine = std::stoi(modifier.substr(0, dashPos));
                endLine = std::stoi(modifier.substr(dashPos + 1));
            } catch (...) {
                return ToolResult{"OBSERVATION: Invalid line range: " + modifier +
                                  ". Use format: start-end (e.g., 10-50)"};
            }
        } else {
            try {
                startLine = std::stoi(modifier);
                endLine = std::min(startLine + 99, (int)lines.size());
            } catch (...) {
                return ToolResult{"OBSERVATION: Invalid modifier: " + modifier +
                                  ". Use line range (10-50) or 'method <name>'"};
            }
        }
    }

    // Clamp
    startLine = std::max(1, startLine);
    endLine = std::min(endLine, (int)lines.size());

    // Cap output to 200 lines
    if (endLine - startLine + 1 > 200) {
        endLine = startLine + 199;
        if (endLine > (int)lines.size()) endLine = (int)lines.size();
    }

    std::ostringstream out;
    out << filePath << " (" << lines.size() << " lines";
    if (startLine != 1 || endLine != (int)lines.size()) {
        out << ", showing " << startLine << "-" << endLine;
    }
    out << "):\n\n";

    for (int i = startLine - 1; i < endLine && i < (int)lines.size(); i++) {
        out << (i + 1) << "\t" << lines[i] << "\n";
    }

    if (endLine < (int)lines.size() && endLine - startLine + 1 >= 200) {
        out << "\n... truncated. Use READ: " << filePath << " | "
            << (endLine + 1) << "-" << std::min(endLine + 200, (int)lines.size())
            << " to continue.\n";
    }

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{"OBSERVATION: " + result};
}

} // namespace area
