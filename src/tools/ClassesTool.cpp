#include "tools/ClassesTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace area {

static std::string toLowerCL(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

static bool shouldSkipDirCL(const std::string& name) {
    return name == ".git" || name == "node_modules" || name == ".cache" ||
           name == "__pycache__" || name == ".gradle" || name == "build" ||
           name == ".idea" || name == ".vscode";
}

struct ClassInfo {
    std::string filePath;
    std::string className;      // full smali class e.g. Lcom/example/Foo;
    std::string javaName;       // com.example.Foo
    std::string packageName;    // com.example
    std::string simpleName;     // Foo
    std::string superClass;     // Landroid/app/Service;
    std::string superJava;      // android.app.Service
    std::vector<std::string> interfaces;
    std::vector<std::string> interfacesJava;
    int methodCount = 0;
    int fieldCount = 0;
    bool isPublic = false;
    bool isAbstract = false;
    bool isInterface = false;
    bool isEnum = false;
    std::vector<std::string> methodNames;  // first 10 method names for preview
};

static std::string smaliToJava(const std::string& desc) {
    if (desc.size() >= 2 && desc[0] == 'L' && desc.back() == ';') {
        std::string name = desc.substr(1, desc.size() - 2);
        for (auto& c : name) if (c == '/') c = '.';
        return name;
    }
    return desc;
}

static std::string smaliSimpleName(const std::string& javaName) {
    auto dot = javaName.rfind('.');
    if (dot != std::string::npos) return javaName.substr(dot + 1);
    auto dollar = javaName.rfind('$');
    if (dollar != std::string::npos) return javaName.substr(dollar + 1);
    return javaName;
}

static std::string smaliPackage(const std::string& javaName) {
    auto dot = javaName.rfind('.');
    if (dot != std::string::npos) return javaName.substr(0, dot);
    return "(default)";
}

static ClassInfo parseSmaliFile(const std::string& path) {
    ClassInfo info;
    info.filePath = path;

    std::ifstream file(path);
    if (!file.is_open()) return info;

    std::string line;
    while (std::getline(file, line)) {
        // Trim leading whitespace
        size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        std::string trimmed = line.substr(start);

        if (trimmed.starts_with(".class")) {
            // .class public abstract Lcom/example/Foo;
            info.className = trimmed;
            if (trimmed.find("public") != std::string::npos) info.isPublic = true;
            if (trimmed.find("abstract") != std::string::npos) info.isAbstract = true;
            if (trimmed.find("interface") != std::string::npos) info.isInterface = true;
            if (trimmed.find("enum") != std::string::npos) info.isEnum = true;

            auto lastSpace = trimmed.rfind(' ');
            if (lastSpace != std::string::npos) {
                std::string desc = trimmed.substr(lastSpace + 1);
                info.javaName = smaliToJava(desc);
                info.simpleName = smaliSimpleName(info.javaName);
                info.packageName = smaliPackage(info.javaName);
            }
        } else if (trimmed.starts_with(".super")) {
            auto sp = trimmed.find(' ');
            if (sp != std::string::npos) {
                info.superClass = trimmed.substr(sp + 1);
                while (!info.superClass.empty() && info.superClass.back() == ' ')
                    info.superClass.pop_back();
                info.superJava = smaliToJava(info.superClass);
            }
        } else if (trimmed.starts_with(".implements")) {
            auto sp = trimmed.find(' ');
            if (sp != std::string::npos) {
                std::string iface = trimmed.substr(sp + 1);
                while (!iface.empty() && iface.back() == ' ') iface.pop_back();
                info.interfaces.push_back(iface);
                info.interfacesJava.push_back(smaliToJava(iface));
            }
        } else if (trimmed.starts_with(".field")) {
            info.fieldCount++;
        } else if (trimmed.starts_with(".method")) {
            info.methodCount++;
            if ((int)info.methodNames.size() < 15) {
                // Extract method name
                auto paren = trimmed.find('(');
                if (paren != std::string::npos) {
                    std::string before = trimmed.substr(0, paren);
                    auto lastSp = before.rfind(' ');
                    if (lastSp != std::string::npos) {
                        info.methodNames.push_back(before.substr(lastSp + 1));
                    }
                }
            }
        }
    }

    return info;
}

std::optional<ToolResult> ClassesTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("CLASSES:") != 0)
        return std::nullopt;

    std::string args = action.substr(8);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a directory path after CLASSES:"};
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

    ctx.cb({AgentMessage::THINKING, "Scanning classes in " + path + "..."});

    std::string filterLower = toLowerCL(filter);
    std::vector<ClassInfo> classes;
    int filesScanned = 0;
    static constexpr int MAX_FILES = 50000;
    static constexpr int MAX_MS = 15000;
    auto startTime = std::chrono::steady_clock::now();
    bool truncated = false;

    auto processFile = [&](const fs::path& filePath) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        if (elapsed > MAX_MS || filesScanned > MAX_FILES) { truncated = true; return; }

        filesScanned++;
        auto info = parseSmaliFile(filePath.string());
        if (info.javaName.empty()) return;

        // Apply filter
        if (!filter.empty()) {
            std::string nameLower = toLowerCL(info.javaName);
            std::string simpleLower = toLowerCL(info.simpleName);
            std::string pkgLower = toLowerCL(info.packageName);
            if (nameLower.find(filterLower) == std::string::npos &&
                simpleLower.find(filterLower) == std::string::npos &&
                pkgLower.find(filterLower) == std::string::npos) {
                return;
            }
        }

        classes.push_back(std::move(info));
    };

    if (fs::is_regular_file(path)) {
        std::string ext = fs::path(path).extension().string();
        for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));
        if (ext == ".smali") {
            processFile(path);
        } else {
            return ToolResult{"OBSERVATION: Not a .smali file or directory: " + path};
        }
    } else {
        std::error_code ec;
        auto it = fs::recursive_directory_iterator(
            path, fs::directory_options::skip_permission_denied, ec);
        for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            if (truncated) break;

            if (it->is_directory(ec) && !ec && shouldSkipDirCL(it->path().filename().string())) {
                it.disable_recursion_pending();
                continue;
            }
            if (ec) { ec.clear(); continue; }
            if (!it->is_regular_file(ec) || ec) { ec.clear(); continue; }

            std::string ext = it->path().extension().string();
            for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));
            if (ext != ".smali") continue;

            processFile(it->path());
        }
    }

    if (classes.empty()) {
        std::string obs = "OBSERVATION: No classes found";
        if (!filter.empty()) obs += " matching \"" + filter + "\"";
        obs += " in " + path + " (" + std::to_string(filesScanned) + " files scanned).";
        return ToolResult{obs};
    }

    // Group by package
    std::map<std::string, std::vector<ClassInfo*>> byPackage;
    for (auto& cls : classes) {
        byPackage[cls.packageName].push_back(&cls);
    }

    // Sort packages, and classes within packages
    std::vector<std::string> sortedPackages;
    for (auto& [pkg, _] : byPackage) sortedPackages.push_back(pkg);
    std::sort(sortedPackages.begin(), sortedPackages.end());

    for (auto& [_, cls] : byPackage) {
        std::sort(cls.begin(), cls.end(), [](const ClassInfo* a, const ClassInfo* b) {
            return a->simpleName < b->simpleName;
        });
    }

    // Build output
    std::ostringstream out;
    out << classes.size() << " class(es) in " << sortedPackages.size()
        << " package(s) (" << filesScanned << " files scanned)";
    if (!filter.empty()) out << ", filter: \"" << filter << "\"";
    out << ":\n\n";

    // Summary stats
    int totalMethods = 0, totalFields = 0;
    int interfaceCount = 0, enumCount = 0, abstractCount = 0;
    for (auto& cls : classes) {
        totalMethods += cls.methodCount;
        totalFields += cls.fieldCount;
        if (cls.isInterface) interfaceCount++;
        if (cls.isEnum) enumCount++;
        if (cls.isAbstract) abstractCount++;
    }
    out << "Summary: " << totalMethods << " methods, " << totalFields << " fields";
    if (interfaceCount > 0) out << ", " << interfaceCount << " interfaces";
    if (enumCount > 0) out << ", " << enumCount << " enums";
    if (abstractCount > 0) out << ", " << abstractCount << " abstract";
    out << "\n\n";

    for (auto& pkg : sortedPackages) {
        auto& pkgClasses = byPackage[pkg];
        out << "== " << pkg << " (" << pkgClasses.size() << " classes) ==\n";

        for (auto* cls : pkgClasses) {
            // Type indicator
            std::string typeTag;
            if (cls->isInterface) typeTag = "[interface] ";
            else if (cls->isEnum) typeTag = "[enum] ";
            else if (cls->isAbstract) typeTag = "[abstract] ";

            out << "  " << typeTag << cls->simpleName;

            // Hierarchy
            std::string superSimple = smaliSimpleName(cls->superJava);
            if (!superSimple.empty() && superSimple != "Object") {
                out << " extends " << superSimple;
            }
            if (!cls->interfacesJava.empty()) {
                out << " implements ";
                for (size_t i = 0; i < cls->interfacesJava.size(); i++) {
                    if (i > 0) out << ", ";
                    out << smaliSimpleName(cls->interfacesJava[i]);
                }
            }

            out << " — " << cls->methodCount << " methods, " << cls->fieldCount << " fields\n";

            // Show methods preview (skip <init>, <clinit>)
            std::vector<std::string> interesting;
            for (auto& m : cls->methodNames) {
                if (m != "<init>" && m != "<clinit>") {
                    interesting.push_back(m);
                }
            }
            if (!interesting.empty()) {
                out << "    methods: ";
                for (size_t i = 0; i < interesting.size() && i < 8; i++) {
                    if (i > 0) out << ", ";
                    out << interesting[i];
                }
                if (interesting.size() > 8) out << ", ...";
                out << "\n";
            }

            out << "    " << cls->filePath << "\n";
        }
        out << "\n";
    }

    if (truncated) {
        out << "(results truncated — " << MAX_FILES << " file or " << MAX_MS / 1000 << "s limit reached)\n";
    }

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{
        "OBSERVATION: " + result +
        "Use READ: or DECOMPILE: to examine specific classes. "
        "Use XREFS: to find cross-references between classes."};
}

} // namespace area
