#include "features/read/ReadCodeTool.h"

#include <stddef.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <compare>
#include <functional>
#include <system_error>
#include <vector>

#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "domains/elf/disassembler.h"
#include "domains/smali/parser.h"
#include "util/file_io.h"

namespace fs = std::filesystem;

namespace area {
static bool hasElfMagic(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char buf[4];
    f.read(buf, 4);
    return f.gcount() == 4 &&
           buf[0] == '\x7f' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F';
}

static std::string formatSmaliFile(const smali::SmaliFile& parsed, const std::string& methodFilter) {
    std::ostringstream out;

    if (!methodFilter.empty()) {
        for (auto& m : parsed.methods) {
            if (m.name == methodFilter || m.name.find(methodFilter) != std::string::npos) {
                out << "Class: " << parsed.class_name << "\n"
                    << "Method: " << m.access << " " << m.name << m.signature << "\n"
                    << "Lines: " << m.line_start << "-" << m.line_end << "\n\n"
                    << m.body << "\n";

                auto calls = smali::extractCalls(m.body);
                if (!calls.empty()) {
                    out << "\nCalls from this method:\n";
                    for (auto& c : calls) {
                        out << "  invoke-" << c.invoke_type << " "
                            << c.target_class << "->" << c.target_method
                            << c.target_signature << "\n";
                    }
                }
                return out.str();
            }
        }
        out << "Method '" << methodFilter << "' not found in " << parsed.class_name << ".\n"
            << "Available methods:\n";
        for (auto& m : parsed.methods) {
            out << "  " << m.access << " " << m.name << m.signature << "\n";
        }
        return out.str();
    }

    out << "Class: " << parsed.class_name << "\n";
    if (!parsed.super_class.empty()) out << "Super: " << parsed.super_class << "\n";
    if (!parsed.source_file.empty()) out << "Source: " << parsed.source_file << "\n";
    if (!parsed.interfaces.empty()) {
        out << "Implements:";
        for (auto& i : parsed.interfaces) out << " " << i;
        out << "\n";
    }
    out << "\n";

    if (!parsed.fields.empty()) {
        out << "Fields:\n";
        for (auto& f : parsed.fields) {
            out << "  " << f.access << " " << f.name << ":" << f.type << "\n";
        }
        out << "\n";
    }

    out << "Methods (" << parsed.methods.size() << "):\n";
    for (auto& m : parsed.methods) {
        out << "  " << m.access << " " << m.name << m.signature
            << " [lines " << m.line_start << "-" << m.line_end << "]\n";
    }

    if (parsed.raw.size() <= 8000) {
        out << "\n--- Full code ---\n" << parsed.raw;
    } else {
        out << "\n--- Method bodies ---\n";
        for (auto& m : parsed.methods) {
            out << "\n" << m.body << "\n";
            if (out.str().size() > 12000) {
                out << "\n... (truncated, " << (parsed.methods.size()) << " methods total. "
                    << "Use READ: <path> <method_name> to view a specific method)\n";
                break;
            }
        }
    }

    return out.str();
}

static std::string formatElfFile(const std::string& contents, const std::string& filename,
                                  const std::string& funcFilter) {
    auto info = elf::disassemble(contents, filename);

    std::ostringstream out;
    out << "ELF binary: " << info.filename << "\n"
        << "Architecture: " << info.arch << "\n"
        << "Type: " << info.type << "\n";

    if (!info.imports.empty()) {
        out << "\nImports (" << info.imports.size() << "):\n";
        int shown = 0;
        for (auto& imp : info.imports) {
            out << "  " << imp << "\n";
            if (++shown >= 50) {
                out << "  ... and " << (info.imports.size() - shown) << " more\n";
                break;
            }
        }
    }

    out << "\nFunctions (" << info.functions.size() << "):\n";

    if (!funcFilter.empty()) {
        for (auto& func : info.functions) {
            if (func.name == funcFilter || func.name.find(funcFilter) != std::string::npos) {
                out << "\n" << func.name << " (0x" << std::hex << func.address
                    << ", " << std::dec << func.size << " bytes):\n"
                    << func.disassembly << "\n";
                return out.str();
            }
        }
        out << "Function '" << funcFilter << "' not found.\nAvailable functions:\n";
        for (auto& func : info.functions) {
            out << "  " << func.name << " (0x" << std::hex << func.address
                << ", " << std::dec << func.size << " bytes)\n";
        }
        return out.str();
    }

    size_t totalSize = 0;
    for (auto& func : info.functions) {
        out << "\n" << func.name << " (0x" << std::hex << func.address
            << ", " << std::dec << func.size << " bytes):\n"
            << func.disassembly << "\n";
        totalSize += func.disassembly.size();
        if (totalSize > 12000) {
            out << "\n... (truncated. Use READ: <path> <function_name> to view a specific function)\n";
            break;
        }
    }

    return out.str();
}

std::optional<ToolResult> ReadCodeTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("READ:"))
        return std::nullopt;

    std::string args = action.substr(5);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a file path.\n"
                          "Usage: READ: <path> [method_or_function_name]"};
    }

    std::string path, filter;

    auto spacePos = args.rfind(' ');
    if (spacePos != std::string::npos) {
        std::string maybePath = args.substr(0, spacePos);
        std::string maybeFilter = args.substr(spacePos + 1);
        while (!maybePath.empty() && maybePath.back() == ' ') maybePath.pop_back();
        while (!maybeFilter.empty() && maybeFilter[0] == ' ') maybeFilter.erase(0, 1);

        if (fs::exists(args)) {
            path = args;
        } else if (fs::exists(maybePath)) {
            path = maybePath;
            filter = maybeFilter;
        } else {
            path = args;
        }
    } else {
        path = args;
    }

    if (!fs::exists(path)) {
        return ToolResult{"OBSERVATION: File not found: " + path +
                          "\nUse FIND_FILES: to locate files."};
    }

    if (fs::is_directory(path)) {
        std::ostringstream out;
        out << "Directory: " << path << "\n\n";
        int smaliCount = 0, elfCount = 0, otherCount = 0;
        std::vector<std::string> files;
        std::error_code ec;
        for (auto it = fs::directory_iterator(path, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear(); continue;
            }
            std::string name = it->path().filename().string();
            if (it->is_regular_file(ec) && !ec) {
                if (name.ends_with(".smali")) smaliCount++;
                else if (hasElfMagic(it->path().string())) elfCount++;
                else otherCount++;
                files.push_back(name);
            } else if (!ec && it->is_directory(ec) && !ec) {
                files.push_back(name + "/");
            }
            if (ec) ec.clear();
        }
        std::sort(files.begin(), files.end());

        out << smaliCount << " smali files, " << elfCount << " ELF binaries, "
            << otherCount << " other files\n\n";
        for (auto& f : files) {
            out << "  " << f << "\n";
            if (out.str().size() > 8000) {
                out << "  ... (truncated)\n";
                break;
            }
        }
        std::string result = out.str();
        ctx.cb({AgentMessage::RESULT, result});
        return ToolResult{"OBSERVATION: " + result};
    }

    ctx.cb({AgentMessage::THINKING, "Reading: " + fs::path(path).filename().string()});

    if (path.ends_with(".smali")) {
        std::string contents = util::readFile(path);
        if (contents.empty()) {
            return ToolResult{"OBSERVATION: Could not read file: " + path};
        }
        auto parsed = smali::parse(contents);
        std::string result = formatSmaliFile(parsed, filter);
        ctx.cb({AgentMessage::RESULT, result});
        return ToolResult{"OBSERVATION: " + result};
    }

    if (hasElfMagic(path)) {
        std::string contents = util::readFile(path);
        if (contents.empty()) {
            return ToolResult{"OBSERVATION: Could not read file: " + path};
        }
        std::string result = formatElfFile(contents, fs::path(path).filename().string(), filter);
        ctx.cb({AgentMessage::RESULT, result});
        return ToolResult{"OBSERVATION: " + result};
    }

    std::string contents = util::readFile(path);
    if (contents.empty()) {
        return ToolResult{"OBSERVATION: Could not read file (empty or binary): " + path};
    }

    if (contents.size() > 10000) {
        auto totalSize = contents.size();
        contents.resize(10000);
        contents += "\n\n... (truncated at 10000 chars, file is "
                   + std::to_string(totalSize) + " chars total)";
    }

    std::string result = "File: " + path + " (" + std::to_string(contents.size()) + " bytes)\n\n" + contents;
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{"OBSERVATION: " + result};
}
}  // namespace area
