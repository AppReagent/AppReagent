#include "features/disasm/DisasmTool.h"
#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "domains/smali/parser.h"
#include "domains/elf/disassembler.h"
#include "util/file_io.h"

#include <algorithm>
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

namespace area {

static std::string toLower(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

std::optional<ToolResult> DisasmTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("DISASM:") != 0)
        return std::nullopt;

    std::string args = action.substr(7);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a file path.\n"
                          "Usage: DISASM: <path> [| <class>::<method>]"};
    }

    // Parse: path | method_filter
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

    if (!fs::exists(path)) {
        return ToolResult{"OBSERVATION: Error — file not found: " + path};
    }

    std::string contents = util::readFile(path);
    if (contents.empty()) {
        return ToolResult{"OBSERVATION: Error — could not read " + path};
    }

    // Handle smali files
    if (path.ends_with(".smali")) {
        auto parsed = smali::parse(contents);

        // Extract method name from filter (handle Class::method or just method)
        std::string filterMethod, filterClass;
        if (!filter.empty()) {
            auto sepPos = filter.find("::");
            if (sepPos != std::string::npos) {
                filterClass = filter.substr(0, sepPos);
                filterMethod = filter.substr(sepPos + 2);
            } else {
                filterMethod = filter;
            }
        }

        std::ostringstream out;
        out << "File: " << path << "\n";
        out << "Class: " << parsed.class_name << "\n";
        if (!parsed.super_class.empty())
            out << "Super: " << parsed.super_class << "\n";
        if (!parsed.interfaces.empty()) {
            out << "Implements:";
            for (auto& i : parsed.interfaces) out << " " << i;
            out << "\n";
        }

        if (!parsed.fields.empty()) {
            out << "Fields: " << parsed.fields.size() << "\n";
            for (auto& f : parsed.fields) {
                out << "  " << f.access << " " << f.name << ":" << f.type << "\n";
            }
        }
        out << "Methods: " << parsed.methods.size() << "\n\n";

        if (filter.empty()) {
            // List all methods with signatures
            out << "--- Method Index ---\n";
            for (size_t i = 0; i < parsed.methods.size(); i++) {
                auto& m = parsed.methods[i];
                auto calls = smali::extractCalls(m.body);
                out << "  " << (i + 1) << ". " << m.access << " " << m.name << m.signature
                    << " (lines " << m.line_start << "-" << m.line_end
                    << ", " << calls.size() << " call(s))\n";
            }
            out << "\nUse DISASM: " << path << " | <method-name> to see full code.\n";
        } else {
            // Show matching methods
            std::string filterLower = toLower(filterMethod);
            bool found = false;

            for (auto& m : parsed.methods) {
                bool matches = false;
                if (toLower(m.name).find(filterLower) != std::string::npos)
                    matches = true;
                if (!filterClass.empty() &&
                    toLower(parsed.class_name).find(toLower(filterClass)) == std::string::npos)
                    matches = false;

                if (!matches) continue;
                found = true;

                out << "--- " << m.access << " " << m.name << m.signature
                    << " (lines " << m.line_start << "-" << m.line_end << ") ---\n";
                out << m.body << "\n";

                // Show call targets
                auto calls = smali::extractCalls(m.body);
                if (!calls.empty()) {
                    out << "  Call targets:\n";
                    for (auto& c : calls) {
                        out << "    [" << c.invoke_type << "] "
                            << c.target_class << "->" << c.target_method
                            << c.target_signature << "\n";
                    }
                    out << "\n";
                }
            }

            if (!found) {
                out << "No method matching '" << filter << "' found.\n"
                    << "Available methods:\n";
                for (auto& m : parsed.methods) {
                    out << "  " << m.name << m.signature << "\n";
                }
            }
        }

        std::string formatted = out.str();
        // Truncate if very long
        if (formatted.size() > 8000) {
            formatted = formatted.substr(0, 8000) + "\n... (truncated, " +
                std::to_string(formatted.size()) + " bytes total)";
        }
        ctx.cb({AgentMessage::RESULT, formatted});
        return ToolResult{"OBSERVATION: " + formatted};
    }

    // Handle ELF files
    if (elf::isElf(contents)) {
        ctx.cb({AgentMessage::THINKING, "Disassembling ELF: " + path});
        auto info = elf::disassemble(contents, path);

        std::ostringstream out;
        out << "File: " << path << "\n"
            << "Type: " << info.type << "\n"
            << "Architecture: " << info.arch << "\n";

        if (!info.imports.empty()) {
            out << "Imports: " << info.imports.size() << "\n";
            int shown = 0;
            for (auto& imp : info.imports) {
                if (shown++ >= 20) {
                    out << "  ... and " << (info.imports.size() - 20) << " more\n";
                    break;
                }
                out << "  " << imp << "\n";
            }
        }
        if (!info.exports.empty()) {
            out << "Exports: " << info.exports.size() << "\n";
            int shown = 0;
            for (auto& exp : info.exports) {
                if (shown++ >= 20) {
                    out << "  ... and " << (info.exports.size() - 20) << " more\n";
                    break;
                }
                out << "  " << exp << "\n";
            }
        }
        out << "\n";

        if (filter.empty()) {
            out << "Functions: " << info.functions.size() << "\n";
            int shown = 0;
            for (auto& func : info.functions) {
                if (shown++ >= 40) {
                    out << "  ... and " << (info.functions.size() - 40) << " more\n";
                    break;
                }
                out << "  " << func.name << " (0x" << std::hex << func.address
                    << ", " << std::dec << func.size << " bytes)\n";
            }
            out << "\nUse DISASM: " << path << " | <function-name> to see assembly.\n";
        } else {
            std::string filterLower = toLower(filter);
            bool found = false;
            for (auto& func : info.functions) {
                if (toLower(func.name).find(filterLower) == std::string::npos)
                    continue;
                found = true;
                out << "--- " << func.name << " @ 0x" << std::hex << func.address
                    << " (" << std::dec << func.size << " bytes) ---\n"
                    << func.disassembly << "\n\n";
            }
            if (!found) {
                out << "No function matching '" << filter << "' found.\n";
            }
        }

        std::string formatted = out.str();
        if (formatted.size() > 8000) {
            formatted = formatted.substr(0, 8000) + "\n... (truncated)";
        }
        ctx.cb({AgentMessage::RESULT, formatted});
        return ToolResult{"OBSERVATION: " + formatted};
    }

    return ToolResult{
        "OBSERVATION: Error — " + path + " is not a recognized format (expected .smali or ELF)."};
}

} // namespace area
