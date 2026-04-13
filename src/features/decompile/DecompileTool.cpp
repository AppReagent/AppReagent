#include "features/decompile/DecompileTool.h"

#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "infra/agent/Agent.h"
#include "infra/tools/ToolContext.h"

namespace fs = std::filesystem;

namespace area {

static std::string typeToJava(const std::string& desc) {
    if (desc.empty()) return "void";
    if (desc == "V") return "void";
    if (desc == "Z") return "boolean";
    if (desc == "B") return "byte";
    if (desc == "C") return "char";
    if (desc == "S") return "short";
    if (desc == "I") return "int";
    if (desc == "J") return "long";
    if (desc == "F") return "float";
    if (desc == "D") return "double";

    if (desc[0] == '[') {
        return typeToJava(desc.substr(1)) + "[]";
    }

    if (desc[0] == 'L' && desc.back() == ';') {
        std::string full = desc.substr(1, desc.size() - 2);
        for (auto& c : full) if (c == '/') c = '.';

        auto lastDot = full.rfind('.');
        if (lastDot != std::string::npos) {
            std::string pkg = full.substr(0, lastDot);
            std::string simple = full.substr(lastDot + 1);
            if (pkg == "java.lang" || pkg == "java.util" || pkg == "java.io" ||
                pkg == "java.net" || pkg == "javax.crypto" || pkg == "javax.crypto.spec") {
                return simple;
            }
            return full;
        }
        return full;
    }

    return desc;
}

struct MethodSig {
    std::vector<std::string> paramTypes;
    std::string returnType;
};

static MethodSig parseMethodSig(const std::string& sig) {
    MethodSig result;
    if (sig.empty() || sig[0] != '(') return result;

    size_t i = 1;
    while (i < sig.size() && sig[i] != ')') {
        if (sig[i] == '[') {
            std::string type;
            while (i < sig.size() && sig[i] == '[') {
                type += '['; i++;
            }
            if (i >= sig.size()) break;
            if (sig[i] == 'L') {
                auto end = sig.find(';', i);
                if (end == std::string::npos) break;
                type += sig.substr(i, end - i + 1);
                i = end + 1;
            } else {
                type += sig[i]; i++;
            }
            result.paramTypes.push_back(typeToJava(type));
        } else if (sig[i] == 'L') {
            auto end = sig.find(';', i);
            if (end == std::string::npos) break;
            result.paramTypes.push_back(typeToJava(sig.substr(i, end - i + 1)));
            i = end + 1;
        } else {
            result.paramTypes.push_back(typeToJava(std::string(1, sig[i])));
            i++;
        }
    }

    if (i < sig.size() && sig[i] == ')') {
        result.returnType = typeToJava(sig.substr(i + 1));
    }

    return result;
}

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static std::string toLowerStr(const std::string& s) {
    std::string result = s;
    for (auto& c : result) c = std::tolower(static_cast<unsigned char>(c));
    return result;
}

static std::string classSimpleName(const std::string& desc) {
    std::string java = typeToJava(desc);
    auto dot = java.rfind('.');
    if (dot != std::string::npos) return java.substr(dot + 1);
    return java;
}

static std::string extractClassName(const std::string& ref) {
    auto arrow = ref.find("->");
    if (arrow != std::string::npos) {
        return classSimpleName(ref.substr(0, arrow));
    }
    return classSimpleName(ref);
}

static std::string extractMemberName(const std::string& ref) {
    auto arrow = ref.find("->");
    if (arrow == std::string::npos) return ref;
    std::string after = ref.substr(arrow + 2);

    auto colon = after.find(':');
    if (colon != std::string::npos) return after.substr(0, colon);

    auto paren = after.find('(');
    if (paren != std::string::npos) return after.substr(0, paren);
    return after;
}

static std::string extractFieldType(const std::string& ref) {
    auto colon = ref.find(':');
    if (colon == std::string::npos) return "";
    return typeToJava(ref.substr(colon + 1));
}

static std::string extractReturnType(const std::string& ref) {
    auto paren = ref.find(')');
    if (paren == std::string::npos) return "void";
    return typeToJava(ref.substr(paren + 1));
}

struct Ops2 { std::string a, b; bool valid; };
struct Ops3 { std::string a, b, c; bool valid; };

static Ops2 splitOps2(const std::string& operands) {
    auto comma = operands.find(',');
    if (comma == std::string::npos) return {{}, {}, false};
    return {trim(operands.substr(0, comma)), trim(operands.substr(comma + 1)), true};
}

static Ops3 splitOps3(const std::string& operands) {
    auto comma1 = operands.find(',');
    if (comma1 == std::string::npos) return {{}, {}, {}, false};
    auto comma2 = operands.find(',', comma1 + 1);
    if (comma2 == std::string::npos) return {{}, {}, {}, false};
    return {
        trim(operands.substr(0, comma1)),
        trim(operands.substr(comma1 + 1, comma2 - comma1 - 1)),
        trim(operands.substr(comma2 + 1)),
        true
    };
}

static std::vector<std::string> parseRegs(const std::string& s) {
    std::vector<std::string> regs;
    auto braceStart = s.find('{');
    auto braceEnd = s.find('}');
    if (braceStart == std::string::npos || braceEnd == std::string::npos) return regs;
    std::string inner = s.substr(braceStart + 1, braceEnd - braceStart - 1);
    std::istringstream ss(inner);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        std::string t = trim(tok);
        auto dotdot = t.find("..");
        if (dotdot != std::string::npos) {
            std::string startReg = trim(t.substr(0, dotdot));
            std::string endReg = trim(t.substr(dotdot + 2));
            regs.push_back(startReg);
            if (startReg.size() > 1 && endReg.size() > 1) {
                try {
                    char prefix = startReg[0];
                    int first = std::stoi(startReg.substr(1));
                    int last = std::stoi(endReg.substr(1));
                    for (int r = first + 1; r <= last; r++) {
                        regs.push_back(std::string(1, prefix) + std::to_string(r));
                    }
                } catch (const std::exception&) {
                }
            }
        } else if (!t.empty()) {
            regs.push_back(t);
        }
    }
    return regs;
}

static std::string extractRef(const std::string& s) {
    auto braceEnd = s.find('}');
    if (braceEnd != std::string::npos) {
        std::string after = s.substr(braceEnd + 1);
        auto comma = after.find(',');
        if (comma != std::string::npos) {
            return trim(after.substr(comma + 1));
        }
        return trim(after);
    }
    return "";
}

static std::string buildArgString(const std::vector<std::string>& regs, size_t startIdx) {
    std::string args;
    for (size_t r = startIdx; r < regs.size(); r++) {
        if (r > startIdx) args += ", ";
        args += regs[r];
    }
    return args;
}

struct DecompileState {
    std::ostringstream& out;
    const std::string indent = "    ";
    std::string pendingCall;
    bool pendingNeedsResult = false;
    std::map<std::string, std::string> newInstances;
};

static void flushPendingCall(DecompileState& state) {
    if (state.pendingNeedsResult && !state.pendingCall.empty()) {
        state.out << state.indent << state.pendingCall << ";\n";
        state.pendingCall.clear();
        state.pendingNeedsResult = false;
    }
}

static void emitCall(DecompileState& state, const std::string& call,
                     const std::string& retType) {
    if (retType != "void") {
        state.pendingCall = call;
        state.pendingNeedsResult = true;
    } else {
        state.out << state.indent << call << ";\n";
    }
}

static bool handleConst(DecompileState& state, const std::string& opcode,
                        const std::string& operands) {
    if (opcode == "const-string" || opcode == "const-string/jumbo") {
        auto [reg, val, ok] = splitOps2(operands);
        if (ok) state.out << state.indent << "String " << reg << " = " << val << ";\n";
        return true;
    }
    if (opcode.starts_with("const/") || opcode == "const") {
        auto [reg, val, ok] = splitOps2(operands);
        if (ok) {
            if (val == "0x0") state.out << state.indent << "int " << reg << " = 0;\n";
            else if (val == "0x1") state.out << state.indent << "int " << reg << " = 1; // true\n";
            else state.out << state.indent << "int " << reg << " = " << val << ";\n";
        }
        return true;
    }
    if (opcode.starts_with("const-wide")) {
        auto [reg, val, ok] = splitOps2(operands);
        if (ok) state.out << state.indent << "long " << reg << " = " << val << ";\n";
        return true;
    }
    if (opcode == "new-instance") {
        auto [reg, type, ok] = splitOps2(operands);
        if (ok) state.newInstances[reg] = typeToJava(type);
        return true;
    }
    return false;
}

static bool handleInvoke(DecompileState& state, const std::string& opcode,
                         const std::string& operands) {
    bool isDirect = opcode.starts_with("invoke-direct");
    bool isVirtual = opcode.starts_with("invoke-virtual");
    bool isInterface = opcode.starts_with("invoke-interface");
    bool isStatic = opcode.starts_with("invoke-static");
    bool isSuper = opcode.starts_with("invoke-super");

    if (!isDirect && !isVirtual && !isInterface && !isStatic && !isSuper) return false;

    auto regs = parseRegs(operands);
    std::string ref = extractRef(operands);
    std::string member = extractMemberName(ref);
    std::string retType = extractReturnType(ref);

    if (isDirect && member == "<init>" && !regs.empty()) {
        std::string objReg = regs[0];
        auto it = state.newInstances.find(objReg);
        if (it != state.newInstances.end()) {
            std::string type = it->second;
            state.out << state.indent << type << " " << objReg << " = new "
                      << type << "(" << buildArgString(regs, 1) << ");\n";
            state.newInstances.erase(it);
            return true;
        }
        if (objReg == "p0") {
            state.out << state.indent << "super(" << buildArgString(regs, 1)
                      << "); // " << extractClassName(ref) << "\n";
            return true;
        }
    }

    std::string call;
    if (isStatic) {
        call = extractClassName(ref) + "." + member + "(" + buildArgString(regs, 0) + ")";
    } else if (isSuper) {
        call = "super." + member + "(" + buildArgString(regs, 1) + ")";
    } else if (!regs.empty()) {
        std::string obj = regs[0];
        if ((isVirtual || isInterface) && obj == "p0") obj = "this";
        call = obj + "." + member + "(" + buildArgString(regs, 1) + ")";
    } else {
        return true;
    }

    emitCall(state, call, retType);
    return true;
}

static bool handleMoveResult(DecompileState& state, const std::string& opcode,
                             const std::string& operands) {
    if (!opcode.starts_with("move-result")) return false;
    std::string reg = trim(operands);
    if (state.pendingNeedsResult && !state.pendingCall.empty()) {
        state.out << state.indent << reg << " = " << state.pendingCall << ";\n";
        state.pendingCall.clear();
        state.pendingNeedsResult = false;
    } else {
        state.out << state.indent << reg << " = <result>;\n";
    }
    return true;
}

static bool handleFieldAccess(DecompileState& state, const std::string& opcode,
                               const std::string& operands) {
    if (opcode.starts_with("iget")) {
        auto [dest, obj, ref, ok] = splitOps3(operands);
        if (ok) {
            if (obj == "p0") obj = "this";
            state.out << state.indent << extractFieldType(ref) << " " << dest
                      << " = " << obj << "." << extractMemberName(ref) << ";\n";
        }
        return true;
    }
    if (opcode.starts_with("iput")) {
        auto [val, obj, ref, ok] = splitOps3(operands);
        if (ok) {
            if (obj == "p0") obj = "this";
            state.out << state.indent << obj << "." << extractMemberName(ref)
                      << " = " << val << ";\n";
        }
        return true;
    }
    if (opcode.starts_with("sget")) {
        auto [dest, ref, ok] = splitOps2(operands);
        if (ok) {
            state.out << state.indent << extractFieldType(ref) << " " << dest << " = "
                      << extractClassName(ref) << "." << extractMemberName(ref) << ";\n";
        }
        return true;
    }
    if (opcode.starts_with("sput")) {
        auto [val, ref, ok] = splitOps2(operands);
        if (ok) {
            state.out << state.indent << extractClassName(ref) << "." << extractMemberName(ref)
                      << " = " << val << ";\n";
        }
        return true;
    }
    return false;
}

static bool handleControlFlow(DecompileState& state, const std::string& opcode,
                               const std::string& operands) {
    if (opcode.starts_with("if-")) {
        static const std::map<std::string, std::string> unaryConds = {
            {"if-eqz", " == 0"}, {"if-nez", " != 0"},
            {"if-ltz", " < 0"},  {"if-gez", " >= 0"},
            {"if-gtz", " > 0"},  {"if-lez", " <= 0"},
        };
        auto it = unaryConds.find(opcode);
        if (it != unaryConds.end()) {
            auto [reg, label, ok] = splitOps2(operands);
            if (ok) {
                if (!label.empty() && label[0] == ':') label = label.substr(1);
                state.out << state.indent << "if (" << reg << it->second
                          << ") goto " << label << ";\n";
            }
            return true;
        }

        static const std::map<std::string, std::string> binaryConds = {
            {"if-eq", " == "}, {"if-ne", " != "},
            {"if-lt", " < "},  {"if-ge", " >= "},
            {"if-gt", " > "},  {"if-le", " <= "},
        };
        auto it2 = binaryConds.find(opcode);
        std::string op = (it2 != binaryConds.end()) ? it2->second : " ? ";
        auto [r1, r2, label, ok] = splitOps3(operands);
        if (ok) {
            if (!label.empty() && label[0] == ':') label = label.substr(1);
            state.out << state.indent << "if (" << r1 << op << r2
                      << ") goto " << label << ";\n";
        }
        return true;
    }

    if (opcode == "goto" || opcode == "goto/16" || opcode == "goto/32") {
        std::string label = trim(operands);
        if (!label.empty() && label[0] == ':') label = label.substr(1);
        state.out << state.indent << "goto " << label << ";\n";
        return true;
    }

    if (opcode == "return-void") {
        state.out << state.indent << "return;\n";
        return true;
    }
    if (opcode == "return" || opcode == "return-object" || opcode == "return-wide") {
        state.out << state.indent << "return " << trim(operands) << ";\n";
        return true;
    }
    if (opcode == "throw") {
        state.out << state.indent << "throw " << trim(operands) << ";\n";
        return true;
    }

    return false;
}

static bool handleArithmetic(DecompileState& state, const std::string& opcode,
                              const std::string& operands) {
    bool isArith = opcode.starts_with("add-") || opcode.starts_with("sub-") ||
                   opcode.starts_with("mul-") || opcode.starts_with("div-") ||
                   opcode.starts_with("rem-") || opcode.starts_with("and-") ||
                   opcode.starts_with("or-")  || opcode.starts_with("xor-") ||
                   opcode.starts_with("shl-") || opcode.starts_with("shr-") ||
                   opcode.starts_with("ushr-");
    if (!isArith) return false;

    std::string op = "+";
    if (opcode.starts_with("sub")) op = "-";
    else if (opcode.starts_with("mul")) op = "*";
    else if (opcode.starts_with("div")) op = "/";
    else if (opcode.starts_with("rem")) op = "%";
    else if (opcode.starts_with("and")) op = "&";
    else if (opcode.starts_with("or-")) op = "|";
    else if (opcode.starts_with("xor")) op = "^";
    else if (opcode.starts_with("ushr")) op = ">>>";
    else if (opcode.starts_with("shl")) op = "<<";
    else if (opcode.starts_with("shr")) op = ">>";

    if (opcode.find("/2addr") != std::string::npos) {
        auto [r1, r2, ok] = splitOps2(operands);
        if (ok) state.out << state.indent << r1 << " " << op << "= " << r2 << ";\n";
    } else {
        auto [dest, r1, r2, ok] = splitOps3(operands);
        if (ok) state.out << state.indent << dest << " = " << r1 << " " << op << " " << r2 << ";\n";
    }
    return true;
}

static bool handleArray(DecompileState& state, const std::string& opcode,
                         const std::string& operands) {
    if (opcode == "new-array") {
        auto [dest, size, type, ok] = splitOps3(operands);
        if (ok) {
            std::string jtype = typeToJava(type);
            state.out << state.indent << jtype << " " << dest
                      << " = new " << jtype << "[" << size << "];\n";
        }
        return true;
    }
    if (opcode.starts_with("aget")) {
        auto [dest, arr, idx, ok] = splitOps3(operands);
        if (ok) state.out << state.indent << dest << " = " << arr << "[" << idx << "];\n";
        return true;
    }
    if (opcode.starts_with("aput")) {
        auto [val, arr, idx, ok] = splitOps3(operands);
        if (ok) state.out << state.indent << arr << "[" << idx << "] = " << val << ";\n";
        return true;
    }
    if (opcode == "array-length") {
        auto [dest, arr, ok] = splitOps2(operands);
        if (ok) state.out << state.indent << "int " << dest << " = " << arr << ".length;\n";
        return true;
    }
    if (opcode.starts_with("filled-new-array")) {
        auto regs = parseRegs(operands);
        std::string type = typeToJava(extractRef(operands));
        state.pendingCall = "new " + type + " {" + buildArgString(regs, 0) + "}";
        state.pendingNeedsResult = true;
        return true;
    }
    if (opcode == "fill-array-data") {
        state.out << state.indent << "// " << opcode << " " << operands << "\n";
        return true;
    }
    return false;
}

static bool handleMisc(DecompileState& state, const std::string& opcode,
                        const std::string& operands) {
    if (opcode == "check-cast") {
        auto [reg, type, ok] = splitOps2(operands);
        if (ok) state.out << state.indent << reg << " = (" << typeToJava(type) << ") " << reg << ";\n";
        return true;
    }
    if (opcode == "instance-of") {
        auto [dest, obj, type, ok] = splitOps3(operands);
        if (ok) {
            state.out << state.indent << "boolean " << dest << " = " << obj
                      << " instanceof " << typeToJava(type) << ";\n";
        }
        return true;
    }
    if (opcode == "move-exception") {
        state.out << state.indent << trim(operands) << " = <caught exception>;\n";
        return true;
    }
    if (opcode.starts_with("move")) {
        auto [dest, src, ok] = splitOps2(operands);
        if (ok) state.out << state.indent << dest << " = " << src << ";\n";
        return true;
    }
    if (opcode.starts_with("neg-") || opcode.starts_with("not-")) {
        auto [dest, src, ok] = splitOps2(operands);
        if (ok) {
            std::string op = opcode.starts_with("neg") ? "-" : "~";
            state.out << state.indent << dest << " = " << op << src << ";\n";
        }
        return true;
    }
    if (opcode.find("-to-") != std::string::npos) {
        auto [dest, src, ok] = splitOps2(operands);
        if (ok) {
            auto toPos = opcode.find("-to-");
            state.out << state.indent << dest << " = (" << opcode.substr(toPos + 4) << ") " << src << ";\n";
        }
        return true;
    }
    if (opcode.starts_with("cmp")) {
        auto [dest, r1, r2, ok] = splitOps3(operands);
        if (ok) {
            state.out << state.indent << "int " << dest
                      << " = compare(" << r1 << ", " << r2 << ");\n";
        }
        return true;
    }
    if (opcode == "nop") return true;
    if (opcode == "monitor-enter") {
        state.out << state.indent << "synchronized(" << trim(operands) << ") { // monitor-enter\n";
        return true;
    }
    if (opcode == "monitor-exit") {
        state.out << state.indent << "} // monitor-exit " << trim(operands) << "\n";
        return true;
    }
    if (opcode == "packed-switch" || opcode == "sparse-switch") {
        state.out << state.indent << "// " << opcode << " " << operands << "\n";
        return true;
    }
    return false;
}

static std::string decompileMethod(const std::vector<std::string>& lines,
                                    int startLine, int endLine,
                                    const std::string& className) {
    std::ostringstream out;
    DecompileState state{out};

    std::string methodLine = trim(lines[startLine]);
    std::string access, methodName, fullSig;
    {
        std::string rest = methodLine;
        if (rest.starts_with(".method")) rest = rest.substr(7);
        rest = trim(rest);

        std::vector<std::string> parts;
        std::istringstream ss(rest);
        std::string tok;
        while (ss >> tok) parts.push_back(tok);

        if (!parts.empty()) {
            fullSig = parts.back();
            for (size_t i = 0; i + 1 < parts.size(); i++) {
                if (!access.empty()) access += " ";
                access += parts[i];
            }
        }
    }

    auto parenPos = fullSig.find('(');
    if (parenPos != std::string::npos) {
        methodName = fullSig.substr(0, parenPos);
        auto msig = parseMethodSig(fullSig.substr(parenPos));

        std::map<int, std::string> paramNames;
        for (int i = startLine + 1; i < endLine; i++) {
            std::string line = trim(lines[i]);
            if (!line.starts_with(".param")) continue;
            auto comma = line.find(',');
            if (comma == std::string::npos) continue;
            std::string reg = trim(line.substr(6, comma - 6));
            std::string name = trim(line.substr(comma + 1));
            if (name.size() >= 2 && name.front() == '"' && name.back() == '"') {
                name = name.substr(1, name.size() - 2);
            }
            if (reg.size() > 1 && reg[0] == 'p') {
                try {
                    int idx = std::stoi(reg.substr(1));
                    paramNames[idx] = name;
                } catch (const std::exception&) {
                }
            }
        }

        bool isStatic = access.find("static") != std::string::npos;
        int paramOffset = isStatic ? 0 : 1;

        out << access;
        if (!access.empty()) out << " ";
        out << msig.returnType << " " << methodName << "(";
        for (size_t i = 0; i < msig.paramTypes.size(); i++) {
            if (i > 0) out << ", ";
            out << msig.paramTypes[i] << " ";
            auto it = paramNames.find(static_cast<int>(i) + paramOffset);
            if (it != paramNames.end()) {
                out << it->second;
            } else {
                out << "p" << (i + paramOffset);
            }
        }
        out << ") {\n";
    } else {
        methodName = fullSig;
        out << access << " " << methodName << "() {\n";
    }

    for (int i = startLine + 1; i < endLine; i++) {
        std::string line = trim(lines[i]);
        if (line.empty() || line.starts_with(".method") || line.starts_with(".end method"))
            continue;

        if (line.starts_with(".locals") || line.starts_with(".param") ||
            line.starts_with(".annotation") || line.starts_with(".end annotation") ||
            line.starts_with(".prologue") || line.starts_with(".line") ||
            line.starts_with(".registers") || line.starts_with(".enum") ||
            line.starts_with(".source"))
            continue;

        if (line[0] == ':') {
            out << "\n" << state.indent << line.substr(1) << ":\n";
            continue;
        }

        if (line[0] == '#') {
            out << state.indent << "//" << line.substr(1) << "\n";
            continue;
        }

        if (line.starts_with(".catch")) {
            auto braceStart = line.find('{');
            auto braceEnd = line.find('}');
            if (braceStart != std::string::npos && braceEnd != std::string::npos) {
                std::string inner = line.substr(braceStart + 1, braceEnd - braceStart - 1);
                std::string excType = "Exception";
                auto semi = line.find(';');
                if (semi != std::string::npos && semi < braceStart) {
                    excType = classSimpleName(
                        line.substr(line.find('L'), semi - line.find('L') + 1));
                }
                out << state.indent << "// try-catch(" << excType << ") " << trim(inner) << "\n";
            }
            continue;
        }

        std::string opcode, operands;
        auto spacePos = line.find(' ');
        if (spacePos != std::string::npos) {
            opcode = line.substr(0, spacePos);
            operands = trim(line.substr(spacePos + 1));
        } else {
            opcode = line;
        }

        if (handleMoveResult(state, opcode, operands)) continue;
        flushPendingCall(state);

        if (handleConst(state, opcode, operands)) continue;
        if (handleInvoke(state, opcode, operands)) continue;
        if (handleFieldAccess(state, opcode, operands)) continue;
        if (handleControlFlow(state, opcode, operands)) continue;
        if (handleArithmetic(state, opcode, operands)) continue;
        if (handleArray(state, opcode, operands)) continue;
        if (handleMisc(state, opcode, operands)) continue;

        out << state.indent << "// " << line << "\n";
    }

    flushPendingCall(state);
    out << "}\n";
    return out.str();
}

struct ClassInfo {
    std::string name;
    std::string superClass;
    std::vector<std::string> interfaces;
    std::vector<std::string> fields;
};

static ClassInfo parseClassInfo(const std::vector<std::string>& lines) {
    ClassInfo info;
    for (auto& l : lines) {
        std::string trimmed = trim(l);
        if (trimmed.starts_with(".class")) {
            auto lastSpace = trimmed.rfind(' ');
            if (lastSpace != std::string::npos)
                info.name = typeToJava(trimmed.substr(lastSpace + 1));
        } else if (trimmed.starts_with(".super")) {
            auto sp = trimmed.find(' ');
            if (sp != std::string::npos)
                info.superClass = typeToJava(trim(trimmed.substr(sp + 1)));
        } else if (trimmed.starts_with(".implements")) {
            auto sp = trimmed.find(' ');
            if (sp != std::string::npos)
                info.interfaces.push_back(typeToJava(trim(trimmed.substr(sp + 1))));
        } else if (trimmed.starts_with(".field")) {
            std::string rest = trim(trimmed.substr(6));
            auto colonPos = rest.rfind(':');
            if (colonPos != std::string::npos) {
                std::string nameAndAccess = rest.substr(0, colonPos);
                std::string type = typeToJava(rest.substr(colonPos + 1));
                auto lastSp = nameAndAccess.rfind(' ');
                std::string fieldAccess, fieldName;
                if (lastSp != std::string::npos) {
                    fieldAccess = nameAndAccess.substr(0, lastSp);
                    fieldName = nameAndAccess.substr(lastSp + 1);
                } else {
                    fieldName = nameAndAccess;
                }
                info.fields.push_back(fieldAccess + " " + type + " " + fieldName);
            }
        }
    }
    return info;
}

struct MethodBounds {
    int start;
    int end;
    std::string name;
};

static std::vector<MethodBounds> findMethods(const std::vector<std::string>& lines) {
    std::vector<MethodBounds> methods;
    for (int i = 0; i < static_cast<int>(lines.size()); i++) {
        std::string trimmed = trim(lines[i]);
        if (!trimmed.starts_with(".method")) continue;

        int endLine = i;
        for (int j = i + 1; j < static_cast<int>(lines.size()); j++) {
            if (trim(lines[j]).starts_with(".end method")) {
                endLine = j;
                break;
            }
        }

        auto paren = trimmed.find('(');
        if (paren != std::string::npos) {
            std::string before = trimmed.substr(0, paren);
            auto lastSp = before.rfind(' ');
            std::string name = (lastSp != std::string::npos) ? before.substr(lastSp + 1) : before;
            methods.push_back({i, endLine, name});
        }
        i = endLine;
    }
    return methods;
}

std::optional<ToolResult> DecompileTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (!action.starts_with("DECOMPILE:"))
        return std::nullopt;

    std::string args = trim(action.substr(10));
    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a .smali file path after DECOMPILE:"};
    }

    std::string filePath, modifier;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        filePath = trim(args.substr(0, pipePos));
        modifier = trim(args.substr(pipePos + 1));
    } else {
        filePath = args;
    }

    if (!filePath.empty() && filePath[0] == '~') {
        if (auto home = std::getenv("HOME")) {
            filePath = std::string(home) + filePath.substr(1);
        }
    }

    if (!fs::exists(filePath)) {
        return ToolResult{"OBSERVATION: File not found: " + filePath};
    }
    if (!fs::is_regular_file(filePath)) {
        return ToolResult{"OBSERVATION: Not a file: " + filePath};
    }
    if (toLowerStr(fs::path(filePath).extension().string()) != ".smali") {
        return ToolResult{"OBSERVATION: DECOMPILE only supports .smali files. Got: " +
                          fs::path(filePath).extension().string()};
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

    ctx.cb({AgentMessage::THINKING, "Decompiling " + filePath + "..."});

    auto classInfo = parseClassInfo(lines);
    auto methods = findMethods(lines);

    if (methods.empty()) {
        return ToolResult{"OBSERVATION: No methods found in " + filePath};
    }

    std::string targetMethod;
    if (!modifier.empty()) {
        std::string modLower = toLowerStr(modifier);
        targetMethod = modLower.starts_with("method") ? trim(modifier.substr(6)) : modifier;
    }

    if (!targetMethod.empty()) {
        std::string targetLower = toLowerStr(targetMethod);
        std::vector<MethodBounds> filtered;
        for (auto& m : methods) {
            if (toLowerStr(m.name).find(targetLower) != std::string::npos) {
                filtered.push_back(m);
            }
        }
        if (filtered.empty()) {
            std::ostringstream avail;
            avail << "OBSERVATION: Method \"" << targetMethod << "\" not found. Available methods:\n";
            for (auto& m : methods) {
                avail << "  " << m.name << " (line " << (m.start + 1) << ")\n";
            }
            return ToolResult{avail.str()};
        }
        methods = filtered;
    }

    static constexpr int MAX_METHODS = 20;
    bool truncatedMethods = false;
    if (static_cast<int>(methods.size()) > MAX_METHODS) {
        methods.resize(MAX_METHODS);
        truncatedMethods = true;
    }

    std::ostringstream out;
    out << "// Decompiled from: " << filePath << "\n";
    out << "class " << classInfo.name;
    if (!classInfo.superClass.empty() && classInfo.superClass != "Object" &&
        classInfo.superClass != "java.lang.Object") {
        out << " extends " << classInfo.superClass;
    }
    if (!classInfo.interfaces.empty()) {
        out << " implements ";
        for (size_t i = 0; i < classInfo.interfaces.size(); i++) {
            if (i > 0) out << ", ";
            out << classInfo.interfaces[i];
        }
    }
    out << " {\n\n";

    if (!classInfo.fields.empty() && targetMethod.empty()) {
        for (auto& f : classInfo.fields) {
            out << "    " << f << ";\n";
        }
        out << "\n";
    }

    for (auto& m : methods) {
        out << decompileMethod(lines, m.start, m.end, classInfo.name) << "\n";
    }

    if (truncatedMethods) {
        out << "// ... " << (methods.size()) << " methods shown, more available. "
            << "Use DECOMPILE: " << filePath << " | method <name> to target a specific method.\n";
    }

    out << "}\n";

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{
        "OBSERVATION: Pseudo-Java decompilation of " + filePath + ":\n\n" + result +
        "\nNote: This is approximate pseudo-Java. Register names (v0, p0) are preserved. "
        "p0 = 'this' for instance methods. Use READ: to see original smali."};
}
}  // namespace area
