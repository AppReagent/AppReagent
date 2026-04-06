#include "tools/DecompileTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace area {

// --- Smali type descriptor to Java type ---
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

    // Array types
    if (desc[0] == '[') {
        return typeToJava(desc.substr(1)) + "[]";
    }

    // Object types: Ljava/lang/String; -> String
    if (desc[0] == 'L' && desc.back() == ';') {
        std::string full = desc.substr(1, desc.size() - 2);
        // Replace / with .
        for (auto& c : full) if (c == '/') c = '.';
        // Use simple name for common types
        auto lastDot = full.rfind('.');
        if (lastDot != std::string::npos) {
            std::string pkg = full.substr(0, lastDot);
            std::string simple = full.substr(lastDot + 1);
            // For java.lang.* and short names, use simple name
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

// Parse method signature: (Ljava/lang/String;I)V -> {params, returnType}
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
            // Array: collect all [ prefixes then the base type
            std::string type;
            while (i < sig.size() && sig[i] == '[') { type += '['; i++; }
            if (i < sig.size()) {
                if (sig[i] == 'L') {
                    auto end = sig.find(';', i);
                    if (end != std::string::npos) {
                        type += sig.substr(i, end - i + 1);
                        i = end + 1;
                    }
                } else {
                    type += sig[i]; i++;
                }
            }
            result.paramTypes.push_back(typeToJava(type));
        } else if (sig[i] == 'L') {
            auto end = sig.find(';', i);
            if (end != std::string::npos) {
                result.paramTypes.push_back(typeToJava(sig.substr(i, end - i + 1)));
                i = end + 1;
            } else break;
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

// Extract class simple name from Lcom/example/Foo; -> Foo
static std::string classSimpleName(const std::string& desc) {
    std::string java = typeToJava(desc);
    auto dot = java.rfind('.');
    if (dot != std::string::npos) return java.substr(dot + 1);
    return java;
}

// Extract class name from Lcom/example/Foo;->method -> Foo
static std::string extractClassName(const std::string& ref) {
    auto arrow = ref.find("->");
    if (arrow != std::string::npos) {
        return classSimpleName(ref.substr(0, arrow));
    }
    return classSimpleName(ref);
}

// Extract field/method name from Lcom/example/Foo;->fieldName:Ltype; or ->methodName(sig)ret
static std::string extractMemberName(const std::string& ref) {
    auto arrow = ref.find("->");
    if (arrow == std::string::npos) return ref;
    std::string after = ref.substr(arrow + 2);
    // Field: name:type
    auto colon = after.find(':');
    if (colon != std::string::npos) return after.substr(0, colon);
    // Method: name(sig)ret
    auto paren = after.find('(');
    if (paren != std::string::npos) return after.substr(0, paren);
    return after;
}

// Extract field type from Lcom/example/Foo;->fieldName:Ltype;
static std::string extractFieldType(const std::string& ref) {
    auto colon = ref.find(':');
    if (colon == std::string::npos) return "";
    return typeToJava(ref.substr(colon + 1));
}

// Extract return type from method reference
static std::string extractReturnType(const std::string& ref) {
    auto paren = ref.find(')');
    if (paren == std::string::npos) return "void";
    return typeToJava(ref.substr(paren + 1));
}

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Decompile a single method's body
static std::string decompileMethod(const std::vector<std::string>& lines,
                                    int startLine, int endLine,
                                    const std::string& className) {
    std::ostringstream out;
    std::string indent = "    ";

    // Parse .method line for signature
    std::string methodLine = trim(lines[startLine]);
    // .method <access> <name>(sig)ret
    // Find method name and signature
    std::string access, methodName, fullSig;
    {
        // Remove .method prefix
        std::string rest = methodLine;
        if (rest.starts_with(".method")) rest = rest.substr(7);
        rest = trim(rest);

        // Parse access modifiers
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

    // Parse name(sig)ret
    auto parenPos = fullSig.find('(');
    if (parenPos != std::string::npos) {
        methodName = fullSig.substr(0, parenPos);
        auto msig = parseMethodSig(fullSig.substr(parenPos));

        // Build Java-like method declaration
        out << access;
        if (!access.empty()) out << " ";
        out << msig.returnType << " " << methodName << "(";

        // Collect .param names
        std::map<int, std::string> paramNames;
        for (int i = startLine + 1; i < endLine; i++) {
            std::string line = trim(lines[i]);
            if (line.starts_with(".param")) {
                // .param p1, "data"
                auto comma = line.find(',');
                if (comma != std::string::npos) {
                    std::string reg = trim(line.substr(6, comma - 6));
                    std::string name = trim(line.substr(comma + 1));
                    // Remove quotes
                    if (name.size() >= 2 && name.front() == '"' && name.back() == '"') {
                        name = name.substr(1, name.size() - 2);
                    }
                    // p1 -> index 1, p2 -> index 2...
                    if (reg.size() > 1 && reg[0] == 'p') {
                        try {
                            int idx = std::stoi(reg.substr(1));
                            paramNames[idx] = name;
                        } catch (...) {}
                    }
                }
            }
        }

        // Check if static (no this pointer)
        bool isStatic = access.find("static") != std::string::npos;
        int paramOffset = isStatic ? 0 : 1; // p0 = this for instance methods

        for (size_t i = 0; i < msig.paramTypes.size(); i++) {
            if (i > 0) out << ", ";
            out << msig.paramTypes[i] << " ";
            auto it = paramNames.find((int)i + paramOffset);
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

    // Track pending move-result assignment
    std::string pendingCall;
    bool pendingNeedsResult = false;

    // Track new-instance for constructor pairing
    std::map<std::string, std::string> newInstances; // register -> type

    // Decompile instructions
    for (int i = startLine + 1; i < endLine; i++) {
        std::string line = trim(lines[i]);
        if (line.empty() || line.starts_with(".method") || line.starts_with(".end method")) continue;

        // Skip directives
        if (line.starts_with(".locals") || line.starts_with(".param") ||
            line.starts_with(".annotation") || line.starts_with(".end annotation") ||
            line.starts_with(".prologue") || line.starts_with(".line") ||
            line.starts_with(".registers") || line.starts_with(".enum") ||
            line.starts_with(".source")) continue;

        // Labels
        if (line[0] == ':') {
            out << "\n" << indent << line.substr(1) << ":\n";
            continue;
        }

        // Comments
        if (line[0] == '#') {
            out << indent << "//" << line.substr(1) << "\n";
            continue;
        }

        // Handle .catch / .catchall
        if (line.starts_with(".catch")) {
            // .catch Ljava/lang/Exception; {:try_start .. :try_end} :catch
            auto braceStart = line.find('{');
            auto braceEnd = line.find('}');
            if (braceStart != std::string::npos && braceEnd != std::string::npos) {
                std::string inner = line.substr(braceStart + 1, braceEnd - braceStart - 1);
                // Extract type
                std::string excType = "Exception";
                auto semi = line.find(';');
                if (semi != std::string::npos && semi < braceStart) {
                    excType = classSimpleName(line.substr(line.find('L'), semi - line.find('L') + 1));
                }
                out << indent << "// try-catch(" << excType << ") " << trim(inner) << "\n";
            }
            continue;
        }

        // Split instruction into opcode and operands
        std::string opcode, operands;
        {
            auto spacePos = line.find(' ');
            if (spacePos != std::string::npos) {
                opcode = line.substr(0, spacePos);
                operands = trim(line.substr(spacePos + 1));
            } else {
                opcode = line;
            }
        }

        // Parse register list from {v0, v1, ...}
        auto parseRegs = [](const std::string& s) -> std::vector<std::string> {
            std::vector<std::string> regs;
            auto braceStart = s.find('{');
            auto braceEnd = s.find('}');
            if (braceStart == std::string::npos || braceEnd == std::string::npos) return regs;
            std::string inner = s.substr(braceStart + 1, braceEnd - braceStart - 1);
            std::istringstream ss(inner);
            std::string tok;
            while (std::getline(ss, tok, ',')) {
                std::string t = trim(tok);
                // Handle range: v0 .. v3
                auto dotdot = t.find("..");
                if (dotdot != std::string::npos) {
                    std::string start = trim(t.substr(0, dotdot));
                    std::string end = trim(t.substr(dotdot + 2));
                    regs.push_back(start);
                    // Expand range
                    if (start.size() > 1 && end.size() > 1) {
                        try {
                            char prefix = start[0];
                            int s = std::stoi(start.substr(1));
                            int e = std::stoi(end.substr(1));
                            for (int r = s + 1; r <= e; r++) {
                                regs.push_back(std::string(1, prefix) + std::to_string(r));
                            }
                        } catch (...) {}
                    }
                } else if (!t.empty()) {
                    regs.push_back(t);
                }
            }
            return regs;
        };

        // Extract method/field reference after }, or after last comma for non-brace ops
        auto extractRef = [](const std::string& s) -> std::string {
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
        };

        // --- Instruction decompilation ---

        // const-string
        if (opcode == "const-string" || opcode == "const-string/jumbo") {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string reg = trim(operands.substr(0, comma));
                std::string val = trim(operands.substr(comma + 1));
                out << indent << "String " << reg << " = " << val << ";\n";
            }
            continue;
        }

        // const/4, const/16, const, const/high16
        if (opcode.starts_with("const/") || opcode == "const") {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string reg = trim(operands.substr(0, comma));
                std::string val = trim(operands.substr(comma + 1));
                // Try to interpret common values
                if (val == "0x0") out << indent << "int " << reg << " = 0;\n";
                else if (val == "0x1") out << indent << "int " << reg << " = 1; // true\n";
                else out << indent << "int " << reg << " = " << val << ";\n";
            }
            continue;
        }

        // const-wide
        if (opcode.starts_with("const-wide")) {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string reg = trim(operands.substr(0, comma));
                std::string val = trim(operands.substr(comma + 1));
                out << indent << "long " << reg << " = " << val << ";\n";
            }
            continue;
        }

        // new-instance
        if (opcode == "new-instance") {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string reg = trim(operands.substr(0, comma));
                std::string type = trim(operands.substr(comma + 1));
                std::string javaType = typeToJava(type);
                newInstances[reg] = javaType;
                // Don't emit yet — wait for <init> call
            }
            continue;
        }

        // invoke-direct with <init> -> constructor
        if (opcode.starts_with("invoke-direct") || opcode.starts_with("invoke-direct/range")) {
            auto regs = parseRegs(operands);
            std::string ref = extractRef(operands);
            std::string memberName = extractMemberName(ref);

            if (memberName == "<init>" && !regs.empty()) {
                std::string objReg = regs[0];
                auto it = newInstances.find(objReg);
                if (it != newInstances.end()) {
                    // Constructor call
                    std::string type = it->second;
                    std::string args;
                    for (size_t r = 1; r < regs.size(); r++) {
                        if (r > 1) args += ", ";
                        args += regs[r];
                    }
                    out << indent << type << " " << objReg << " = new " << type << "(" << args << ");\n";
                    newInstances.erase(it);
                    continue;
                }
                // super() or this() call
                if (objReg == "p0") {
                    std::string cls = extractClassName(ref);
                    std::string args;
                    for (size_t r = 1; r < regs.size(); r++) {
                        if (r > 1) args += ", ";
                        args += regs[r];
                    }
                    out << indent << "super(" << args << "); // " << cls << "\n";
                    continue;
                }
            }

            // Regular direct call (private method)
            if (!regs.empty()) {
                std::string member = extractMemberName(ref);
                std::string retType = extractReturnType(ref);
                std::string obj = regs[0];
                std::string args;
                for (size_t r = 1; r < regs.size(); r++) {
                    if (r > 1) args += ", ";
                    args += regs[r];
                }
                if (retType != "void") {
                    pendingCall = obj + "." + member + "(" + args + ")";
                    pendingNeedsResult = true;
                } else {
                    out << indent << obj << "." << member << "(" << args << ");\n";
                }
            }
            continue;
        }

        // invoke-virtual, invoke-interface
        if (opcode.starts_with("invoke-virtual") || opcode.starts_with("invoke-interface")) {
            auto regs = parseRegs(operands);
            std::string ref = extractRef(operands);
            std::string member = extractMemberName(ref);
            std::string retType = extractReturnType(ref);

            if (!regs.empty()) {
                std::string obj = regs[0];
                // p0 -> this
                if (obj == "p0") obj = "this";
                std::string args;
                for (size_t r = 1; r < regs.size(); r++) {
                    if (r > 1) args += ", ";
                    args += regs[r];
                }
                if (retType != "void") {
                    pendingCall = obj + "." + member + "(" + args + ")";
                    pendingNeedsResult = true;
                } else {
                    out << indent << obj << "." + member + "(" << args << ");\n";
                }
            }
            continue;
        }

        // invoke-static
        if (opcode.starts_with("invoke-static")) {
            auto regs = parseRegs(operands);
            std::string ref = extractRef(operands);
            std::string cls = extractClassName(ref);
            std::string member = extractMemberName(ref);
            std::string retType = extractReturnType(ref);

            std::string args;
            for (size_t r = 0; r < regs.size(); r++) {
                if (r > 0) args += ", ";
                args += regs[r];
            }
            if (retType != "void") {
                pendingCall = cls + "." + member + "(" + args + ")";
                pendingNeedsResult = true;
            } else {
                out << indent << cls << "." << member << "(" << args << ");\n";
            }
            continue;
        }

        // invoke-super
        if (opcode.starts_with("invoke-super")) {
            auto regs = parseRegs(operands);
            std::string ref = extractRef(operands);
            std::string member = extractMemberName(ref);
            std::string retType = extractReturnType(ref);

            std::string args;
            for (size_t r = 1; r < regs.size(); r++) {
                if (r > 1) args += ", ";
                args += regs[r];
            }
            if (retType != "void") {
                pendingCall = "super." + member + "(" + args + ")";
                pendingNeedsResult = true;
            } else {
                out << indent << "super." << member << "(" << args << ");\n";
            }
            continue;
        }

        // move-result, move-result-object, move-result-wide
        if (opcode.starts_with("move-result")) {
            std::string reg = trim(operands);
            if (pendingNeedsResult && !pendingCall.empty()) {
                out << indent << reg << " = " << pendingCall << ";\n";
                pendingCall.clear();
                pendingNeedsResult = false;
            } else {
                out << indent << reg << " = <result>;\n";
            }
            continue;
        }

        // If we had a pending void call that wasn't consumed, emit it
        if (pendingNeedsResult && !pendingCall.empty() && !opcode.starts_with("move-result")) {
            out << indent << pendingCall << ";\n";
            pendingCall.clear();
            pendingNeedsResult = false;
        }

        // iget-object, iget, iget-wide, iget-boolean, iget-byte, iget-char, iget-short
        if (opcode.starts_with("iget")) {
            // iget-object v0, v1, Lclass;->field:Ltype;
            auto parts_str = operands;
            auto comma1 = parts_str.find(',');
            if (comma1 != std::string::npos) {
                std::string dest = trim(parts_str.substr(0, comma1));
                auto comma2 = parts_str.find(',', comma1 + 1);
                if (comma2 != std::string::npos) {
                    std::string obj = trim(parts_str.substr(comma1 + 1, comma2 - comma1 - 1));
                    std::string ref = trim(parts_str.substr(comma2 + 1));
                    std::string fieldName = extractMemberName(ref);
                    std::string fieldType = extractFieldType(ref);
                    if (obj == "p0") obj = "this";
                    out << indent << fieldType << " " << dest << " = " << obj << "." << fieldName << ";\n";
                }
            }
            continue;
        }

        // iput-object, iput, etc.
        if (opcode.starts_with("iput")) {
            auto comma1 = operands.find(',');
            if (comma1 != std::string::npos) {
                std::string val = trim(operands.substr(0, comma1));
                auto comma2 = operands.find(',', comma1 + 1);
                if (comma2 != std::string::npos) {
                    std::string obj = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                    std::string ref = trim(operands.substr(comma2 + 1));
                    std::string fieldName = extractMemberName(ref);
                    if (obj == "p0") obj = "this";
                    out << indent << obj << "." << fieldName << " = " << val << ";\n";
                }
            }
            continue;
        }

        // sget-object, sget, etc.
        if (opcode.starts_with("sget")) {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma));
                std::string ref = trim(operands.substr(comma + 1));
                std::string cls = extractClassName(ref);
                std::string fieldName = extractMemberName(ref);
                std::string fieldType = extractFieldType(ref);
                out << indent << fieldType << " " << dest << " = " << cls << "." << fieldName << ";\n";
            }
            continue;
        }

        // sput-object, sput, etc.
        if (opcode.starts_with("sput")) {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string val = trim(operands.substr(0, comma));
                std::string ref = trim(operands.substr(comma + 1));
                std::string cls = extractClassName(ref);
                std::string fieldName = extractMemberName(ref);
                out << indent << cls << "." << fieldName << " = " << val << ";\n";
            }
            continue;
        }

        // check-cast
        if (opcode == "check-cast") {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string reg = trim(operands.substr(0, comma));
                std::string type = trim(operands.substr(comma + 1));
                out << indent << reg << " = (" << typeToJava(type) << ") " << reg << ";\n";
            }
            continue;
        }

        // instance-of
        if (opcode == "instance-of") {
            auto comma1 = operands.find(',');
            if (comma1 != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma1));
                auto comma2 = operands.find(',', comma1 + 1);
                if (comma2 != std::string::npos) {
                    std::string obj = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                    std::string type = trim(operands.substr(comma2 + 1));
                    out << indent << "boolean " << dest << " = " << obj << " instanceof " << typeToJava(type) << ";\n";
                }
            }
            continue;
        }

        // if-* conditional branches
        if (opcode.starts_with("if-")) {
            // if-eqz v0, :label  or  if-eq v0, v1, :label
            std::string cond;
            if (opcode == "if-eqz") cond = " == 0";
            else if (opcode == "if-nez") cond = " != 0";
            else if (opcode == "if-ltz") cond = " < 0";
            else if (opcode == "if-gez") cond = " >= 0";
            else if (opcode == "if-gtz") cond = " > 0";
            else if (opcode == "if-lez") cond = " <= 0";

            if (!cond.empty()) {
                // Single register: if-xxz vN, :label
                auto comma = operands.find(',');
                if (comma != std::string::npos) {
                    std::string reg = trim(operands.substr(0, comma));
                    std::string label = trim(operands.substr(comma + 1));
                    if (!label.empty() && label[0] == ':') label = label.substr(1);
                    out << indent << "if (" << reg << cond << ") goto " << label << ";\n";
                }
            } else {
                // Two register: if-eq v0, v1, :label
                std::string op;
                if (opcode == "if-eq") op = " == ";
                else if (opcode == "if-ne") op = " != ";
                else if (opcode == "if-lt") op = " < ";
                else if (opcode == "if-ge") op = " >= ";
                else if (opcode == "if-gt") op = " > ";
                else if (opcode == "if-le") op = " <= ";
                else op = " ? ";

                auto comma1 = operands.find(',');
                if (comma1 != std::string::npos) {
                    std::string r1 = trim(operands.substr(0, comma1));
                    auto comma2 = operands.find(',', comma1 + 1);
                    if (comma2 != std::string::npos) {
                        std::string r2 = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                        std::string label = trim(operands.substr(comma2 + 1));
                        if (!label.empty() && label[0] == ':') label = label.substr(1);
                        out << indent << "if (" << r1 << op << r2 << ") goto " << label << ";\n";
                    }
                }
            }
            continue;
        }

        // goto
        if (opcode == "goto" || opcode == "goto/16" || opcode == "goto/32") {
            std::string label = trim(operands);
            if (!label.empty() && label[0] == ':') label = label.substr(1);
            out << indent << "goto " << label << ";\n";
            continue;
        }

        // return
        if (opcode == "return-void") {
            out << indent << "return;\n";
            continue;
        }
        if (opcode == "return" || opcode == "return-object" || opcode == "return-wide") {
            out << indent << "return " << trim(operands) << ";\n";
            continue;
        }

        // throw
        if (opcode == "throw") {
            out << indent << "throw " << trim(operands) << ";\n";
            continue;
        }

        // move, move-object, move-wide
        if (opcode.starts_with("move") && !opcode.starts_with("move-result") && !opcode.starts_with("move-exception")) {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma));
                std::string src = trim(operands.substr(comma + 1));
                out << indent << dest << " = " << src << ";\n";
            }
            continue;
        }

        // move-exception
        if (opcode == "move-exception") {
            out << indent << trim(operands) << " = <caught exception>;\n";
            continue;
        }

        // new-array
        if (opcode == "new-array") {
            auto comma1 = operands.find(',');
            if (comma1 != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma1));
                auto comma2 = operands.find(',', comma1 + 1);
                if (comma2 != std::string::npos) {
                    std::string size = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                    std::string type = trim(operands.substr(comma2 + 1));
                    out << indent << typeToJava(type) << " " << dest << " = new "
                        << typeToJava(type.substr(0, type.size())) << "[" << size << "];\n";
                }
            }
            continue;
        }

        // aget-*, aput-*
        if (opcode.starts_with("aget")) {
            auto comma1 = operands.find(',');
            if (comma1 != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma1));
                auto comma2 = operands.find(',', comma1 + 1);
                if (comma2 != std::string::npos) {
                    std::string arr = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                    std::string idx = trim(operands.substr(comma2 + 1));
                    out << indent << dest << " = " << arr << "[" << idx << "];\n";
                }
            }
            continue;
        }
        if (opcode.starts_with("aput")) {
            auto comma1 = operands.find(',');
            if (comma1 != std::string::npos) {
                std::string val = trim(operands.substr(0, comma1));
                auto comma2 = operands.find(',', comma1 + 1);
                if (comma2 != std::string::npos) {
                    std::string arr = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                    std::string idx = trim(operands.substr(comma2 + 1));
                    out << indent << arr << "[" << idx << "] = " << val << ";\n";
                }
            }
            continue;
        }

        // Arithmetic: add-int, sub-int, mul-int, div-int, etc.
        if (opcode.starts_with("add-") || opcode.starts_with("sub-") ||
            opcode.starts_with("mul-") || opcode.starts_with("div-") ||
            opcode.starts_with("rem-") || opcode.starts_with("and-") ||
            opcode.starts_with("or-")  || opcode.starts_with("xor-") ||
            opcode.starts_with("shl-") || opcode.starts_with("shr-") ||
            opcode.starts_with("ushr-")) {

            char op = '+';
            if (opcode.starts_with("sub")) op = '-';
            else if (opcode.starts_with("mul")) op = '*';
            else if (opcode.starts_with("div")) op = '/';
            else if (opcode.starts_with("rem")) op = '%';
            else if (opcode.starts_with("and")) op = '&';
            else if (opcode.starts_with("or-")) op = '|';
            else if (opcode.starts_with("xor")) op = '^';

            // 2addr form: add-int/2addr v0, v1 -> v0 = v0 + v1
            if (opcode.find("/2addr") != std::string::npos) {
                auto comma = operands.find(',');
                if (comma != std::string::npos) {
                    std::string r1 = trim(operands.substr(0, comma));
                    std::string r2 = trim(operands.substr(comma + 1));
                    out << indent << r1 << " " << op << "= " << r2 << ";\n";
                }
            }
            // lit form: add-int/lit8 v0, v1, 5 -> v0 = v1 + 5
            else if (opcode.find("/lit") != std::string::npos) {
                auto comma1 = operands.find(',');
                if (comma1 != std::string::npos) {
                    std::string dest = trim(operands.substr(0, comma1));
                    auto comma2 = operands.find(',', comma1 + 1);
                    if (comma2 != std::string::npos) {
                        std::string src = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                        std::string lit = trim(operands.substr(comma2 + 1));
                        out << indent << dest << " = " << src << " " << op << " " << lit << ";\n";
                    }
                }
            }
            // Normal form: add-int v0, v1, v2 -> v0 = v1 + v2
            else {
                auto comma1 = operands.find(',');
                if (comma1 != std::string::npos) {
                    std::string dest = trim(operands.substr(0, comma1));
                    auto comma2 = operands.find(',', comma1 + 1);
                    if (comma2 != std::string::npos) {
                        std::string r1 = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                        std::string r2 = trim(operands.substr(comma2 + 1));
                        out << indent << dest << " = " << r1 << " " << op << " " << r2 << ";\n";
                    }
                }
            }
            continue;
        }

        // neg-*, not-*
        if (opcode.starts_with("neg-") || opcode.starts_with("not-")) {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma));
                std::string src = trim(operands.substr(comma + 1));
                std::string op = opcode.starts_with("neg") ? "-" : "~";
                out << indent << dest << " = " << op << src << ";\n";
            }
            continue;
        }

        // Type conversions: int-to-long, long-to-int, etc.
        if (opcode.find("-to-") != std::string::npos) {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma));
                std::string src = trim(operands.substr(comma + 1));
                // Extract target type from opcode
                auto toPos = opcode.find("-to-");
                std::string targetType = opcode.substr(toPos + 4);
                out << indent << dest << " = (" << targetType << ") " << src << ";\n";
            }
            continue;
        }

        // cmp operations
        if (opcode.starts_with("cmp") || opcode.starts_with("cmpl") || opcode.starts_with("cmpg")) {
            auto comma1 = operands.find(',');
            if (comma1 != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma1));
                auto comma2 = operands.find(',', comma1 + 1);
                if (comma2 != std::string::npos) {
                    std::string r1 = trim(operands.substr(comma1 + 1, comma2 - comma1 - 1));
                    std::string r2 = trim(operands.substr(comma2 + 1));
                    out << indent << "int " << dest << " = compare(" << r1 << ", " << r2 << ");\n";
                }
            }
            continue;
        }

        // array-length
        if (opcode == "array-length") {
            auto comma = operands.find(',');
            if (comma != std::string::npos) {
                std::string dest = trim(operands.substr(0, comma));
                std::string arr = trim(operands.substr(comma + 1));
                out << indent << "int " << dest << " = " << arr << ".length;\n";
            }
            continue;
        }

        // fill-array-data, packed-switch, sparse-switch - emit as comment
        if (opcode == "fill-array-data" || opcode == "packed-switch" || opcode == "sparse-switch") {
            out << indent << "// " << opcode << " " << operands << "\n";
            continue;
        }

        // .packed-switch / .sparse-switch data
        if (opcode.starts_with(".packed-switch") || opcode.starts_with(".sparse-switch") ||
            opcode.starts_with(".end packed-switch") || opcode.starts_with(".end sparse-switch") ||
            opcode.starts_with(".array-data") || opcode.starts_with(".end array-data")) {
            out << indent << "// " << line << "\n";
            continue;
        }

        // nop
        if (opcode == "nop") continue;

        // monitor-enter, monitor-exit
        if (opcode == "monitor-enter") {
            out << indent << "synchronized(" << trim(operands) << ") { // monitor-enter\n";
            continue;
        }
        if (opcode == "monitor-exit") {
            out << indent << "} // monitor-exit " << trim(operands) << "\n";
            continue;
        }

        // filled-new-array
        if (opcode.starts_with("filled-new-array")) {
            auto regs = parseRegs(operands);
            std::string ref = extractRef(operands);
            std::string type = typeToJava(ref);
            std::string args;
            for (size_t r = 0; r < regs.size(); r++) {
                if (r > 0) args += ", ";
                args += regs[r];
            }
            pendingCall = "new " + type + " {" + args + "}";
            pendingNeedsResult = true;
            continue;
        }

        // Fallback: emit as comment
        out << indent << "// " << line << "\n";
    }

    // Flush any pending call
    if (pendingNeedsResult && !pendingCall.empty()) {
        out << indent << pendingCall << ";\n";
    }

    out << "}\n";
    return out.str();
}

std::optional<ToolResult> DecompileTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("DECOMPILE:") != 0)
        return std::nullopt;

    std::string args = action.substr(10);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);
    while (!args.empty() && args.back() == ' ') args.pop_back();

    if (args.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a .smali file path after DECOMPILE:"};
    }

    // Parse: path | method <name>
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

    std::string ext = fs::path(filePath).extension().string();
    for (auto& c : ext) c = std::tolower(static_cast<unsigned char>(c));
    if (ext != ".smali") {
        return ToolResult{"OBSERVATION: DECOMPILE only supports .smali files. Got: " + ext};
    }

    // Read file
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

    // Extract class name, super, interfaces, fields
    std::string className, superClass;
    std::vector<std::string> interfaces;
    std::vector<std::string> fields;

    for (auto& l : lines) {
        std::string trimmed = trim(l);
        if (trimmed.starts_with(".class")) {
            // .class public Lcom/example/Foo;
            auto lastSpace = trimmed.rfind(' ');
            if (lastSpace != std::string::npos) {
                className = typeToJava(trimmed.substr(lastSpace + 1));
            }
        } else if (trimmed.starts_with(".super")) {
            auto sp = trimmed.find(' ');
            if (sp != std::string::npos) {
                superClass = typeToJava(trim(trimmed.substr(sp + 1)));
            }
        } else if (trimmed.starts_with(".implements")) {
            auto sp = trimmed.find(' ');
            if (sp != std::string::npos) {
                interfaces.push_back(typeToJava(trim(trimmed.substr(sp + 1))));
            }
        } else if (trimmed.starts_with(".field")) {
            // .field private serverUrl:Ljava/lang/String;
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
                fields.push_back(fieldAccess + " " + type + " " + fieldName);
            }
        }
    }

    // Find target method(s)
    std::string targetMethod;
    if (!modifier.empty()) {
        std::string modLower = modifier;
        for (auto& c : modLower) c = std::tolower(static_cast<unsigned char>(c));
        if (modLower.starts_with("method")) {
            targetMethod = trim(modifier.substr(6));
        } else {
            targetMethod = modifier;
        }
    }

    // Find method boundaries
    struct MethodBounds {
        int start;
        int end;
        std::string name;
    };
    std::vector<MethodBounds> methods;

    for (int i = 0; i < (int)lines.size(); i++) {
        std::string trimmed = trim(lines[i]);
        if (trimmed.starts_with(".method")) {
            // Find .end method
            int endLine = i;
            for (int j = i + 1; j < (int)lines.size(); j++) {
                if (trim(lines[j]).starts_with(".end method")) {
                    endLine = j;
                    break;
                }
            }
            // Extract method name
            auto paren = trimmed.find('(');
            if (paren != std::string::npos) {
                std::string before = trimmed.substr(0, paren);
                auto lastSp = before.rfind(' ');
                std::string name = (lastSp != std::string::npos) ? before.substr(lastSp + 1) : before;
                methods.push_back({i, endLine, name});
            }
            i = endLine;
        }
    }

    if (methods.empty()) {
        return ToolResult{"OBSERVATION: No methods found in " + filePath};
    }

    // If target specified, filter
    if (!targetMethod.empty()) {
        std::string targetLower = targetMethod;
        for (auto& c : targetLower) c = std::tolower(static_cast<unsigned char>(c));

        std::vector<MethodBounds> filtered;
        for (auto& m : methods) {
            std::string nameLower = m.name;
            for (auto& c : nameLower) c = std::tolower(static_cast<unsigned char>(c));
            if (nameLower.find(targetLower) != std::string::npos) {
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

    // Cap output
    static constexpr int MAX_METHODS = 20;
    bool truncatedMethods = false;
    if ((int)methods.size() > MAX_METHODS) {
        methods.resize(MAX_METHODS);
        truncatedMethods = true;
    }

    // Build output
    std::ostringstream out;
    out << "// Decompiled from: " << filePath << "\n";

    // Class header
    out << "class " << className;
    if (!superClass.empty() && superClass != "Object" && superClass != "java.lang.Object") {
        out << " extends " << superClass;
    }
    if (!interfaces.empty()) {
        out << " implements ";
        for (size_t i = 0; i < interfaces.size(); i++) {
            if (i > 0) out << ", ";
            out << interfaces[i];
        }
    }
    out << " {\n\n";

    // Fields
    if (!fields.empty() && targetMethod.empty()) {
        for (auto& f : fields) {
            out << "    " << f << ";\n";
        }
        out << "\n";
    }

    // Decompile each method
    for (auto& m : methods) {
        out << decompileMethod(lines, m.start, m.end, className) << "\n";
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

} // namespace area
