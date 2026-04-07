#include "domains/smali/parser.h"

#include <sstream>

namespace area::smali {

// Trim whitespace from both ends
static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Split "access name type" from a .field directive
static SmaliField parseFieldLine(const std::string& line) {
    SmaliField f;
    f.raw = line;

    // .field <access> <name>:<type> [= value]
    std::string rest = line.substr(7); // skip ".field "
    rest = trim(rest);

    // Find the name:type part (last token before optional = value)
    auto eqPos = rest.find(" = ");
    std::string beforeEq = (eqPos != std::string::npos) ? rest.substr(0, eqPos) : rest;

    // The name:type is the last space-separated token
    auto lastSpace = beforeEq.rfind(' ');
    std::string nameType;
    if (lastSpace != std::string::npos) {
        f.access = beforeEq.substr(0, lastSpace);
        nameType = beforeEq.substr(lastSpace + 1);
    } else {
        nameType = beforeEq;
    }

    auto colonPos = nameType.find(':');
    if (colonPos != std::string::npos) {
        f.name = nameType.substr(0, colonPos);
        f.type = nameType.substr(colonPos + 1);
    } else {
        f.name = nameType;
    }

    return f;
}

// Parse .method line: ".method <access> <name>(<params>)<return>"
static void parseMethodDirective(const std::string& line, SmaliMethod& m) {
    // .method <access modifiers> <name>(signature)
    std::string rest = line.substr(8); // skip ".method "
    rest = trim(rest);

    // everything before the last token is access,
    // the last token contains name(sig)
    auto parenPos = rest.find('(');
    if (parenPos == std::string::npos) {
        m.name = rest;
        return;
    }

    std::string beforeParen = rest.substr(0, parenPos);
    m.signature = rest.substr(parenPos);

    auto lastSpace = beforeParen.rfind(' ');
    if (lastSpace != std::string::npos) {
        m.access = beforeParen.substr(0, lastSpace);
        m.name = beforeParen.substr(lastSpace + 1);
    } else {
        m.name = beforeParen;
    }
}

SmaliFile parse(const std::string& contents) {
    SmaliFile result;
    result.raw = contents;

    std::istringstream stream(contents);
    std::string line;
    int lineNum = 0;

    bool inMethod = false;
    SmaliMethod currentMethod;
    std::ostringstream methodBody;

    while (std::getline(stream, line)) {
        lineNum++;
        std::string trimmed = trim(line);

        // Class directives
        if (trimmed.starts_with(".class ")) {
            auto lastSpace = trimmed.rfind(' ');
            if (lastSpace != std::string::npos) {
                result.class_name = trimmed.substr(lastSpace + 1);
            }
            continue;
        }

        if (trimmed.starts_with(".super ")) {
            result.super_class = trimmed.substr(7);
            continue;
        }

        if (trimmed.starts_with(".source ")) {
            result.source_file = trimmed.substr(8);
            // Remove quotes if present
            if (!result.source_file.empty() && result.source_file[0] == '"') {
                result.source_file = result.source_file.substr(1);
                if (!result.source_file.empty() && result.source_file.back() == '"') {
                    result.source_file.pop_back();
                }
            }
            continue;
        }

        if (trimmed.starts_with(".implements ")) {
            result.interfaces.push_back(trimmed.substr(12));
            continue;
        }

        // Fields
        if (trimmed.starts_with(".field ")) {
            result.fields.push_back(parseFieldLine(trimmed));
            continue;
        }

        // Methods
        if (trimmed.starts_with(".method ")) {
            inMethod = true;
            currentMethod = SmaliMethod{};
            currentMethod.line_start = lineNum;
            parseMethodDirective(trimmed, currentMethod);
            methodBody.str("");
            methodBody.clear();
            methodBody << line << "\n";
            continue;
        }

        if (trimmed == ".end method" && inMethod) {
            methodBody << line << "\n";
            currentMethod.line_end = lineNum;
            currentMethod.body = methodBody.str();
            result.methods.push_back(std::move(currentMethod));
            inMethod = false;
            continue;
        }

        if (inMethod) {
            methodBody << line << "\n";
        }
    }

    return result;
}

std::vector<SmaliCall> extractCalls(const std::string& method_body) {
    std::vector<SmaliCall> calls;
    std::istringstream stream(method_body);
    std::string line;

    while (std::getline(stream, line)) {
        std::string trimmed = trim(line);

        // Match invoke-virtual, invoke-direct, invoke-static, invoke-super, invoke-interface
        // and their /range variants
        std::string invokeType;
        if (trimmed.starts_with("invoke-virtual")) invokeType = "virtual";
        else if (trimmed.starts_with("invoke-direct")) invokeType = "direct";
        else if (trimmed.starts_with("invoke-static")) invokeType = "static";
        else if (trimmed.starts_with("invoke-super")) invokeType = "super";
        else if (trimmed.starts_with("invoke-interface")) invokeType = "interface";
        else continue;

        // Format: invoke-type {regs}, Lclass;->method(sig)ret
        // Find the method reference after "}, "
        auto braceClose = trimmed.find('}');
        if (braceClose == std::string::npos) continue;
        auto refStart = trimmed.find_first_not_of(" ,", braceClose + 1);
        if (refStart == std::string::npos) continue;

        std::string ref = trimmed.substr(refStart);

        // Split on "->" to get class and method+sig
        auto arrowPos = ref.find("->");
        if (arrowPos == std::string::npos) continue;

        std::string targetClass = ref.substr(0, arrowPos);
        std::string methodAndSig = ref.substr(arrowPos + 2);

        // Split method name from signature at '('
        auto parenPos = methodAndSig.find('(');
        std::string targetMethod;
        std::string targetSig;
        if (parenPos != std::string::npos) {
            targetMethod = methodAndSig.substr(0, parenPos);
            targetSig = methodAndSig.substr(parenPos);
        } else {
            targetMethod = methodAndSig;
        }

        calls.push_back({invokeType, targetClass, targetMethod, targetSig});
    }

    return calls;
}

} // namespace area::smali
