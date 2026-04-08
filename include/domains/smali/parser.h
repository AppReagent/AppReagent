#pragma once

#include <string>
#include <vector>

namespace area::smali {

struct SmaliField {
    std::string access;
    std::string name;
    std::string type;
    std::string raw;
};

struct SmaliMethod {
    std::string access;
    std::string name;
    std::string signature;
    std::string body;
    int line_start = 0;
    int line_end = 0;
};

struct SmaliCall {
    std::string invoke_type;
    std::string target_class;
    std::string target_method;
    std::string target_signature;
};

struct SmaliFile {
    std::string class_name;
    std::string super_class;
    std::string source_file;
    std::vector<std::string> interfaces;
    std::vector<SmaliField> fields;
    std::vector<SmaliMethod> methods;
    std::string raw;
};

SmaliFile parse(const std::string& contents);

std::vector<SmaliCall> extractCalls(const std::string& method_body);

}  // namespace area::smali
