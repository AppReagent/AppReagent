#pragma once

#include <string>
#include <vector>

namespace area::smali {

struct SmaliField {
    std::string access;  // e.g. "private", "public static"
    std::string name;
    std::string type;    // e.g. "Ljava/lang/String;"
    std::string raw;     // full original line
};

struct SmaliMethod {
    std::string access;    // e.g. "public", "private static"
    std::string name;      // e.g. "sendSMS"
    std::string signature; // e.g. "(Ljava/lang/String;)V"
    std::string body;      // everything from .method to .end method (inclusive)
    int line_start = 0;
    int line_end = 0;
};

struct SmaliCall {
    std::string invoke_type;   // "virtual", "direct", "static", "super", "interface"
    std::string target_class;  // e.g. "Landroid/telephony/SmsManager;"
    std::string target_method; // e.g. "sendTextMessage"
    std::string target_signature; // e.g. "(Ljava/lang/String;...)V"
};

struct SmaliFile {
    std::string class_name;   // e.g. "Lcom/malware/Payload;"
    std::string super_class;  // e.g. "Ljava/lang/Object;"
    std::string source_file;  // from .source directive
    std::vector<std::string> interfaces;
    std::vector<SmaliField> fields;
    std::vector<SmaliMethod> methods;
    std::string raw;          // full file contents
};

// Parse a .smali file from its contents
SmaliFile parse(const std::string& contents);

// Extract invoke-* call targets from a method body
std::vector<SmaliCall> extractCalls(const std::string& method_body);

} // namespace area::smali
