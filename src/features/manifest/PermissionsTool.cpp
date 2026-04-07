#include "features/manifest/PermissionsTool.h"
#include "infra/tools/ToolContext.h"
#include "Agent.h"
#include "util/file_io.h"

#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

namespace area {

// Dangerous permissions that deserve extra scrutiny
static const std::set<std::string> DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.WAKE_LOCK",
    "android.permission.INTERNET",
    "android.permission.CHANGE_NETWORK_STATE",
};

// Suspicious permission combinations
struct SuspiciousCombination {
    std::vector<std::string> perms;
    std::string warning;
};

static const std::vector<SuspiciousCombination> SUSPICIOUS_COMBOS = {
    {{"android.permission.READ_SMS", "android.permission.INTERNET"},
     "SMS reading + internet access: potential SMS exfiltration"},
    {{"android.permission.READ_CONTACTS", "android.permission.INTERNET"},
     "Contacts reading + internet access: potential contact exfiltration"},
    {{"android.permission.CAMERA", "android.permission.INTERNET"},
     "Camera + internet: potential covert surveillance"},
    {{"android.permission.RECORD_AUDIO", "android.permission.INTERNET"},
     "Microphone + internet: potential audio surveillance"},
    {{"android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"},
     "Fine location + internet: potential location tracking"},
    {{"android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"},
     "SMS send + receive: potential premium SMS fraud or C2 via SMS"},
    {{"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"},
     "Accessibility service + internet: potential overlay attack or keylogging"},
    {{"android.permission.BIND_DEVICE_ADMIN", "android.permission.INTERNET"},
     "Device admin + internet: potential ransomware or remote device control"},
    {{"android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"},
     "Boot receiver + internet: persistent background communication"},
    {{"android.permission.INSTALL_PACKAGES", "android.permission.INTERNET"},
     "Package install + internet: potential dropper/downloader behavior"},
    {{"android.permission.READ_PHONE_STATE", "android.permission.INTERNET"},
     "Phone state + internet: potential device fingerprinting/tracking"},
    {{"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"},
     "System alert window + internet: potential phishing overlay"},
};

struct ManifestInfo {
    std::string package_name;
    std::string version_name;
    std::string version_code;
    std::string min_sdk;
    std::string target_sdk;
    std::vector<std::string> permissions;
    std::vector<std::string> uses_features;

    struct Component {
        std::string type; // activity, service, receiver, provider
        std::string name;
        bool exported = false;
        std::vector<std::string> intent_filters;
    };
    std::vector<Component> components;
};

// Simple XML attribute parser (no dependency on libxml)
static std::string getAttr(const std::string& line, const std::string& attr) {
    // Look for android:attr="value" or attr="value"
    for (auto prefix : {"android:", "a:", ""}) {
        std::string needle = std::string(prefix) + attr + "=\"";
        auto pos = line.find(needle);
        if (pos != std::string::npos) {
            auto start = pos + needle.size();
            auto end = line.find('"', start);
            if (end != std::string::npos)
                return line.substr(start, end - start);
        }
    }
    return "";
}

static ManifestInfo parseManifest(const std::string& contents) {
    ManifestInfo info;

    // Pre-process: join multi-line tags into single lines.
    // XML tags can span multiple lines; join them so attribute parsing works.
    std::string normalized;
    {
        std::istringstream stream(contents);
        std::string line;
        bool inTag = false;
        while (std::getline(stream, line)) {
            auto trimStart = line.find_first_not_of(" \t\r\n");
            if (trimStart == std::string::npos) continue;
            std::string trimmed = line.substr(trimStart);
            if (inTag) {
                normalized += " " + trimmed;
                if (trimmed.find('>') != std::string::npos) inTag = false;
            } else {
                if (!normalized.empty()) normalized += "\n";
                normalized += trimmed;
                // Check if tag is unclosed (has < but no >)
                if (trimmed.find('<') != std::string::npos &&
                    trimmed.find('>') == std::string::npos)
                    inTag = true;
            }
        }
    }

    std::istringstream stream(normalized);
    std::string line;

    ManifestInfo::Component currentComponent;
    bool inComponent = false;
    bool inIntentFilter = false;
    std::string currentIntentFilter;

    while (std::getline(stream, line)) {
        // Trim
        auto trimStart = line.find_first_not_of(" \t");
        if (trimStart == std::string::npos) continue;
        std::string trimmed = line.substr(trimStart);

        // Package and version
        if (trimmed.find("<manifest") != std::string::npos) {
            info.package_name = getAttr(trimmed, "package");
            info.version_name = getAttr(trimmed, "versionName");
            info.version_code = getAttr(trimmed, "versionCode");
        }

        // SDK versions
        if (trimmed.find("<uses-sdk") != std::string::npos) {
            info.min_sdk = getAttr(trimmed, "minSdkVersion");
            info.target_sdk = getAttr(trimmed, "targetSdkVersion");
        }

        // Permissions
        if (trimmed.find("<uses-permission") != std::string::npos) {
            std::string perm = getAttr(trimmed, "name");
            if (!perm.empty()) info.permissions.push_back(perm);
        }

        // Features
        if (trimmed.find("<uses-feature") != std::string::npos) {
            std::string feat = getAttr(trimmed, "name");
            if (!feat.empty()) info.uses_features.push_back(feat);
        }

        // Components
        for (auto& type : {"activity", "service", "receiver", "provider"}) {
            std::string open = std::string("<") + type;
            if (trimmed.find(open) == 0 || trimmed.find(open + " ") != std::string::npos) {
                inComponent = true;
                currentComponent = {};
                currentComponent.type = type;
                currentComponent.name = getAttr(trimmed, "name");
                std::string exp = getAttr(trimmed, "exported");
                currentComponent.exported = (exp == "true");
                // Self-closing tag
                if (trimmed.find("/>") != std::string::npos) {
                    info.components.push_back(currentComponent);
                    inComponent = false;
                }
                break;
            }
        }

        // Intent filters
        if (trimmed.find("<intent-filter") != std::string::npos) {
            inIntentFilter = true;
            currentIntentFilter.clear();
        }

        if (inIntentFilter) {
            if (trimmed.find("<action") != std::string::npos) {
                std::string action = getAttr(trimmed, "name");
                if (!action.empty()) {
                    if (!currentIntentFilter.empty()) currentIntentFilter += ", ";
                    currentIntentFilter += "action:" + action;
                }
                // Also: implicit export if LAUNCHER action
                if (action.find("MAIN") != std::string::npos) {
                    currentComponent.exported = true;
                }
            }
            if (trimmed.find("<category") != std::string::npos) {
                std::string cat = getAttr(trimmed, "name");
                if (!cat.empty()) {
                    if (!currentIntentFilter.empty()) currentIntentFilter += ", ";
                    currentIntentFilter += "cat:" + cat;
                }
            }
            if (trimmed.find("<data") != std::string::npos) {
                std::string scheme = getAttr(trimmed, "scheme");
                std::string host = getAttr(trimmed, "host");
                std::string mime = getAttr(trimmed, "mimeType");
                std::string dataStr;
                if (!scheme.empty()) dataStr += scheme + "://";
                if (!host.empty()) dataStr += host;
                if (!mime.empty()) { if (!dataStr.empty()) dataStr += " "; dataStr += mime; }
                if (!dataStr.empty()) {
                    if (!currentIntentFilter.empty()) currentIntentFilter += ", ";
                    currentIntentFilter += "data:" + dataStr;
                }
            }
            if (trimmed.find("</intent-filter>") != std::string::npos) {
                inIntentFilter = false;
                if (!currentIntentFilter.empty() && inComponent) {
                    currentComponent.intent_filters.push_back(currentIntentFilter);
                    // Components with intent-filters are implicitly exported (pre-API 31)
                    currentComponent.exported = true;
                }
            }
        }

        // Component end
        for (auto& type : {"activity", "service", "receiver", "provider"}) {
            std::string close = std::string("</") + type + ">";
            if (trimmed.find(close) != std::string::npos && inComponent) {
                info.components.push_back(currentComponent);
                inComponent = false;
                break;
            }
        }
    }

    return info;
}

std::optional<ToolResult> PermissionsTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("PERMISSIONS:") != 0)
        return std::nullopt;

    std::string path = action.substr(12);
    while (!path.empty() && path[0] == ' ') path.erase(0, 1);
    while (!path.empty() && path.back() == ' ') path.pop_back();

    if (path.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a path to AndroidManifest.xml or a directory."};
    }

    // Find the manifest
    std::string manifestPath;
    if (fs::is_directory(path)) {
        if (fs::exists(path + "/AndroidManifest.xml"))
            manifestPath = path + "/AndroidManifest.xml";
        else {
            // Search recursively (apktool output structure)
            std::error_code ec2;
            auto pit = fs::recursive_directory_iterator(path,
                fs::directory_options::skip_permission_denied, ec2);
            for (; pit != fs::recursive_directory_iterator(); pit.increment(ec2)) {
                if (ec2) { ec2.clear(); continue; }
                if (pit->path().filename() == "AndroidManifest.xml") {
                    manifestPath = pit->path().string();
                    break;
                }
            }
        }
    } else if (fs::exists(path)) {
        manifestPath = path;
    }

    if (manifestPath.empty() || !fs::exists(manifestPath)) {
        return ToolResult{
            "OBSERVATION: AndroidManifest.xml not found at " + path + ". "
            "If analyzing an APK, use DECOMPILE first to extract it."};
    }

    ctx.cb({AgentMessage::THINKING, "Parsing " + manifestPath + "..."});

    std::string contents = util::readFile(manifestPath);
    if (contents.empty()) {
        return ToolResult{"OBSERVATION: Error — could not read " + manifestPath};
    }

    auto info = parseManifest(contents);

    std::ostringstream out;
    out << "AndroidManifest Analysis: " << manifestPath << "\n\n";

    // App info
    if (!info.package_name.empty())
        out << "Package: " << info.package_name << "\n";
    if (!info.version_name.empty())
        out << "Version: " << info.version_name << " (code " << info.version_code << ")\n";
    if (!info.min_sdk.empty())
        out << "SDK: min=" << info.min_sdk << " target=" << info.target_sdk << "\n";
    out << "\n";

    // Permissions
    if (!info.permissions.empty()) {
        int dangerousCount = 0;
        out << "--- Permissions (" << info.permissions.size() << ") ---\n";
        for (auto& perm : info.permissions) {
            bool dangerous = DANGEROUS_PERMISSIONS.count(perm) > 0;
            if (dangerous) dangerousCount++;
            out << "  " << (dangerous ? "[!] " : "    ") << perm << "\n";
        }
        out << "  (" << dangerousCount << " dangerous permission(s) marked with [!])\n\n";
    }

    // Suspicious combinations
    {
        std::set<std::string> permSet(info.permissions.begin(), info.permissions.end());
        std::vector<std::string> warnings;
        for (auto& combo : SUSPICIOUS_COMBOS) {
            bool allPresent = true;
            for (auto& p : combo.perms) {
                if (!permSet.count(p)) { allPresent = false; break; }
            }
            if (allPresent) warnings.push_back(combo.warning);
        }
        if (!warnings.empty()) {
            out << "--- Suspicious Permission Combinations ---\n";
            for (auto& w : warnings) {
                out << "  [!] " << w << "\n";
            }
            out << "\n";
        }
    }

    // Components
    if (!info.components.empty()) {
        // Group by type
        std::map<std::string, std::vector<ManifestInfo::Component*>> byType;
        for (auto& c : info.components) byType[c.type].push_back(&c);

        for (auto& [type, comps] : byType) {
            int exportedCount = 0;
            for (auto* c : comps) if (c->exported) exportedCount++;

            out << "--- " << type << "s (" << comps.size()
                << ", " << exportedCount << " exported) ---\n";
            for (auto* c : comps) {
                out << "  " << (c->exported ? "[EXPORTED] " : "           ") << c->name << "\n";
                for (auto& filter : c->intent_filters) {
                    out << "    intent-filter: " << filter << "\n";
                }
            }
            out << "\n";
        }
    }

    // Features
    if (!info.uses_features.empty()) {
        out << "--- Required Features (" << info.uses_features.size() << ") ---\n";
        for (auto& f : info.uses_features) {
            out << "  " << f << "\n";
        }
        out << "\n";
    }

    // Summary risk indicators
    {
        std::set<std::string> permSet(info.permissions.begin(), info.permissions.end());
        std::vector<std::string> indicators;

        if (permSet.count("android.permission.BIND_DEVICE_ADMIN"))
            indicators.push_back("Device admin capability (common in ransomware)");
        if (permSet.count("android.permission.BIND_ACCESSIBILITY_SERVICE"))
            indicators.push_back("Accessibility service (can read screen, perform actions)");
        if (permSet.count("android.permission.INSTALL_PACKAGES") ||
            permSet.count("android.permission.REQUEST_INSTALL_PACKAGES"))
            indicators.push_back("Can install other packages (dropper behavior)");
        if (permSet.count("android.permission.SYSTEM_ALERT_WINDOW"))
            indicators.push_back("Can draw over other apps (phishing overlays)");

        int exportedServices = 0, exportedReceivers = 0;
        for (auto& c : info.components) {
            if (c.exported && c.type == "service") exportedServices++;
            if (c.exported && c.type == "receiver") exportedReceivers++;
        }
        if (exportedServices > 0)
            indicators.push_back(std::to_string(exportedServices) + " exported service(s) — attack surface");
        if (exportedReceivers > 0)
            indicators.push_back(std::to_string(exportedReceivers) + " exported receiver(s) — can be triggered externally");

        if (!indicators.empty()) {
            out << "--- Risk Indicators ---\n";
            for (auto& ind : indicators) {
                out << "  [!] " << ind << "\n";
            }
            out << "\n";
        }
    }

    std::string formatted = out.str();
    ctx.cb({AgentMessage::RESULT, formatted});

    return ToolResult{
        "OBSERVATION: " + formatted +
        "Use SCAN: to perform LLM-powered analysis of the smali code, "
        "or STRINGS: to extract hardcoded values."};
}

} // namespace area
