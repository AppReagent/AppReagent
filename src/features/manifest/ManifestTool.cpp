#include "features/manifest/ManifestTool.h"
#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

namespace area {

static std::string toLowerMF(const std::string& s) {
    std::string out = s;
    for (auto& c : out) c = std::tolower(static_cast<unsigned char>(c));
    return out;
}

// Extract attribute value: android:name="value" -> value
static std::string extractAttr(const std::string& line, const std::string& attr) {
    auto pos = line.find(attr + "=\"");
    if (pos == std::string::npos) {
        // Try without namespace prefix
        auto shortAttr = attr;
        auto colon = shortAttr.find(':');
        if (colon != std::string::npos) {
            shortAttr = shortAttr.substr(colon + 1);
            pos = line.find(shortAttr + "=\"");
        }
    }
    if (pos == std::string::npos) return "";

    auto qStart = line.find('"', pos);
    if (qStart == std::string::npos) return "";
    auto qEnd = line.find('"', qStart + 1);
    if (qEnd == std::string::npos) return "";
    return line.substr(qStart + 1, qEnd - qStart - 1);
}

static std::string findManifest(const std::string& path) {
    if (fs::is_regular_file(path)) {
        if (fs::path(path).filename() == "AndroidManifest.xml") return path;
        return "";
    }

    // Search directory for AndroidManifest.xml
    std::error_code ec;
    auto it = fs::recursive_directory_iterator(
        path, fs::directory_options::skip_permission_denied, ec);
    if (ec) return "";

    for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (it->is_regular_file(ec) && !ec &&
            it->path().filename() == "AndroidManifest.xml") {
            return it->path().string();
        }
        if (ec) ec.clear();
    }
    return "";
}

std::optional<ToolResult> ManifestTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("MANIFEST:") != 0)
        return std::nullopt;

    std::string path = action.substr(9);
    while (!path.empty() && path[0] == ' ') path.erase(0, 1);
    while (!path.empty() && path.back() == ' ') path.pop_back();

    if (path.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a path to AndroidManifest.xml or app directory."};
    }

    if (!path.empty() && path[0] == '~') {
        if (auto home = std::getenv("HOME")) {
            path = std::string(home) + path.substr(1);
        }
    }

    if (!fs::exists(path)) {
        return ToolResult{"OBSERVATION: Path not found: " + path};
    }

    std::string manifestPath = findManifest(path);
    if (manifestPath.empty()) {
        return ToolResult{"OBSERVATION: AndroidManifest.xml not found in " + path +
                          ". This tool requires a decompiled APK directory containing AndroidManifest.xml."};
    }

    ctx.cb({AgentMessage::THINKING, "Parsing " + manifestPath + "..."});

    std::ifstream file(manifestPath);
    if (!file.is_open()) {
        return ToolResult{"OBSERVATION: Cannot open " + manifestPath};
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }

    std::string packageName;
    std::vector<std::string> permissions;
    std::vector<std::string> activities;
    std::vector<std::string> services;
    std::vector<std::string> receivers;
    std::vector<std::string> providers;
    std::vector<std::string> intentFilters;
    std::vector<std::string> metaData;
    std::string minSdk, targetSdk;
    bool exported = false;

    enum Section { NONE, ACTIVITY, SERVICE, RECEIVER, PROVIDER, INTENT_FILTER };
    Section current = NONE;
    std::string currentComponent;

    for (size_t i = 0; i < lines.size(); i++) {
        std::string& l = lines[i];
        std::string lower = toLowerMF(l);

        // Package name
        if (lower.find("<manifest") != std::string::npos) {
            std::string pkg = extractAttr(l, "package");
            if (!pkg.empty()) packageName = pkg;
        }

        // SDK versions
        if (lower.find("<uses-sdk") != std::string::npos || lower.find("usesSdk") != std::string::npos) {
            std::string ms = extractAttr(l, "android:minSdkVersion");
            std::string ts = extractAttr(l, "android:targetSdkVersion");
            if (!ms.empty()) minSdk = ms;
            if (!ts.empty()) targetSdk = ts;
        }

        // Permissions
        if (lower.find("<uses-permission") != std::string::npos) {
            std::string perm = extractAttr(l, "android:name");
            if (!perm.empty()) permissions.push_back(perm);
        }

        // Components
        if (lower.find("<activity") != std::string::npos && lower.find("<activity-alias") == std::string::npos) {
            std::string name = extractAttr(l, "android:name");
            std::string exp = extractAttr(l, "android:exported");
            std::string entry = name;
            if (exp == "true") entry += " [exported]";
            if (!name.empty()) activities.push_back(entry);
            current = ACTIVITY;
            currentComponent = name;
        }
        if (lower.find("<service") != std::string::npos) {
            std::string name = extractAttr(l, "android:name");
            std::string exp = extractAttr(l, "android:exported");
            std::string entry = name;
            if (exp == "true") entry += " [exported]";
            if (!name.empty()) services.push_back(entry);
            current = SERVICE;
            currentComponent = name;
        }
        if (lower.find("<receiver") != std::string::npos) {
            std::string name = extractAttr(l, "android:name");
            std::string exp = extractAttr(l, "android:exported");
            std::string entry = name;
            if (exp == "true") entry += " [exported]";
            if (!name.empty()) receivers.push_back(entry);
            current = RECEIVER;
            currentComponent = name;
        }
        if (lower.find("<provider") != std::string::npos) {
            std::string name = extractAttr(l, "android:name");
            std::string auth = extractAttr(l, "android:authorities");
            std::string exp = extractAttr(l, "android:exported");
            std::string entry = name;
            if (!auth.empty()) entry += " (authorities: " + auth + ")";
            if (exp == "true") entry += " [exported]";
            if (!name.empty()) providers.push_back(entry);
            current = PROVIDER;
            currentComponent = name;
        }

        // Intent filters
        if (lower.find("<action") != std::string::npos && lower.find("android:name") != std::string::npos) {
            std::string actionName = extractAttr(l, "android:name");
            if (!actionName.empty() && !currentComponent.empty()) {
                intentFilters.push_back(currentComponent + " -> " + actionName);
            }
        }

        // Meta-data
        if (lower.find("<meta-data") != std::string::npos) {
            std::string name = extractAttr(l, "android:name");
            std::string value = extractAttr(l, "android:value");
            if (!name.empty()) {
                std::string entry = name;
                if (!value.empty()) entry += " = " + value;
                metaData.push_back(entry);
            }
        }

        // Close tags reset section
        if (lower.find("</activity") != std::string::npos ||
            lower.find("</service") != std::string::npos ||
            lower.find("</receiver") != std::string::npos ||
            lower.find("</provider") != std::string::npos) {
            current = NONE;
            currentComponent.clear();
        }
    }

    // Format output
    std::ostringstream out;
    out << "AndroidManifest.xml analysis (" << manifestPath << "):\n\n";

    if (!packageName.empty()) out << "Package: " << packageName << "\n";
    if (!minSdk.empty()) out << "Min SDK: " << minSdk << "\n";
    if (!targetSdk.empty()) out << "Target SDK: " << targetSdk << "\n";
    out << "\n";

    if (!permissions.empty()) {
        out << "== Permissions (" << permissions.size() << ") ==\n";
        // Classify dangerous permissions
        static const std::vector<std::string> dangerous = {
            "INTERNET", "READ_CONTACTS", "WRITE_CONTACTS", "READ_PHONE_STATE",
            "CALL_PHONE", "READ_CALL_LOG", "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
            "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "ACCESS_BACKGROUND_LOCATION",
            "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
            "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
            "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
            "RECEIVE_BOOT_COMPLETED", "READ_CALENDAR", "WRITE_CALENDAR"
        };
        for (auto& p : permissions) {
            std::string upper = p;
            for (auto& c : upper) c = std::toupper(static_cast<unsigned char>(c));
            bool isDangerous = false;
            for (auto& d : dangerous) {
                if (upper.find(d) != std::string::npos) { isDangerous = true; break; }
            }
            out << "  " << (isDangerous ? "[!] " : "    ") << p << "\n";
        }
        out << "\n";
    }

    if (!activities.empty()) {
        out << "== Activities (" << activities.size() << ") ==\n";
        for (auto& a : activities) out << "  " << a << "\n";
        out << "\n";
    }

    if (!services.empty()) {
        out << "== Services (" << services.size() << ") ==\n";
        for (auto& s : services) out << "  " << s << "\n";
        out << "\n";
    }

    if (!receivers.empty()) {
        out << "== Receivers (" << receivers.size() << ") ==\n";
        for (auto& r : receivers) out << "  " << r << "\n";
        out << "\n";
    }

    if (!providers.empty()) {
        out << "== Providers (" << providers.size() << ") ==\n";
        for (auto& p : providers) out << "  " << p << "\n";
        out << "\n";
    }

    if (!intentFilters.empty()) {
        out << "== Intent Filters (" << intentFilters.size() << ") ==\n";
        for (auto& f : intentFilters) out << "  " << f << "\n";
        out << "\n";
    }

    if (!metaData.empty()) {
        out << "== Meta-data (" << metaData.size() << ") ==\n";
        for (auto& m : metaData) out << "  " << m << "\n";
        out << "\n";
    }

    std::string result = out.str();
    ctx.cb({AgentMessage::RESULT, result});
    return ToolResult{"OBSERVATION: " + result};
}

} // namespace area
