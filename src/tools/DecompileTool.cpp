#include "tools/DecompileTool.h"
#include "tools/ToolContext.h"
#include "Agent.h"
#include "Sandbox.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace area {

std::optional<ToolResult> DecompileTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("DECOMPILE:") != 0)
        return std::nullopt;

    std::string args = action.substr(10);
    while (!args.empty() && args[0] == ' ') args.erase(0, 1);

    if (ctx.confirm) {
        auto r = ctx.confirm("DECOMPILE: " + args);
        if (r.action == ConfirmResult::DENY)
            return ToolResult{"User denied this action."};
        if (r.action == ConfirmResult::CUSTOM)
            args = r.customText;
    }

    // Parse: apk_path | output_dir
    std::string apkPath, outputDir;
    auto pipePos = args.find('|');
    if (pipePos != std::string::npos) {
        apkPath = args.substr(0, pipePos);
        outputDir = args.substr(pipePos + 1);
        while (!apkPath.empty() && apkPath.back() == ' ') apkPath.pop_back();
        while (!outputDir.empty() && outputDir[0] == ' ') outputDir.erase(0, 1);
        while (!outputDir.empty() && outputDir.back() == ' ') outputDir.pop_back();
    } else {
        apkPath = args;
        while (!apkPath.empty() && apkPath.back() == ' ') apkPath.pop_back();
    }

    if (apkPath.empty()) {
        return ToolResult{"OBSERVATION: Error — provide a path to an APK file.\n"
                          "Usage: DECOMPILE: <apk-path> [| <output-dir>]"};
    }

    if (!fs::exists(apkPath)) {
        return ToolResult{"OBSERVATION: Error — file not found: " + apkPath};
    }

    // Verify it's an APK (ZIP with PK magic)
    {
        std::ifstream f(apkPath, std::ios::binary);
        char magic[2] = {};
        f.read(magic, 2);
        if (magic[0] != 'P' || magic[1] != 'K') {
            return ToolResult{"OBSERVATION: Error — " + apkPath + " does not appear to be a valid APK/ZIP file."};
        }
    }

    // Default output directory
    if (outputDir.empty()) {
        std::string stem = fs::path(apkPath).stem().string();
        outputDir = fs::path(apkPath).parent_path().string() + "/" + stem + "_decompiled";
    }

    ctx.cb({AgentMessage::THINKING, "Decompiling " + apkPath + " to " + outputDir + "..."});

    // Try apktool first, fall back to unzip + baksmali
    std::string command;
    bool useApktool = true;

    // Check if apktool is available
    if (sandbox_) {
        auto check = sandbox_->exec("which apktool 2>/dev/null || which java 2>/dev/null");
        if (check.exit_code != 0 || check.output.empty()) {
            useApktool = false;
        }
    }

    if (useApktool && sandbox_) {
        command = "apktool d -f -o '" + outputDir + "' '" + apkPath + "' 2>&1";
        auto result = sandbox_->exec(command);

        if (result.exit_code == 0) {
            // Count what we got
            int smaliFiles = 0, xmlFiles = 0;
            std::error_code ec;
            for (auto& entry : fs::recursive_directory_iterator(outputDir,
                    fs::directory_options::skip_permission_denied, ec)) {
                if (!entry.is_regular_file()) continue;
                auto ext = entry.path().extension().string();
                if (ext == ".smali") smaliFiles++;
                else if (ext == ".xml") xmlFiles++;
            }

            bool hasManifest = fs::exists(outputDir + "/AndroidManifest.xml");

            std::ostringstream out;
            out << "Decompiled " << fs::path(apkPath).filename().string() << " successfully:\n"
                << "  Output: " << outputDir << "\n"
                << "  Smali files: " << smaliFiles << "\n"
                << "  XML files: " << xmlFiles << "\n"
                << "  AndroidManifest.xml: " << (hasManifest ? "yes" : "no") << "\n\n"
                << "Next steps:\n"
                << "  - PERMISSIONS: " << outputDir << " (analyze manifest)\n"
                << "  - STRINGS: " << outputDir << " (extract interesting strings)\n"
                << "  - SCAN: " << outputDir << " | <your question> (LLM analysis)";

            std::string formatted = out.str();
            ctx.cb({AgentMessage::RESULT, formatted});
            return ToolResult{"OBSERVATION: " + formatted};
        }
    }

    // Fallback: basic unzip
    if (sandbox_) {
        fs::create_directories(outputDir);
        command = "unzip -o -q '" + apkPath + "' -d '" + outputDir + "' 2>&1";
        auto result = sandbox_->exec(command);

        if (result.exit_code != 0) {
            return ToolResult{"OBSERVATION: Error decompiling — " + result.output +
                "\nMake sure apktool or unzip is available."};
        }

        // Try to run baksmali on any .dex files
        std::vector<std::string> dexFiles;
        for (auto& entry : fs::directory_iterator(outputDir)) {
            if (entry.path().extension() == ".dex")
                dexFiles.push_back(entry.path().string());
        }

        int smaliFiles = 0;
        for (auto& dex : dexFiles) {
            std::string smaliOut = outputDir + "/smali";
            auto bResult = sandbox_->exec(
                "baksmali d -o '" + smaliOut + "' '" + dex + "' 2>&1");
            if (bResult.exit_code == 0) {
                std::error_code ec;
                for (auto& entry : fs::recursive_directory_iterator(smaliOut,
                        fs::directory_options::skip_permission_denied, ec)) {
                    if (entry.path().extension() == ".smali") smaliFiles++;
                }
            }
        }

        std::ostringstream out;
        out << "Extracted " << fs::path(apkPath).filename().string() << ":\n"
            << "  Output: " << outputDir << "\n"
            << "  DEX files found: " << dexFiles.size() << "\n"
            << "  Smali files extracted: " << smaliFiles << "\n\n";

        if (smaliFiles == 0 && !dexFiles.empty()) {
            out << "Note: baksmali not available — DEX files were extracted but not disassembled.\n"
                << "Install baksmali to get smali output.\n\n";
        }

        out << "Next steps:\n"
            << "  - STRINGS: " << outputDir << " (extract interesting strings)\n"
            << "  - SCAN: " << outputDir << "/smali | <your question> (LLM analysis)";

        std::string formatted = out.str();
        ctx.cb({AgentMessage::RESULT, formatted});
        return ToolResult{"OBSERVATION: " + formatted};
    }

    return ToolResult{
        "OBSERVATION: Error — no sandbox available for decompilation. "
        "Start the server or use standalone mode."};
}

} // namespace area
