#include "Sandbox.h"

#include <array>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <sstream>

namespace fs = std::filesystem;

namespace area {

static std::string runCmd(const std::string& cmd, int* exitCode = nullptr) {
    std::string result;
    std::string wrapped = cmd + " 2>&1";
    FILE* pipe = popen(wrapped.c_str(), "r");
    if (!pipe) {
        if (exitCode) *exitCode = -1;
        return "failed to execute command";
    }
    // RAII guard to ensure pclose is called even on exception
    auto pcloseDeleter = [](FILE* f) { return pclose(f); };
    std::unique_ptr<FILE, decltype(pcloseDeleter)> pipeGuard(pipe, pcloseDeleter);
    std::array<char, 4096> buf;
    while (fgets(buf.data(), buf.size(), pipeGuard.get())) {
        result += buf.data();
    }
    int status = pclose(pipeGuard.release());
    if (exitCode) *exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    // trim trailing newline
    while (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}

Sandbox::Sandbox(const std::string& dataDir, const std::string& samplesDir)
    : dataDir_(dataDir), samplesDir_(samplesDir) {
    workDir_ = dataDir + "/sandbox-workspace";
    fs::create_directories(workDir_);
}

Sandbox::~Sandbox() {
    stop();
}

void Sandbox::ensureRunning() {
    if (!containerId_.empty()) return;

    // Shell-quote a path to prevent command injection from special characters
    auto shellQuote = [](const std::string& s) -> std::string {
        std::string q = "'";
        for (char c : s) {
            if (c == '\'') q += "'\\''";
            else q += c;
        }
        q += "'";
        return q;
    };

    std::ostringstream cmd;
    cmd << "docker run -d --rm"
        << " --network none"
        << " --memory 512m"
        << " --cpus 1"
        << " -v " << shellQuote(workDir_) << ":/workspace";

    if (!samplesDir_.empty() && fs::exists(samplesDir_)) {
        cmd << " -v " << shellQuote(samplesDir_) << ":/samples:ro";
    }

    cmd << " -w /workspace"
        << " area-sandbox"
        << " sleep infinity";

    int exitCode;
    std::string id = runCmd(cmd.str(), &exitCode);
    if (exitCode != 0) {
        // Try pulling/building the image
        std::cerr << "[sandbox] container start failed: " << id << std::endl;
        std::cerr << "[sandbox] trying to build image..." << std::endl;
        int buildExit;
        std::string buildOut = runCmd("docker build -t area-sandbox -f Dockerfile.sandbox .", &buildExit);
        if (buildExit != 0) {
            std::cerr << "[sandbox] image build failed: " << buildOut << std::endl;
            return;
        }
        // Retry
        id = runCmd(cmd.str(), &exitCode);
        if (exitCode != 0) {
            std::cerr << "[sandbox] container start failed after build: " << id << std::endl;
            return;
        }
    }

    containerId_ = id;
    std::cerr << "[sandbox] container started: " << containerId_.substr(0, 12) << std::endl;
}

void Sandbox::stop() {
    std::lock_guard lk(mu_);
    if (containerId_.empty()) return;
    runCmd("docker kill " + containerId_);
    std::cerr << "[sandbox] container stopped: " << containerId_.substr(0, 12) << std::endl;
    containerId_.clear();
}

ExecResult Sandbox::exec(const std::string& command, int timeout_sec) {
    std::lock_guard lk(mu_);
    ensureRunning();

    if (containerId_.empty()) {
        return {"Sandbox not available. Docker may not be installed or the area-sandbox image could not be built.", 1};
    }

    // Escape single quotes in command for shell
    std::string escaped;
    for (char c : command) {
        if (c == '\'') escaped += "'\\''";
        else escaped += c;
    }

    std::ostringstream cmd;
    cmd << "timeout " << timeout_sec
        << " docker exec " << containerId_
        << " /bin/bash -c '" << escaped << "'";

    int exitCode;
    std::string output = runCmd(cmd.str(), &exitCode);

    // Truncate very long output
    const size_t maxOutput = 8192;
    if (output.size() > maxOutput) {
        output = output.substr(0, maxOutput) + "\n... (output truncated at " + std::to_string(maxOutput) + " bytes)";
    }

    return {output, exitCode};
}

} // namespace area
