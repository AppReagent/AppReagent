#pragma once

#include <functional>
#include <mutex>
#include <string>

namespace area {

struct ExecResult {
    std::string output; // combined stdout + stderr
    int exit_code = -1;
};

class Sandbox {
public:
    // dataDir: where to create the workspace volume
    // samplesDir: read-only mount for malware samples (optional)
    Sandbox(const std::string& dataDir, const std::string& samplesDir = "");
    ~Sandbox();

    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;

    // Execute a command inside the container. Lazy-launches if needed.
    ExecResult exec(const std::string& command, int timeout_sec = 60);

    // Check if the container is running
    bool running() const { std::lock_guard lk(mu_); return !containerId_.empty(); }

    // Path to the writable workspace (host side)
    const std::string& workDir() const { return workDir_; }

private:
    void ensureRunning();
    void stop();

    std::string dataDir_;
    std::string samplesDir_;
    std::string workDir_;
    std::string containerId_;
    mutable std::mutex mu_;
};

} // namespace area
