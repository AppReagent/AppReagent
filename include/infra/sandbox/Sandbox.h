#pragma once

#include <mutex>
#include <string>

namespace area {
struct ExecResult {
    std::string output;
    int exit_code = -1;
};

class Sandbox {
 public:
    explicit Sandbox(const std::string& dataDir, const std::string& samplesDir = "");
    ~Sandbox();

    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;

    ExecResult exec(const std::string& command, int timeout_sec = 60);

    bool running() const { std::lock_guard lk(mu_); return !containerId_.empty(); }

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
}  // namespace area
