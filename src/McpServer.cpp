#include "McpServer.h"
#include "mcp/McpServer.h"
#include "mcp/McpUtil.h"
#include "IPC.h"
#include "util/file_io.h"
#include "features/chat/ChatFeature.h"
#include "features/tui/TuiFeature.h"

#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace area {

// ── helpers shared by inline tools ────────────────────────────────

static constexpr size_t kBuildOutputTrimLen  = 3000;
static constexpr size_t kBuildSuccessTrimLen = 1000;
static constexpr int    kServerStartPollIter = 24;
static constexpr int    kServerStopPollIter  = 20;

static std::string findBin(const std::string& workDir) {
    auto exe = util::selfExe();
    if (!exe.empty() && fs::exists(exe)) return exe;
    auto wb = workDir + "/area";
    if (fs::exists(wb)) return wb;
    return {};
}

static bool isServerRunning(const std::string& pidPath, int* outPid = nullptr) {
    std::ifstream f(pidPath);
    if (!f) return false;
    int pid = 0;
    f >> pid;
    if (pid <= 0) return false;
    if (outPid) *outPid = pid;
    return kill(pid, 0) == 0;
}

// ── inline tools (will become features later) ─────────────────────

static void registerBuildTools(mcp::McpServer& server, const std::string& workDir) {
    server.registerTool({
        "area_build",
        "Build (or rebuild) the AppReagent project. Run after editing C++ "
        "source, prompts, or CMakeLists.",
        {{"type", "object"}, {"properties", {
             {"target", {{"type", "string"},
                         {"description",
                          "Make target (default: all). Use 'test' for unit tests."}}}
        }}},
        [workDir](const json& args) -> mcp::ToolResult {
            auto target = args.value("target", "all");
            if (!mcp::isValidName(target)) return {"Invalid make target.", true};
            std::cerr << "[area-mcp] build target=" << target << std::endl;
            auto [out, rc] = mcp::exec(workDir, {"make", target});
            out = mcp::trimOutput(out, kBuildOutputTrimLen);
            if (rc != 0)
                return {"Build failed (exit " + std::to_string(rc) + "):\n" + out, true};
            return {"Build succeeded.\n" + mcp::trimOutput(out, kBuildSuccessTrimLen), false};
        }
    });
}

static void registerServerTools(mcp::McpServer& server,
                                 const std::string& dataDir,
                                 const std::string& workDir) {
    auto sockPath = dataDir + "/area.sock";
    auto pidPath  = dataDir + "/area.pid";

    server.registerTool({
        "area_server_start",
        "Start the AppReagent server daemon. Must be running before area_chat.",
        {{"type", "object"}, {"properties", json::object()}},
        [dataDir, workDir, sockPath, pidPath](const json&) -> mcp::ToolResult {
            int pid = 0;
            if (isServerRunning(pidPath, &pid))
                return {"Server already running (PID " + std::to_string(pid) + ").", false};

            auto bin = findBin(workDir);
            if (bin.empty()) return {"Binary not found — run area_build first.", true};

            std::error_code ec;
            fs::create_directories(dataDir, ec);
            fs::remove(sockPath, ec);

            std::cerr << "[area-mcp] starting server: " << bin << std::endl;

            pid_t child = fork();
            if (child < 0) return {"fork() failed.", true};
            if (child == 0) {
                setsid();
                pid_t srv = fork();
                if (srv == 0) {
                    int devnull = open("/dev/null", O_WRONLY);
                    if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
                    setenv("AREA_DATA_DIR", dataDir.c_str(), 1);
                    execl(bin.c_str(), bin.c_str(), "server", nullptr);
                    _exit(1);
                }
                _exit(0);
            }
            waitpid(child, nullptr, 0);

            for (int i = 0; i < kServerStartPollIter; i++) {
                usleep(500000);
                if (fs::exists(sockPath)) {
                    int spid = 0;
                    isServerRunning(pidPath, &spid);
                    return {"Server started (PID " + std::to_string(spid) + ").", false};
                }
            }
            return {"Server did not start within " +
                    std::to_string(kServerStartPollIter / 2) +
                    " s. Check config.json and database.", true};
        }
    });

    server.registerTool({
        "area_server_stop",
        "Stop the AppReagent server daemon.",
        {{"type", "object"}, {"properties", json::object()}},
        [sockPath, pidPath](const json&) -> mcp::ToolResult {
            int fd = ipc::connectTo(sockPath);
            if (fd >= 0) {
                ipc::sendLine(fd, {{"type", "shutdown"}});
                usleep(100000);
                ipc::closeFd(fd);
            }
            for (int i = 0; i < kServerStopPollIter; i++) {
                if (!isServerRunning(pidPath)) break;
                usleep(500000);
            }
            int pid = 0;
            if (isServerRunning(pidPath, &pid)) {
                kill(pid, SIGKILL);
                usleep(200000);
            }
            std::cerr << "[area-mcp] server stopped" << std::endl;
            return {"Server stopped.", false};
        }
    });

    server.registerTool({
        "area_server_restart",
        "Restart the AppReagent server. Use after rebuilding to pick up "
        "code and prompt changes.",
        {{"type", "object"}, {"properties", json::object()}},
        [&server, sockPath, pidPath, dataDir, workDir](const json& args) -> mcp::ToolResult {
            // Stop
            int fd = ipc::connectTo(sockPath);
            if (fd >= 0) {
                ipc::sendLine(fd, {{"type", "shutdown"}});
                usleep(100000);
                ipc::closeFd(fd);
            }
            for (int i = 0; i < kServerStopPollIter; i++) {
                if (!isServerRunning(pidPath)) break;
                usleep(500000);
            }
            int pid = 0;
            if (isServerRunning(pidPath, &pid)) {
                kill(pid, SIGKILL);
                usleep(200000);
            }
            usleep(500000);

            // Start
            auto bin = findBin(workDir);
            if (bin.empty()) return {"Binary not found — run area_build first.", true};

            std::error_code ec;
            fs::create_directories(dataDir, ec);
            fs::remove(sockPath, ec);

            pid_t child = fork();
            if (child < 0) return {"fork() failed.", true};
            if (child == 0) {
                setsid();
                pid_t srv = fork();
                if (srv == 0) {
                    int devnull = open("/dev/null", O_WRONLY);
                    if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
                    setenv("AREA_DATA_DIR", dataDir.c_str(), 1);
                    execl(bin.c_str(), bin.c_str(), "server", nullptr);
                    _exit(1);
                }
                _exit(0);
            }
            waitpid(child, nullptr, 0);

            for (int i = 0; i < kServerStartPollIter; i++) {
                usleep(500000);
                if (fs::exists(sockPath)) {
                    int spid = 0;
                    isServerRunning(pidPath, &spid);
                    return {"Server started (PID " + std::to_string(spid) + ").", false};
                }
            }
            return {"Server did not start.", true};
        }
    });

    server.registerTool({
        "area_server_status",
        "Check whether the AppReagent server is running.",
        {{"type", "object"}, {"properties", json::object()}},
        [workDir, sockPath, pidPath, dataDir](const json&) -> mcp::ToolResult {
            int pid = 0;
            bool running = isServerRunning(pidPath, &pid);
            json status = {
                {"running",       running},
                {"pid",           running ? pid : 0},
                {"socket_exists", fs::exists(sockPath)},
                {"binary",        findBin(workDir).empty() ? "not found" : findBin(workDir)},
                {"data_dir",      dataDir}
            };
            return {status.dump(2), false};
        }
    });
}

static void registerTestTools(mcp::McpServer& server, const std::string& workDir) {
    server.registerTool({
        "area_test_unit",
        "Run C++ unit tests (Google Test, ~125 tests). Rebuilds if needed.",
        {{"type", "object"}, {"properties", json::object()}},
        [workDir](const json&) -> mcp::ToolResult {
            std::cerr << "[area-mcp] running unit tests" << std::endl;
            auto [out, rc] = mcp::exec(workDir, {"make", "test"});
            out = mcp::trimOutput(out);
            if (out.empty()) out = rc == 0 ? "All tests passed." : "Tests failed.";
            return {out, rc != 0};
        }
    });

    server.registerTool({
        "area_test_e2e",
        "Run end-to-end use-case tests against a real server with real LLM "
        "endpoints. Can take several minutes.",
        {{"type", "object"}, {"properties", {
             {"test_name", {{"type", "string"},
                            {"description",
                             "Specific test or 'all' (default: all). "
                             "E.g. 'scan-benign-file'."}}}
        }}},
        [workDir](const json& args) -> mcp::ToolResult {
            auto testName = args.value("test_name", "all");
            if (!mcp::isValidName(testName)) return {"Invalid test name.", true};
            std::cerr << "[area-mcp] running e2e: " << testName << std::endl;
            auto [out, rc] = mcp::exec(workDir, {"./scripts/test-use-case.sh", testName});
            out = mcp::trimOutput(out);
            if (out.empty()) out = rc == 0 ? "E2E tests passed." : "E2E tests failed.";
            return {out, rc != 0};
        }
    });

    server.registerTool({
        "area_evaluate",
        "Run the scan evaluation pipeline to score current prompt quality, "
        "classification accuracy, and risk calibration.",
        {{"type", "object"}, {"properties", json::object()}},
        [workDir](const json&) -> mcp::ToolResult {
            auto bin = findBin(workDir);
            if (bin.empty()) return {"Binary not found — run area_build first.", true};
            std::cerr << "[area-mcp] running evaluation" << std::endl;
            auto [out, rc] = mcp::exec(workDir, {bin, "evaluate"});
            out = mcp::trimOutput(out);
            if (out.empty()) out = rc == 0 ? "Evaluation complete." : "Evaluation failed.";
            return {out, rc != 0};
        }
    });
}

// ── entry point ───────────────────────────────────────────────────

int runMcpServer(const std::string& dataDir, const std::string& workDir) {
    auto sockPath = dataDir + "/area.sock";
    auto bin = findBin(workDir);

    mcp::McpServer server;

    // Register features
    features::chat::registerTools(server, sockPath);
    if (!bin.empty()) {
        features::tui::registerTools(server, bin, sockPath);
    }

    // Register inline tools (will become features later)
    registerBuildTools(server, workDir);
    registerServerTools(server, dataDir, workDir);
    registerTestTools(server, workDir);

    return server.run();
}

} // namespace area
