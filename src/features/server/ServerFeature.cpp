#include "features/server/ServerFeature.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <system_error>

#include "infra/ipc/IPC.h"
#include "mcp/McpTool.h"
#include "nlohmann/detail/json_ref.hpp"
#include "nlohmann/json.hpp"
#include "util/file_io.h"
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace area::features::server {

static constexpr int kServerStartPollIter = 24;
static constexpr int kServerStopPollIter  = 20;

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

static mcp::ToolResult startServer(const std::string& dataDir,
                                    const std::string& workDir,
                                    const std::string& sockPath,
                                    const std::string& pidPath) {
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
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO); close(devnull);
            }
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

static mcp::ToolResult stopServer(const std::string& sockPath,
                                   const std::string& pidPath) {
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

void registerTools(mcp::McpServer& server,
                   const std::string& dataDir,
                   const std::string& workDir) {
    auto sockPath = dataDir + "/area.sock";
    auto pidPath  = dataDir + "/area.pid";

    server.registerTool({
        "area_server_start",
        "Start the AppReagent server daemon. Must be running before area_chat.",
        {{"type", "object"}, {"properties", json::object()}},
        [=](const json&) -> mcp::ToolResult {
            return startServer(dataDir, workDir, sockPath, pidPath);
        }
    });

    server.registerTool({
        "area_server_stop",
        "Stop the AppReagent server daemon.",
        {{"type", "object"}, {"properties", json::object()}},
        [=](const json&) -> mcp::ToolResult {
            return stopServer(sockPath, pidPath);
        }
    });

    server.registerTool({
        "area_server_restart",
        "Restart the AppReagent server. Use after rebuilding to pick up "
        "code and prompt changes.",
        {{"type", "object"}, {"properties", json::object()}},
        [=](const json&) -> mcp::ToolResult {
            stopServer(sockPath, pidPath);
            usleep(500000);
            return startServer(dataDir, workDir, sockPath, pidPath);
        }
    });

    server.registerTool({
        "area_server_status",
        "Check whether the AppReagent server is running.",
        {{"type", "object"}, {"properties", json::object()}},
        [=](const json&) -> mcp::ToolResult {
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

}  // namespace area::features::server
