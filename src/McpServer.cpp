#include "McpServer.h"
#include "IPC.h"
#include "util/file_io.h"

#include <cctype>
#include <cstdio>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace area {

// ── helpers ────────────────────────────────────────────────────────

struct CmdResult { std::string output; int exitCode; };

static CmdResult exec(const std::string& workDir,
                       const std::vector<std::string>& argv) {
    if (argv.empty()) return {"no command", -1};

    int pipefd[2];
    if (pipe(pipefd) < 0) return {"pipe() failed", -1};

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return {"fork() failed", -1};
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        if (!workDir.empty()) {
            if (chdir(workDir.c_str()) != 0) _exit(127);
        }
        std::vector<const char*> cargs;
        for (auto& a : argv) cargs.push_back(a.c_str());
        cargs.push_back(nullptr);
        execvp(cargs[0], const_cast<char**>(cargs.data()));
        _exit(127);
    }

    close(pipefd[1]);
    std::string out;
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) out.append(buf, n);
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    return {out, WIFEXITED(status) ? WEXITSTATUS(status) : -1};
}

static constexpr size_t kDefaultTrimLen     = 4000;
static constexpr size_t kBuildOutputTrimLen  = 3000;
static constexpr size_t kBuildSuccessTrimLen = 1000;
static constexpr int    kServerStartPollIter = 24;     // x 500ms = 12s
static constexpr int    kServerStopPollIter  = 20;     // x 500ms = 10s
static constexpr int    kChatPollTimeoutMs   = 300000; // 5 min for scans

static std::string trimOutput(std::string s, size_t maxLen = kDefaultTrimLen) {
    if (s.size() > maxLen) s = "...\n" + s.substr(s.size() - maxLen);
    while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

static bool isValidName(const std::string& s) {
    for (char c : s)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_')
            return false;
    return !s.empty();
}

// ── McpServer ──────────────────────────────────────────────────────

McpServer::McpServer(std::string dataDir, std::string workDir)
    : dataDir_(std::move(dataDir))
    , workDir_(std::move(workDir))
    , sockPath_(dataDir_ + "/area.sock")
    , pidPath_(dataDir_ + "/area.pid")
{}

void McpServer::log(const std::string& msg) {
    std::cerr << "[area-mcp] " << msg << std::endl;
}

void McpServer::send(const json& msg) {
    std::cout << msg.dump() << "\n" << std::flush;
}

std::string McpServer::findBin() {
    auto exe = util::selfExe();
    if (!exe.empty() && fs::exists(exe)) return exe;
    auto wb = workDir_ + "/area";
    if (fs::exists(wb)) return wb;
    return {};
}

bool McpServer::isServerRunning(int* outPid) {
    std::ifstream f(pidPath_);
    if (!f) return false;
    int pid = 0;
    f >> pid;
    if (pid <= 0) return false;
    if (outPid) *outPid = pid;
    return kill(pid, 0) == 0;
}

// ── main loop ──────────────────────────────────────────────────────

int McpServer::run() {
    log("ready (data=" + dataDir_ + " work=" + workDir_ + ")");

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;

        json req;
        try { req = json::parse(line); }
        catch (...) { continue; }

        auto id     = req.contains("id") ? req["id"] : json();
        auto method = req.value("method", "");
        auto params = req.value("params", json::object());

        // Notifications have no id — just acknowledge silently
        if (id.is_null()) continue;

        try {
            if (method == "initialize") {
                send({{"jsonrpc", "2.0"}, {"id", id}, {"result", {
                    {"protocolVersion", "2024-11-05"},
                    {"capabilities", {{"tools", json::object()}}},
                    {"serverInfo", {{"name", "area"}, {"version", "1.0.0"}}}
                }}});

            } else if (method == "tools/list") {
                send({{"jsonrpc", "2.0"}, {"id", id},
                      {"result", {{"tools", toolList()}}}});

            } else if (method == "tools/call") {
                auto name = params.value("name", "");
                auto args = params.value("arguments", json::object());
                auto [text, isErr] = dispatch(name, args);
                send({{"jsonrpc", "2.0"}, {"id", id}, {"result", {
                    {"content", json::array({{{"type", "text"}, {"text", text}}})},
                    {"isError", isErr}
                }}});

            } else {
                send({{"jsonrpc", "2.0"}, {"id", id}, {"error",
                    {{"code", -32601}, {"message", "Unknown method: " + method}}}});
            }
        } catch (const std::exception& e) {
            log("error: " + std::string(e.what()));
            send({{"jsonrpc", "2.0"}, {"id", id}, {"error",
                {{"code", -32603}, {"message", e.what()}}}});
        }
    }

    return 0;
}

// ── tool list ──────────────────────────────────────────────────────

json McpServer::toolList() {
    return json::array({
        {{"name", "area_build"},
         {"description",
          "Build (or rebuild) the AppReagent project. Run after editing C++ "
          "source, prompts, or CMakeLists."},
         {"inputSchema", {{"type", "object"}, {"properties", {
              {"target", {{"type", "string"},
                          {"description",
                           "Make target (default: all). Use 'test' for unit tests."}}}
          }}}}},

        {{"name", "area_server_start"},
         {"description",
          "Start the AppReagent server daemon. Must be running before area_chat."},
         {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

        {{"name", "area_server_stop"},
         {"description", "Stop the AppReagent server daemon."},
         {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

        {{"name", "area_server_restart"},
         {"description",
          "Restart the AppReagent server. Use after rebuilding to pick up "
          "code and prompt changes."},
         {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

        {{"name", "area_server_status"},
         {"description", "Check whether the AppReagent server is running."},
         {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

        {{"name", "area_chat"},
         {"description",
          "Send a message to the AppReagent agent. The agent can run scans "
          "(SCAN), execute SQL queries, analyze files, generate reports, and "
          "more. The server must be running (area_server_start)."},
         {"inputSchema", {{"type", "object"},
          {"properties", {
              {"message", {{"type", "string"},
                           {"description",
                            "Message for the agent. Examples: 'scan "
                            "/path/to/file.smali', 'show last 5 scan results', "
                            "'SELECT * FROM scan_results LIMIT 5'"}}},
              {"chat_id", {{"type", "string"},
                           {"description",
                            "Chat session ID (default: claude-code). "
                            "Different IDs = separate conversations."}}}
          }},
          {"required", json::array({"message"})}}}},

        {{"name", "area_clear_chat"},
         {"description",
          "Clear conversation history for a chat session. Useful for starting "
          "a fresh analysis."},
         {"inputSchema", {{"type", "object"}, {"properties", {
              {"chat_id", {{"type", "string"},
                           {"description",
                            "Chat session ID (default: claude-code)."}}}
          }}}}},

        {{"name", "area_test_unit"},
         {"description",
          "Run C++ unit tests (Google Test, ~125 tests). Rebuilds if needed."},
         {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}},

        {{"name", "area_test_e2e"},
         {"description",
          "Run end-to-end use-case tests against a real server with real LLM "
          "endpoints. Can take several minutes."},
         {"inputSchema", {{"type", "object"}, {"properties", {
              {"test_name", {{"type", "string"},
                             {"description",
                              "Specific test or 'all' (default: all). "
                              "E.g. 'scan-benign-file'."}}}
          }}}}},

        {{"name", "area_evaluate"},
         {"description",
          "Run the scan evaluation pipeline to score current prompt quality, "
          "classification accuracy, and risk calibration."},
         {"inputSchema", {{"type", "object"}, {"properties", json::object()}}}}
    });
}

// ── dispatch ───────────────────────────────────────────────────────

std::pair<std::string, bool> McpServer::dispatch(const std::string& name,
                                                  const json& args) {
    if (name == "area_build")          return toolBuild(args);
    if (name == "area_server_start")   return toolServerStart();
    if (name == "area_server_stop")    return toolServerStop();
    if (name == "area_server_restart") return toolServerRestart();
    if (name == "area_server_status")  return toolServerStatus();
    if (name == "area_chat")           return toolChat(args);
    if (name == "area_clear_chat")     return toolClearChat(args);
    if (name == "area_test_unit")      return toolTestUnit();
    if (name == "area_test_e2e")       return toolTestE2e(args);
    if (name == "area_evaluate")       return toolEvaluate();
    return {"Unknown tool: " + name, true};
}

// ── tool implementations ───────────────────────────────────────────

std::pair<std::string, bool> McpServer::toolBuild(const json& args) {
    auto target = args.value("target", "all");
    if (!isValidName(target)) return {"Invalid make target.", true};

    log("build target=" + target);
    auto [out, rc] = exec(workDir_, {"make", target});
    out = trimOutput(out, kBuildOutputTrimLen);

    if (rc != 0)
        return {"Build failed (exit " + std::to_string(rc) + "):\n" + out, true};
    return {"Build succeeded.\n" + trimOutput(out, kBuildSuccessTrimLen), false};
}

std::pair<std::string, bool> McpServer::toolServerStart() {
    int pid = 0;
    if (isServerRunning(&pid))
        return {"Server already running (PID " + std::to_string(pid) + ").", false};

    auto bin = findBin();
    if (bin.empty()) return {"Binary not found — run area_build first.", true};

    // Ensure data dir exists; remove stale socket
    std::error_code ec;
    fs::create_directories(dataDir_, ec);
    fs::remove(sockPath_, ec);

    log("starting server: " + bin);

    // Double-fork to fully daemonize the server process.
    pid_t child = fork();
    if (child < 0) return {"fork() failed.", true};

    if (child == 0) {
        setsid();
        pid_t server = fork();
        if (server == 0) {
            // Grandchild: becomes the server
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); close(devnull); }
            setenv("AREA_DATA_DIR", dataDir_.c_str(), 1);
            execl(bin.c_str(), bin.c_str(), "server", nullptr);
            _exit(1);
        }
        _exit(0);
    }
    waitpid(child, nullptr, 0); // reap intermediate child immediately

    // Wait for socket to appear
    for (int i = 0; i < kServerStartPollIter; i++) {
        usleep(500000);
        if (fs::exists(sockPath_)) {
            int spid = 0;
            isServerRunning(&spid);
            return {"Server started (PID " + std::to_string(spid) + ").", false};
        }
    }
    return {"Server did not start within " +
            std::to_string(kServerStartPollIter / 2) +
            " s. Check config.json and database.", true};
}

std::pair<std::string, bool> McpServer::toolServerStop() {
    int fd = ipc::connectTo(sockPath_);
    if (fd >= 0) {
        ipc::sendLine(fd, {{"type", "shutdown"}});
        usleep(100000);
        ipc::closeFd(fd);
    }

    for (int i = 0; i < kServerStopPollIter; i++) {
        if (!isServerRunning()) break;
        usleep(500000);
    }

    // Force-kill if still alive
    int pid = 0;
    if (isServerRunning(&pid)) {
        kill(pid, SIGKILL);
        usleep(200000);
    }

    log("server stopped");
    return {"Server stopped.", false};
}

std::pair<std::string, bool> McpServer::toolServerRestart() {
    auto [stopMsg, _] = toolServerStop();
    usleep(500000);
    return toolServerStart();
}

std::pair<std::string, bool> McpServer::toolServerStatus() {
    int pid = 0;
    bool running = isServerRunning(&pid);
    json status = {
        {"running",       running},
        {"pid",           running ? pid : 0},
        {"socket_exists", fs::exists(sockPath_)},
        {"binary",        findBin().empty() ? "not found" : findBin()},
        {"data_dir",      dataDir_}
    };
    return {status.dump(2), false};
}

std::pair<std::string, bool> McpServer::toolChat(const json& args) {
    auto message = args.value("message", "");
    auto chatId  = args.value("chat_id", "claude-code");
    if (message.empty()) return {"'message' is required.", true};

    if (!fs::exists(sockPath_))
        return {"Server not running — call area_server_start first.", true};

    log("chat[" + chatId + "]: " + message.substr(0, 80));

    int fd = ipc::connectTo(sockPath_);
    if (fd < 0) return {"Could not connect to server.", true};

    // Attach + dangerous mode
    ipc::sendLine(fd, {{"type", "attach"},        {"chat_id", chatId}});
    ipc::sendLine(fd, {{"type", "set_dangerous"}, {"chat_id", chatId},
                       {"enabled", true}});

    // Drain history / initial state
    for (int i = 0; i < 50; i++) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 200) > 0) {
            bool gotState = false;
            while (auto msg = ipc::readLine(fd)) {
                if (msg->value("type", "") == "state") gotState = true;
            }
            if (gotState) break;
        }
    }

    ipc::sendLine(fd, {{"type", "user_input"}, {"chat_id", chatId},
                       {"content", message}});

    std::string result;
    bool done = false;
    while (!done) {
        struct pollfd rpfd = {fd, POLLIN, 0};
        if (poll(&rpfd, 1, kChatPollTimeoutMs) <= 0) { // 5 min timeout for scans
            result += "\n[timeout after 5 minutes]";
            break;
        }
        while (auto resp = ipc::readLine(fd)) {
            auto type = resp->value("type", "");
            if (type == "agent_msg") {
                auto t = (*resp)["msg"].value("type", "");
                auto c = (*resp)["msg"].value("content", "");
                if      (t == "answer")   result += c + "\n";
                else if (t == "sql")      result += "[sql] " + c + "\n";
                else if (t == "result")   result += "[result] " + c + "\n";
                else if (t == "error")    result += "[error] " + c + "\n";
                else if (t == "thinking") result += "[thinking] " + c + "\n";
            } else if (type == "state") {
                if (!resp->value("processing", true)) done = true;
            }
        }
    }

    ipc::closeFd(fd);

    if (result.empty()) return {"(no response)", false};
    while (!result.empty() && (result.back() == '\n' || result.back() == ' '))
        result.pop_back();
    return {result, false};
}

std::pair<std::string, bool> McpServer::toolClearChat(const json& args) {
    auto chatId = args.value("chat_id", "claude-code");

    int fd = ipc::connectTo(sockPath_);
    if (fd < 0) return {"Server not running.", true};

    ipc::sendLine(fd, {{"type", "attach"},        {"chat_id", chatId}});
    usleep(200000);
    ipc::sendLine(fd, {{"type", "clear_context"}, {"chat_id", chatId}});
    usleep(200000);
    ipc::closeFd(fd);

    return {"Chat \"" + chatId + "\" cleared.", false};
}

std::pair<std::string, bool> McpServer::toolTestUnit() {
    log("running unit tests");
    auto [out, rc] = exec(workDir_, {"make", "test"});
    out = trimOutput(out);
    if (out.empty()) out = rc == 0 ? "All tests passed." : "Tests failed.";
    return {out, rc != 0};
}

std::pair<std::string, bool> McpServer::toolTestE2e(const json& args) {
    auto testName = args.value("test_name", "all");
    if (!isValidName(testName)) return {"Invalid test name.", true};

    log("running e2e: " + testName);
    auto [out, rc] = exec(workDir_, {"./scripts/test-use-case.sh", testName});
    out = trimOutput(out);
    if (out.empty()) out = rc == 0 ? "E2E tests passed." : "E2E tests failed.";
    return {out, rc != 0};
}

std::pair<std::string, bool> McpServer::toolEvaluate() {
    auto bin = findBin();
    if (bin.empty()) return {"Binary not found — run area_build first.", true};

    log("running evaluation");
    auto [out, rc] = exec(workDir_, {bin, "evaluate"});
    out = trimOutput(out);
    if (out.empty()) out = rc == 0 ? "Evaluation complete." : "Evaluation failed.";
    return {out, rc != 0};
}

} // namespace area
