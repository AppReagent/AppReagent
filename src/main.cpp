#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <curl/curl.h>
#include <bits/chrono.h>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <functional>
#include <map>
#include <algorithm>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "infra/config/ArgParse.h"
#include "infra/config/Config.h"
#include "infra/db/Database.h"
#include "infra/agent/Harness.h"
#include "features/ghidra/GhidraTool.h"
#include "features/scan/ScanCommand.h"
#include "features/frontend/tui/Tui.h"
#include "features/frontend/ws/WebSocketFrontend.h"
#include "features/server/AreaServer.h"
#include "infra/ipc/IPC.h"
#include "features/frontend/mcp/McpWiring.h"
#include "infra/tools/ToolRegistry.h"
#include "features/improve/ImproveTool.h"
#include "infra/tools/ToolContext.h"
#include "util/file_io.h"
#include "infra/agent/Agent.h"
#include "infra/llm/LLMBackend.h"
#include "infra/tools/Tool.h"
#include "nlohmann/detail/json_ref.hpp"
#include "nlohmann/json.hpp"

namespace fs = std::filesystem;

static constexpr int kServerStartPollIter = 24;
static constexpr int kChatPollTimeoutMs = 60000;
static constexpr int kStatePollIter = 50;
static constexpr int kStatePollIntervalMs = 200;
static constexpr int kShutdownDelayUs = 100000;

static std::string getDataDir() {
    if (auto dir = std::getenv("AREA_DATA_DIR")) return dir;
    return "/opt/area";
}

static std::string getSockPath() {
    return getDataDir() + "/area.sock";
}

static bool isServerAlive(const std::string& dataDir) {
    std::string pidPath = dataDir + "/area.pid";
    std::ifstream pf(pidPath);
    if (!pf) return false;
    pid_t pid = 0;
    pf >> pid;
    if (pid <= 0) return false;
    return kill(pid, 0) == 0;
}

static bool launchServer(const std::string& dataDir, const std::string& sockPath) {
    if (isServerAlive(dataDir)) {
        std::cerr << "Server process is running but socket is not responding" << std::endl;
        return false;
    }

    std::string bin = area::util::selfExe();
    if (bin.empty() || !fs::exists(bin)) {
        std::cerr << "Cannot find binary to launch server" << std::endl;
        return false;
    }

    std::error_code ec;
    fs::create_directories(dataDir, ec);
    fs::remove(sockPath, ec);

    std::cerr << "Starting server..." << std::endl;

    pid_t child = fork();
    if (child < 0) {
        std::cerr << "fork() failed" << std::endl; return false;
    }

    if (child == 0) {
        setsid();
        pid_t server = fork();
        if (server == 0) {
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
            std::cerr << "Server started" << std::endl;
            return true;
        }
    }
    std::cerr << "Server did not start within "
              << (kServerStartPollIter / 2) << "s" << std::endl;
    return false;
}

static int connectToServer() {
    std::string sockPath = getSockPath();

    struct stat st;
    if (stat(sockPath.c_str(), &st) == 0 && st.st_uid == 0 && getuid() != 0) {
        std::cerr << "Requires root" << std::endl;
        _exit(1);
    }

    int fd = area::ipc::connectTo(sockPath);
    if (fd >= 0) return fd;

    if (!launchServer(getDataDir(), sockPath)) return -1;
    return area::ipc::connectTo(sockPath);
}

static int cmdMcp() {
    signal(SIGPIPE, SIG_IGN);
    return area::runMcpServer(getDataDir(), fs::current_path().string());
}

static int cmdScan(area::Config& config, area::Database& db, area::ArgParse& args) {
    auto target = args.getPositionalArg(2);
    if (!target) {
        std::cerr << "Usage: area scan <path-or-jsonl> [--run-id <id>] [--goal <question>]" << std::endl;
        return 1;
    }

    area::ScanCommand scan(config, db);
    if (target->ends_with(".jsonl")) {
        auto summary = scan.runFromFile(*target);
        return (summary.files_error > 0) ? 1 : 0;
    }

    auto runId = args.getNamedArg("run-id").value_or("");
    auto goal = args.getNamedArg("goal").value_or("");
    auto summary = scan.run(*target, runId, goal);
    return (summary.files_error > 0) ? 1 : 0;
}

static int cmdTest(area::Config& config) {
    if (config.ai_endpoints.empty()) {
        std::cerr << "No ai_endpoints configured" << std::endl;
        return 1;
    }

    int exitCode = 0;
    for (auto& ep : config.ai_endpoints) {
        std::cerr << ep.id << " (" << ep.provider << " " << ep.url << ") ... " << std::flush;
        auto backend = area::LLMBackend::create(ep);
        auto start = std::chrono::steady_clock::now();
        try {
            auto result = backend->chat("Reply with just 'ok'.", {{"user", "ping"}});
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            std::cerr << "ok " << ms << "ms (" << result.substr(0, 40) << ")" << std::endl;
        } catch (const std::exception& e) {
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            std::cerr << "FAIL " << ms << "ms (" << e.what() << ")" << std::endl;
            exitCode = 1;
        }
    }
    return exitCode;
}

static int cmdServer(area::Config& config) {
    area::AreaServer server(config, getDataDir());

    std::unique_ptr<area::WebSocketFrontend> wsFrontend;
    if (config.ws_port > 0) {
        wsFrontend = std::make_unique<area::WebSocketFrontend>(
            server, server.eventBus(), config.ws_port);
        wsFrontend->start();
    }

    server.run();

    if (wsFrontend) wsFrontend->stop();
    return 0;
}

static int cmdKillServer() {
    int fd = area::ipc::connectTo(getSockPath());
    if (fd < 0) {
        std::cerr << "No server running" << std::endl;
        return 1;
    }
    area::ipc::sendLine(fd, {{"type", "shutdown"}});
    usleep(kShutdownDelayUs);
    area::ipc::closeFd(fd);
    std::cerr << "Server shutdown sent" << std::endl;
    return 0;
}

static void waitForState(int sockFd) {
    for (int i = 0; i < kStatePollIter; i++) {
        struct pollfd p = {sockFd, POLLIN, 0};
        if (poll(&p, 1, kStatePollIntervalMs) > 0) {
            bool gotState = false;
            while (auto msg = area::ipc::readLine(sockFd)) {
                if (msg->value("type", "") == "state") gotState = true;
            }
            if (gotState) break;
        }
    }
}

static void processChatResponse(int sockFd) {
    bool done = false;
    while (!done) {
        struct pollfd rpfd = {sockFd, POLLIN, 0};
        if (poll(&rpfd, 1, kChatPollTimeoutMs) <= 0) break;
        while (auto resp = area::ipc::readLine(sockFd)) {
            auto type = resp->value("type", "");
            if (type == "agent_msg") {
                auto t = (*resp)["msg"].value("type", "");
                auto c = (*resp)["msg"].value("content", "");
                if (t == "answer") std::cout << c << std::endl;
                else if (t == "sql") std::cout << "[sql] " << c << std::endl;
                else if (t == "result") std::cout << "[result] " << c << std::endl;
                else if (t == "error") std::cerr << "[error] " << c << std::endl;
            } else if (type == "state") {
                if (!resp->value("processing", true)) done = true;
            }
        }
    }
}

static int cmdGhidra(area::ArgParse& args) {
    auto path = args.getPositionalArg(2);
    if (!path) {
        std::cerr << "Usage: area ghidra <binary> [mode] [filter]" << std::endl;
        std::cerr << "  modes: overview (default), decompile, strings, imports, xrefs, function_at, data_at, all" << std::endl;
        std::cerr << "  filter: function name substring or hex address (0x1000D02E)" << std::endl;
        return 1;
    }

    auto mode = args.getPositionalArg(3).value_or("overview");
    auto filter = args.getPositionalArg(4).value_or("");

    area::GhidraTool tool;
    area::Harness harness;
    area::ToolContext ctx{
        [](const area::AgentMessage& msg) {
            if (msg.type == area::AgentMessage::RESULT ||
                msg.type == area::AgentMessage::ANSWER) {
                std::cout << msg.content << std::endl;
            } else if (msg.type == area::AgentMessage::ERROR) {
                std::cerr << msg.content << std::endl;
            }
        },
        nullptr,
        harness,
    };

    std::string action = "GHIDRA: " + *path + " | " + mode;
    if (!filter.empty()) action += " | " + filter;

    auto result = tool.tryExecute(action, ctx);
    if (!result) {
        std::cerr << "GhidraTool did not accept action" << std::endl;
        return 1;
    }
    bool failed = result->observation.find("Error") != std::string::npos;
    return failed ? 1 : 0;
}

static int cmdChat(area::ArgParse& args) {
    int sockFd = connectToServer();
    if (sockFd < 0) {
        std::cerr << "Could not connect to server" << std::endl;
        return 1;
    }

    auto chatId = args.getPositionalArg(2).value_or("default");
    area::ipc::sendLine(sockFd, {{"type", "attach"}, {"chat_id", chatId}});
    area::ipc::sendLine(sockFd, {{"type", "set_dangerous"}, {"chat_id", chatId}, {"enabled", true}});

    waitForState(sockFd);

    std::vector<std::string> queries;
    if (isatty(fileno(stdin))) {
        std::string line;
        while (std::getline(std::cin, line)) {
            if (!line.empty()) queries.push_back(line);
        }
    } else {
        std::string all((std::istreambuf_iterator<char>(std::cin)),
                        std::istreambuf_iterator<char>());
        while (!all.empty() && (all.back() == '\n' || all.back() == '\r')) all.pop_back();
        if (!all.empty()) queries.push_back(all);
    }

    for (auto& query : queries) {
        if (query == "/clear") {
            area::ipc::sendLine(sockFd, {{"type", "clear_context"}, {"chat_id", chatId}});
            continue;
        }
        area::ipc::sendLine(sockFd, {{"type", "user_input"}, {"chat_id", chatId}, {"content", query}});
        processChatResponse(sockFd);
    }

    area::ipc::closeFd(sockFd);
    return 0;
}

static area::ToolContext makeImproveContext() {
    area::ToolRegistry dummyTools;
    static area::Harness dummyHarness;
    return area::ToolContext{
        [](const area::AgentMessage& msg) {
            if (msg.type == area::AgentMessage::THINKING)
                std::cerr << msg.content << std::endl;
            else if (msg.type == area::AgentMessage::RESULT)
                std::cout << msg.content << std::endl;
            else if (msg.type == area::AgentMessage::ERROR)
                std::cerr << "[error] " << msg.content << std::endl;
        },
        nullptr,
        dummyHarness
    };
}

static int cmdEvaluate(area::Config& config, area::Database& db) {
    area::ImproveTool improve(&config, db, fs::current_path().string());
    auto ctx = makeImproveContext();
    auto result = improve.tryExecute("IMPROVE: evaluate", ctx);
    return (result && result->observation.find("Error") != std::string::npos) ? 1 : 0;
}

static int cmdImprove(area::Config& config, area::Database& db, area::ArgParse& args) {
    auto task = args.getPositionalArg(2);
    if (!task) {
        std::cerr << "Usage: area improve <task description>" << std::endl;
        std::cerr << "  area improve \"improve triage accuracy\"" << std::endl;
        std::cerr << "  area evaluate  (eval-only, no Claude Code needed)" << std::endl;
        return 1;
    }

    area::ImproveTool improve(&config, db, fs::current_path().string());
    auto ctx = makeImproveContext();
    auto result = improve.tryExecute("IMPROVE: " + *task, ctx);
    return (result && result->observation.find("Error") != std::string::npos) ? 1 : 0;
}

static int cmdTui(area::Config& config) {
    int sockFd = connectToServer();
    if (sockFd < 0) {
        std::cerr << "Could not connect to server" << std::endl;
        return 1;
    }

    std::cerr << "Connected to server" << std::endl;
    area::Tui tui(sockFd, config.theme);
    tui.run();
    area::ipc::closeFd(sockFd);
    return 0;
}

static void initProcess() {
    signal(SIGPIPE, SIG_IGN);

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
}

int main(int argc, char* argv[]) {
    area::ArgParse args(argc, argv);
    args.parse();

    auto command = args.getPositionalArg(1).value_or("tui");

    if (command == "mcp") return cmdMcp();

    area::Config config;
    try {
        auto configPath = args.getNamedArg("config").value_or("");
        if (configPath.empty()) {
            auto dataConfig = getDataDir() + "/config.json";
            configPath = fs::exists(dataConfig) ? dataConfig : "config.json";
        }
        config = area::Config::load(configPath);
    } catch (const std::exception& e) {
        std::cerr << "Failed to load config: " << e.what() << std::endl;
        return 1;
    }

    initProcess();

    area::Database db;
    try {
        db.connect(config.postgres_url, config.postgres_cert);
    } catch (const std::exception& e) {
        std::cerr << "Failed to connect to database: " << e.what() << std::endl;
        curl_global_cleanup();
        return 1;
    }

    using Handler = std::function<int()>;
    const std::map<std::string, Handler> commands = {
        {"scan",        [&] { return cmdScan(config, db, args); }},
        {"test",        [&] { return cmdTest(config); }},
        {"server",      [&] { return cmdServer(config); }},
        {"kill-server", [&] { return cmdKillServer(); }},
        {"chat",        [&] { return cmdChat(args); }},
        {"ghidra",      [&] { return cmdGhidra(args); }},
        {"evaluate",    [&] { return cmdEvaluate(config, db); }},
        {"improve",     [&] { return cmdImprove(config, db, args); }},
        {"tui",         [&] { return cmdTui(config); }},
    };

    int exitCode;
    auto it = commands.find(command);
    if (it != commands.end()) {
        exitCode = it->second();
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        std::cerr << "Usage: area [server | kill-server | chat | scan <path>"
                  << " | tui | test | evaluate | improve <task> | mcp]" << std::endl;
        exitCode = 1;
    }

    curl_global_cleanup();
    return exitCode;
}
