#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <poll.h>
#include <unistd.h>
#include <curl/curl.h>

#include "ArgParse.h"
#include "Config.h"
#include "ScanLog.h"
#include "Database.h"
#include "LLMBackend.h"
#include "Agent.h"
#include "BackendPool.h"
#include "Harness.h"
#include "Sandbox.h"
#include "ScanCommand.h"
#include "ScanState.h"
#include "Tui.h"
#include "AreaServer.h"
#include "IPC.h"
#include "tools/ToolRegistry.h"
#include "tools/GenerateRunIdTool.h"
#include "tools/StateTool.h"
#include "tools/PauseScanTool.h"
#include "tools/ResumeScanTool.h"
#include "tools/DeleteScanTool.h"
#include "tools/ShellTool.h"
#include "tools/ScanTool.h"
#include "tools/SqlTool.h"
#include "tools/AnalyzeTool.h"
#include "tools/FindFilesTool.h"
#include "tools/ImproveTool.h"
#include "tools/SimilarTool.h"
#include "tools/CallGraphTool.h"
#include "tools/FindBehaviorTool.h"
#include "tools/GrepTool.h"
#include "tools/ReadFileTool.h"
#include "tools/XrefsTool.h"
#include "tools/StringsTool.h"
#include "tools/ManifestTool.h"
#include "tools/PermissionsTool.h"
#include "tools/DecompileTool.h"
#include "tools/DisasmTool.h"
#include "tools/ReportTool.h"
#include "tools/ReadCodeTool.h"
#include "tools/ClassesTool.h"
#include "tools/ToolContext.h"

namespace fs = std::filesystem;

static std::string getDataDir() {
    if (auto dir = std::getenv("AREA_DATA_DIR")) return dir;
    return "/opt/area";
}

static std::string getSockPath() {
    return getDataDir() + "/area.sock";
}

static int runScan(area::Config& config, area::Database& db,
                   const std::string& target, const std::string& runId,
                   const std::string& goal = "") {
    area::ScanCommand scan(config, db);
    auto summary = scan.run(target, runId, goal);
    return (summary.files_error > 0) ? 1 : 0;
}

static int runTui(area::Config& config, area::Database& db) {
    // Try connecting to server first
    int sockFd = area::ipc::connectTo(getSockPath());
    if (sockFd >= 0) {
        std::cerr << "Connected to server" << std::endl;
        area::Tui tui(sockFd, config.theme);
        tui.run();
        area::ipc::closeFd(sockFd);
        return 0;
    }

    // Standalone mode
    if (config.ai_endpoints.empty()) {
        std::cerr << "No ai_endpoints configured" << std::endl;
        return 1;
    }

    area::ScanLog(db).ensureTables();

    auto pool = std::make_unique<area::BackendPool>(config.ai_endpoints);
    area::ScanState scanState;
    area::Sandbox sandbox(getDataDir());

    // Build tool registry
    area::ToolRegistry tools;
    tools.add(std::make_unique<area::GenerateRunIdTool>());
    tools.add(std::make_unique<area::StateTool>(&scanState));
    tools.add(std::make_unique<area::PauseScanTool>(&scanState));
    tools.add(std::make_unique<area::ResumeScanTool>(&config, db, &scanState, "standalone"));
    tools.add(std::make_unique<area::DeleteScanTool>(db, &scanState));
    tools.add(std::make_unique<area::ShellTool>(&sandbox));
    tools.add(std::make_unique<area::FindFilesTool>());
    tools.add(std::make_unique<area::GrepTool>());
    tools.add(std::make_unique<area::ReadFileTool>());
    tools.add(std::make_unique<area::ReadCodeTool>());
    tools.add(std::make_unique<area::XrefsTool>());
    tools.add(std::make_unique<area::StringsTool>());
    tools.add(std::make_unique<area::ManifestTool>());
    tools.add(std::make_unique<area::DecompileTool>());
    tools.add(std::make_unique<area::ClassesTool>());
    tools.add(std::make_unique<area::ScanTool>(&config, db, &scanState, "standalone"));
    tools.add(std::make_unique<area::AnalyzeTool>(&config, db));
    tools.add(std::make_unique<area::SqlTool>(db));
    tools.add(std::make_unique<area::SimilarTool>(&config, db));
    tools.add(std::make_unique<area::CallGraphTool>(db));
    tools.add(std::make_unique<area::FindBehaviorTool>(db));
    tools.add(std::make_unique<area::PermissionsTool>());
    tools.add(std::make_unique<area::DisasmTool>());
    tools.add(std::make_unique<area::ReportTool>(db));
    tools.add(std::make_unique<area::ImproveTool>(&config, db, fs::current_path().string()));

    area::Agent agent(pool.get(), tools);

    // Build system context
    std::string systemCtx;
    std::string ddl;
    try { ddl = area::ScanLog::loadDDL(); } catch (...) {}
    if (!ddl.empty()) {
        systemCtx += "Database DDL:\n```sql\n" + ddl + "```\n";
    }
    try {
        std::string schema = db.getSchema();
        if (!schema.empty()) {
            systemCtx += "\nLive schema:\n" + schema;
        }
    } catch (...) {}
    agent.setSystemContext(systemCtx);

    area::Tui tui(agent, config.theme);
    tui.run();
    return 0;
}

int main(int argc, char* argv[]) {
    area::ArgParse args(argc, argv);
    args.parse();

    area::Config config;
    try {
        auto configPath = args.getNamedArg("config").value_or("config.json");
        config = area::Config::load(configPath);
    } catch (const std::exception& e) {
        std::cerr << "Failed to load config: " << e.what() << std::endl;
        return 1;
    }

    // Ignore SIGPIPE so writing to a disconnected socket returns EPIPE
    // instead of killing the process.
    signal(SIGPIPE, SIG_IGN);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    area::Database db;
    try {
        db.connect(config.postgres_url, config.postgres_cert);
    } catch (const std::exception& e) {
        std::cerr << "Failed to connect to database: " << e.what() << std::endl;
        curl_global_cleanup();
        return 1;
    }

    int exitCode = 0;
    auto command = args.getPositionalArg(1);

    if (command == "scan") {
        auto target = args.getPositionalArg(2);
        if (!target) {
            std::cerr << "Usage: area scan <path-or-jsonl> [--run-id <id>] [--goal <question>]" << std::endl;
            exitCode = 1;
        } else if (target->ends_with(".jsonl")) {
            area::ScanCommand scan(config, db);
            auto summary = scan.runFromFile(*target);
            exitCode = (summary.files_error > 0) ? 1 : 0;
        } else {
            auto runId = args.getNamedArg("run-id").value_or("");
            auto goal = args.getNamedArg("goal").value_or("");
            exitCode = runScan(config, db, *target, runId, goal);
        }
    } else if (command == "test") {
        if (config.ai_endpoints.empty()) {
            std::cerr << "No ai_endpoints configured" << std::endl;
            exitCode = 1;
        } else {
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
        }
    } else if (command == "server") {
        area::AreaServer server(config, getDataDir());
        server.run();
    } else if (command == "kill-server") {
        int fd = area::ipc::connectTo(getSockPath());
        if (fd < 0) {
            std::cerr << "No server running" << std::endl;
            exitCode = 1;
        } else {
            area::ipc::sendLine(fd, {{"type", "shutdown"}});
            usleep(100000);
            area::ipc::closeFd(fd);
            std::cerr << "Server shutdown sent" << std::endl;
        }
    } else if (command == "chat") {
        int sockFd = area::ipc::connectTo(getSockPath());
        if (sockFd < 0) {
            std::cerr << "No server running. Start one with: area server" << std::endl;
            exitCode = 1;
        } else {
            auto chatId = args.getPositionalArg(2).value_or("default");
            area::ipc::sendLine(sockFd, {{"type", "attach"}, {"chat_id", chatId}});
            area::ipc::sendLine(sockFd, {{"type", "set_dangerous"}, {"chat_id", chatId}, {"enabled", true}});

            for (int i = 0; i < 50; i++) {
                struct pollfd p = {sockFd, POLLIN, 0};
                if (poll(&p, 1, 200) > 0) {
                    bool gotState = false;
                    while (auto msg = area::ipc::readLine(sockFd)) {
                        if (msg->value("type", "") == "state") gotState = true;
                    }
                    if (gotState) break;
                }
            }

            std::vector<std::string> queries;
            std::string line;
            while (std::getline(std::cin, line)) {
                if (!line.empty()) queries.push_back(line);
            }

            for (auto& query : queries) {
                if (query == "/clear") {
                    area::ipc::sendLine(sockFd, {{"type", "clear_context"}, {"chat_id", chatId}});
                    continue;
                }
                area::ipc::sendLine(sockFd, {{"type", "user_input"}, {"chat_id", chatId}, {"content", query}});

                bool done = false;
                while (!done) {
                    struct pollfd rpfd = {sockFd, POLLIN, 0};
                    if (poll(&rpfd, 1, 60000) <= 0) break;
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
            area::ipc::closeFd(sockFd);
        }
    } else if (command == "evaluate") {
        area::ImproveTool improve(&config, db, fs::current_path().string());
        // Run eval-only via a minimal ToolContext
        area::ToolRegistry dummyTools;
        area::Harness dummyHarness;
        area::ToolContext ctx{
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
        auto result = improve.tryExecute("IMPROVE: evaluate", ctx);
        if (result && result->observation.find("Error") != std::string::npos) exitCode = 1;
    } else if (command == "improve") {
        auto task = args.getPositionalArg(2);
        if (!task) {
            std::cerr << "Usage: area improve <task description>" << std::endl;
            std::cerr << "  area improve \"improve triage accuracy\"" << std::endl;
            std::cerr << "  area evaluate  (eval-only, no Claude Code needed)" << std::endl;
            exitCode = 1;
        } else {
            area::ImproveTool improve(&config, db, fs::current_path().string());
            area::ToolRegistry dummyTools;
            area::Harness dummyHarness;
            area::ToolContext ctx{
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
            auto result = improve.tryExecute("IMPROVE: " + *task, ctx);
            if (result && result->observation.find("Error") != std::string::npos) exitCode = 1;
        }
    } else if (!command || command == "tui") {
        exitCode = runTui(config, db);
    } else {
        std::cerr << "Unknown command: " << *command << std::endl;
        std::cerr << "Usage: area [server | kill-server | chat | scan <path> | tui | test | evaluate | improve <task>]" << std::endl;
        exitCode = 1;
    }

    curl_global_cleanup();
    return exitCode;
}
