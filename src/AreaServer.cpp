#include "AreaServer.h"
#include "IPC.h"
#include "util/convo_io.h"
#include "ScanLog.h"
#include "LLMBackend.h"
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
#include "tools/TuiTool.h"
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

#include <csignal>
#include <filesystem>
#include <fcntl.h>
#include <sys/socket.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <random>
#include <sstream>
#include <unistd.h>

namespace fs = std::filesystem;

namespace area {

static const char* msgTypeStr(AgentMessage::Type t) {
    switch (t) {
        case AgentMessage::THINKING: return "thinking";
        case AgentMessage::SQL:      return "sql";
        case AgentMessage::RESULT:   return "result";
        case AgentMessage::ANSWER:   return "answer";
        case AgentMessage::ERROR:       return "error";
        case AgentMessage::TUI_CONTROL: return "tui_control";
    }
    return "unknown";
}

void ChatSession::saveConvo() {
    std::lock_guard lk(messagesMu);
    fs::create_directories(dataDir);
    std::ofstream f(dataDir + "/convo.txt");
    if (!f.is_open()) return;
    for (auto& m : messages) {
        char prefix;
        if (m.who == "user") prefix = 'U';
        else if (m.type == "thinking") prefix = 'T';
        else if (m.type == "sql") prefix = 'S';
        else if (m.type == "result") prefix = 'R';
        else if (m.type == "answer") prefix = 'A';
        else if (m.type == "error") prefix = 'E';
        else prefix = 'A';
        f << prefix << ":" << util::escapeNewlines(m.content) << "\n";
    }
}

void ChatSession::loadConvo() {
    std::ifstream f(dataDir + "/convo.txt");
    if (!f.is_open()) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.size() < 2 || line[1] != ':') continue;
        char prefix = line[0];
        std::string content = util::unescapeNewlines(line.substr(2));
        DisplayMsg msg;
        if (prefix == 'U') { msg.who = "user"; msg.type = "thinking"; }
        else {
            msg.who = "agent";
            switch (prefix) {
                case 'T': msg.type = "thinking"; break;
                case 'S': msg.type = "sql"; break;
                case 'R': msg.type = "result"; break;
                case 'A': msg.type = "answer"; break;
                case 'E': msg.type = "error"; break;
                default: msg.type = "answer"; break;
            }
        }
        msg.content = std::move(content);
        messages.push_back(std::move(msg));
    }
}

AreaServer::AreaServer(Config config, const std::string& dataDir)
    : config_(std::move(config)), dataDir_(dataDir) {}

AreaServer::~AreaServer() {
    shutdown();
}

std::string AreaServer::generateId() {
    static thread_local std::mt19937 rng(std::random_device{}());
    static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string id;
    for (int i = 0; i < 8; i++) id += chars[rng() % (sizeof(chars) - 1)];
    return id;
}

ChatSession& AreaServer::getOrCreateChat(const std::string& id, const std::string& name) {
    std::lock_guard lk(chatsMu_);
    auto it = chats_.find(id);
    if (it != chats_.end()) return *it->second;

    auto session = std::make_unique<ChatSession>();
    session->id = id;
    session->name = name.empty() ? id : name;
    session->dataDir = dataDir_ + "/chats/" + id;

    if (!config_.ai_endpoints.empty()) {
        if (!chatPool_) {
            chatPool_ = std::make_unique<BackendPool>(config_.ai_endpoints);
        }

        session->sandbox = std::make_unique<Sandbox>(session->dataDir);

        session->tools = std::make_unique<ToolRegistry>();
        session->tools->add(std::make_unique<GenerateRunIdTool>());
        session->tools->add(std::make_unique<StateTool>(&scanState_));
        session->tools->add(std::make_unique<PauseScanTool>(&scanState_));
        session->tools->add(std::make_unique<ResumeScanTool>(&config_, db_, &scanState_, id));
        session->tools->add(std::make_unique<DeleteScanTool>(db_, &scanState_));
        session->tools->add(std::make_unique<ShellTool>(session->sandbox.get()));
        session->tools->add(std::make_unique<FindFilesTool>());
        session->tools->add(std::make_unique<GrepTool>());
        session->tools->add(std::make_unique<ReadFileTool>());
        session->tools->add(std::make_unique<ReadCodeTool>());
        session->tools->add(std::make_unique<XrefsTool>());
        session->tools->add(std::make_unique<StringsTool>());
        session->tools->add(std::make_unique<ManifestTool>());
        session->tools->add(std::make_unique<DecompileTool>());
        session->tools->add(std::make_unique<ClassesTool>());
        session->tools->add(std::make_unique<ScanTool>(&config_, db_, &scanState_, id, &eventBus_));
        session->tools->add(std::make_unique<AnalyzeTool>(&config_, db_, &eventBus_));
        session->tools->add(std::make_unique<TuiTool>());
        session->tools->add(std::make_unique<SqlTool>(db_));
        session->tools->add(std::make_unique<SimilarTool>(&config_, db_));
        session->tools->add(std::make_unique<CallGraphTool>(db_));
        session->tools->add(std::make_unique<FindBehaviorTool>(db_));
        session->tools->add(std::make_unique<PermissionsTool>());
        session->tools->add(std::make_unique<DisasmTool>());
        session->tools->add(std::make_unique<ReportTool>(db_));
        session->tools->add(std::make_unique<ImproveTool>(&config_, db_,
            std::filesystem::current_path().string()));

        Harness h = Harness::createDefault();
        h.loadConstitution(dataDir_ + "/constitution.md");

        session->agent = std::make_unique<Agent>(chatPool_.get(), *session->tools, std::move(h));

        std::string promptsDir = "prompts";
        if (auto envDir = std::getenv("AREA_PROMPTS_DIR")) {
            promptsDir = envDir;
        }
        // Per-session prompt overrides take priority
        std::string sessionPrompts = dataDir_ + "/chats/" + id + "/prompts";
        if (std::filesystem::exists(sessionPrompts + "/agent_system.prompt")) {
            promptsDir = sessionPrompts;
        }
        session->agent->setPromptsDir(promptsDir);

        std::string systemCtx;
        std::string ddl;
        try { ddl = ScanLog::loadDDL(); } catch (...) {}
        if (!ddl.empty()) {
            systemCtx += "Database DDL:\n```sql\n" + ddl + "```\n";
        }
        if (db_.isConnected()) {
            try {
                std::string schema = db_.getSchema();
                if (!schema.empty()) {
                    systemCtx += "\nLive schema:\n" + schema;
                }
            } catch (const std::exception& e) {
                std::cerr << "[server] failed to load schema for chat " << id << ": " << e.what() << std::endl;
            }
        }
        session->agent->setSystemContext(systemCtx);
    }

    session->loadConvo();

    auto& ref = *session;
    chats_[id] = std::move(session);
    return ref;
}

void AreaServer::sendToClient(int fd, const nlohmann::json& msg) {
    if (fd < 0) return;
    if (!ipc::sendLine(fd, msg)) {
        std::cerr << "[server] failed to send to client fd=" << fd << std::endl;
    }
}

void AreaServer::broadcastToChat(const std::string& chatId, const nlohmann::json& msg) {
    std::lock_guard lk(chatsMu_);
    auto it = chats_.find(chatId);
    if (it != chats_.end() && it->second->clientFd >= 0) {
        sendToClient(it->second->clientFd, msg);
    }
}

void AreaServer::processUserInput(ChatSession& chat, const std::string& input) {
    if (chat.processing) {
        // Old query may still be winding down after an interrupt.
        // Wait for it to finish (should be fast since it was interrupted),
        // then proceed with the new input.
        if (chat.processingThread.joinable()) chat.processingThread.join();
        // processing flag is cleared by the thread; double-check
        chat.processing = false;
    }

    {
        std::lock_guard lk(chat.messagesMu);
        chat.messages.push_back({"user", "thinking", input});
    }

    chat.processing = true;

    broadcastToChat(chat.id, nlohmann::json{{"type", "state"}, {"chat_id", chat.id}, {"processing", true}});

    if (chat.processingThread.joinable()) chat.processingThread.join();
    chat.processingThread = std::thread([this, &chat, input]() {
        ConfirmCallback confirm = nullptr;
        if (!chat.dangerousMode) {
            confirm = [this, &chat](const std::string& desc) -> ConfirmResult {
                nlohmann::json msg;
                {
                    std::lock_guard lk(chat.confirmMu);
                    chat.confirmReqId++;
                    int reqId = chat.confirmReqId;
                    chat.confirmPending = true;
                    chat.confirmDescription = desc;
                    chat.confirmIsPath = (desc.find("SCAN:") == 0);
                    chat.confirmResponded = false;

                    msg["type"] = "confirm_req";
                    msg["chat_id"] = chat.id;
                    msg["req_id"] = reqId;
                    msg["description"] = desc;
                    msg["is_path"] = chat.confirmIsPath;
                }
                // Broadcast without holding confirmMu — the event loop
                // acquires chatsMu_ then confirmMu, so holding confirmMu
                // here while broadcastToChat acquires chatsMu_ would deadlock.
                broadcastToChat(chat.id, msg);

                std::unique_lock lk(chat.confirmMu);
                bool ok = chat.confirmCv.wait_for(lk, std::chrono::minutes(5),
                    [&] { return chat.confirmResponded; });

                chat.confirmPending = false;
                if (!ok) return ConfirmResult{ConfirmResult::DENY, ""};
                return chat.confirmResult;
            };
        }

        chat.agent->process(input, [this, &chat](const AgentMessage& msg) {
            if (msg.type == AgentMessage::TUI_CONTROL) {
                try {
                    auto payload = nlohmann::json::parse(msg.content);
                    payload["type"] = "tui_control";
                    payload["chat_id"] = chat.id;
                    broadcastToChat(chat.id, payload);
                } catch (...) {}
                return;
            }

            std::string typeStr = msgTypeStr(msg.type);

            {
                std::lock_guard lk(chat.messagesMu);
                chat.messages.push_back({"agent", typeStr, msg.content});
            }

            broadcastToChat(chat.id, nlohmann::json{
                {"type", "agent_msg"},
                {"chat_id", chat.id},
                {"msg", {{"type", typeStr}, {"content", msg.content}}}
            });
        }, confirm);

        chat.processing = false;
        chat.saveConvo();
        broadcastToChat(chat.id, nlohmann::json{{"type", "state"}, {"chat_id", chat.id}, {"processing", false}});
    });
}

void AreaServer::handleMessage(int clientFd, const nlohmann::json& msg) {
    std::string type = msg.value("type", "");

    if (type == "user_input") {
        std::string chatId = msg.value("chat_id", "default");
        std::string content = msg.value("content", "");
        auto& chat = getOrCreateChat(chatId);
        processUserInput(chat, content);

    } else if (type == "confirm_resp") {
        std::string chatId = msg.value("chat_id", "default");
        std::lock_guard lk(chatsMu_);
        auto it = chats_.find(chatId);
        if (it == chats_.end()) return;
        auto& chat = *it->second;

        std::lock_guard clk(chat.confirmMu);
        std::string action = msg.value("action", "deny");
        if (action == "approve")
            chat.confirmResult = {ConfirmResult::APPROVE, ""};
        else if (action == "custom")
            chat.confirmResult = {ConfirmResult::CUSTOM, msg.value("text", "")};
        else
            chat.confirmResult = {ConfirmResult::DENY, ""};
        chat.confirmResponded = true;
        chat.confirmCv.notify_one();

    } else if (type == "attach") {
        std::string chatId = msg.value("chat_id", "default");
        auto& chat = getOrCreateChat(chatId);

        {
            std::lock_guard lk(chatsMu_);
            for (auto& [id, c] : chats_) {
                if (c->clientFd == clientFd) c->clientFd = -1;
            }
        }

        chat.clientFd = clientFd;

        nlohmann::json history = nlohmann::json::array();
        {
            std::lock_guard lk(chat.messagesMu);
            for (auto& m : chat.messages) {
                history.push_back({{"who", m.who}, {"type", m.type}, {"content", m.content}});
            }
        }
        sendToClient(clientFd, nlohmann::json{
            {"type", "history"},
            {"chat_id", chatId},
            {"messages", history}
        });

        sendToClient(clientFd, nlohmann::json{
            {"type", "state"},
            {"chat_id", chatId},
            {"processing", chat.processing.load()},
            {"dangerous", chat.dangerousMode.load()}
        });

        if (chat.confirmPending) {
            std::lock_guard clk(chat.confirmMu);
            sendToClient(clientFd, nlohmann::json{
                {"type", "confirm_req"},
                {"chat_id", chatId},
                {"req_id", chat.confirmReqId},
                {"description", chat.confirmDescription},
                {"is_path", chat.confirmIsPath}
            });
        }

    } else if (type == "list_chats") {
        nlohmann::json list = nlohmann::json::array();
        std::lock_guard lk(chatsMu_);
        for (auto& [id, c] : chats_) {
            list.push_back({
                {"id", c->id},
                {"name", c->name},
                {"processing", c->processing.load()},
                {"attached", c->clientFd >= 0}
            });
        }
        sendToClient(clientFd, nlohmann::json{{"type", "chat_list"}, {"chats", list}});

    } else if (type == "create_chat") {
        std::string name = msg.value("name", "");
        std::string id = generateId();
        auto& chat = getOrCreateChat(id, name.empty() ? id : name);
        sendToClient(clientFd, nlohmann::json{{"type", "chat_created"}, {"chat_id", chat.id}, {"name", chat.name}});

    } else if (type == "interrupt") {
        std::string chatId = msg.value("chat_id", "default");
        std::lock_guard lk(chatsMu_);
        auto it = chats_.find(chatId);
        if (it != chats_.end() && it->second->agent) {
            it->second->agent->interrupt();
            std::lock_guard clk(it->second->confirmMu);
            if (it->second->confirmPending) {
                it->second->confirmResult = {ConfirmResult::DENY, ""};
                it->second->confirmResponded = true;
                it->second->confirmCv.notify_one();
            }
        }

    } else if (type == "set_dangerous") {
        std::string chatId = msg.value("chat_id", "default");
        std::lock_guard lk(chatsMu_);
        auto it = chats_.find(chatId);
        if (it != chats_.end()) {
            it->second->dangerousMode = msg.value("enabled", false);
        }

    } else if (type == "clear_context") {
        std::string chatId = msg.value("chat_id", "default");
        ChatSession* session = nullptr;
        {
            std::lock_guard lk(chatsMu_);
            auto it = chats_.find(chatId);
            if (it != chats_.end()) session = it->second.get();
        }
        if (session) {
            // Interrupt any in-flight processing so the processing thread
            // doesn't re-save messages after we clear.
            if (session->agent) session->agent->interrupt();
            if (session->processingThread.joinable()) session->processingThread.join();
            session->processing = false;
            {
                std::lock_guard mlk(session->messagesMu);
                session->messages.clear();
            }
            if (session->agent) session->agent->clearHistory();
            session->saveConvo();
            // Tell the TUI processing is done so it can accept input
            broadcastToChat(chatId, nlohmann::json{
                {"type", "state"}, {"chat_id", chatId}, {"processing", false}});
        }

    } else if (type == "shutdown") {
        running_ = false;

    } else if (type == "detach") {
        std::lock_guard lk(chatsMu_);
        for (auto& [id, c] : chats_) {
            if (c->clientFd == clientFd) c->clientFd = -1;
        }
    }
}

void AreaServer::run() {
    fs::create_directories(dataDir_);
    fs::create_directories(dataDir_ + "/chats");

    if (!fs::exists(dataDir_ + "/ddl.sql") && fs::exists("ddl.sql"))
        fs::copy_file("ddl.sql", dataDir_ + "/ddl.sql", fs::copy_options::skip_existing);
    if (!fs::exists(dataDir_ + "/prompts") && fs::exists("prompts"))
        fs::copy("prompts", dataDir_ + "/prompts", fs::copy_options::recursive | fs::copy_options::skip_existing);
    if (!fs::exists(dataDir_ + "/constitution.md") && fs::exists("constitution.md"))
        fs::copy_file("constitution.md", dataDir_ + "/constitution.md", fs::copy_options::skip_existing);

    if (!config_.postgres_url.empty()) {
        try {
            db_.connect(config_.postgres_url, config_.postgres_cert);
            ScanLog(db_).ensureTables();
        } catch (const std::exception& e) {
            std::cerr << "[server] database: " << e.what() << std::endl;
        }
    }

    std::string sockPath = dataDir_ + "/area.sock";
    listenFd_ = ipc::createListener(sockPath);
    if (listenFd_ < 0) {
        std::cerr << "[server] failed to create socket at " << sockPath << std::endl;
        return;
    }

    {
        std::ofstream pf(dataDir_ + "/area.pid");
        pf << getpid() << std::endl;
    }

    std::cerr << "[server] listening on " << sockPath << std::endl;

    getOrCreateChat("default", "default");

    running_ = true;

    while (running_) {
        std::vector<struct pollfd> pfds;
        pfds.push_back({listenFd_, POLLIN, 0});
        {
            std::lock_guard lk(clientsMu_);
            for (int fd : clientFds_) {
                pfds.push_back({fd, POLLIN, 0});
            }
        }

        int ret = poll(pfds.data(), pfds.size(), 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (pfds[0].revents & POLLIN) {
            int clientFd = accept(listenFd_, nullptr, nullptr);
            if (clientFd >= 0) {
                int flags = fcntl(clientFd, F_GETFL, 0);
                if (flags >= 0) fcntl(clientFd, F_SETFL, flags | O_NONBLOCK);
                std::cerr << "[server] client connected fd=" << clientFd << std::endl;
                std::lock_guard lk(clientsMu_);
                clientFds_.push_back(clientFd);
            }
        }

        std::vector<int> toRemove;
        for (size_t i = 1; i < pfds.size(); i++) {
            int fd = pfds[i].fd;
            // Always drain pending data before handling disconnect — a client
            // may send clear_context or other messages right before closing.
            if (pfds[i].revents & (POLLIN | POLLHUP)) {
                while (auto msg = ipc::readLine(fd)) {
                    handleMessage(fd, *msg);
                    if (!running_) break;
                }
            }
            if (pfds[i].revents & (POLLHUP | POLLERR)) {
                toRemove.push_back(fd);
            } else if (pfds[i].revents & POLLIN) {
                char peek;
                ssize_t n = recv(fd, &peek, 1, MSG_PEEK | MSG_DONTWAIT);
                if (n == 0) toRemove.push_back(fd);
            }
        }

        for (int fd : toRemove) {
            std::cerr << "[server] client disconnected fd=" << fd << std::endl;
            {
                std::lock_guard lk(chatsMu_);
                for (auto& [id, c] : chats_) {
                    if (c->clientFd == fd) c->clientFd = -1;
                }
            }
            ipc::closeFd(fd);
            std::lock_guard lk(clientsMu_);
            clientFds_.erase(std::remove(clientFds_.begin(), clientFds_.end(), fd), clientFds_.end());
        }
    }

    std::cerr << "[server] shutting down..." << std::endl;

    {
        std::lock_guard lk(chatsMu_);
        for (auto& [id, c] : chats_) {
            if (c->processingThread.joinable()) c->processingThread.join();
            c->saveConvo();
        }
    }

    {
        std::lock_guard lk(clientsMu_);
        for (int fd : clientFds_) ipc::closeFd(fd);
        clientFds_.clear();
    }

    ipc::closeFd(listenFd_);
    ipc::removeSock(sockPath);
    fs::remove(dataDir_ + "/area.pid");

    std::cerr << "[server] stopped" << std::endl;
}

void AreaServer::shutdown() {
    running_ = false;
}

} // namespace area
