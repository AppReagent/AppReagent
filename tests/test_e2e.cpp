#include <gtest/gtest.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "infra/agent/Agent.h"
#include "features/server/AreaServer.h"
#include "infra/ipc/IPC.h"
#include "infra/llm/LLMBackend.h"
#include "infra/tools/Tool.h"
#include "infra/tools/ToolContext.h"
#include "features/scan/ScanLog.h"
#include "infra/tools/ToolRegistry.h"
#include "features/runid/GenerateRunIdTool.h"
#include "features/sql/SqlTool.h"

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// ScriptedMockBackend: responds based on prompt content to simulate real LLM
// ---------------------------------------------------------------------------

class ScriptedMockBackend : public area::LLMBackend {
public:
    explicit ScriptedMockBackend(const area::AiEndpoint& ep) : LLMBackend(ep) {}

    std::string chat(const std::string& system,
                     const std::vector<area::ChatMessage>& messages) override {
        callCount_++;
        if (messages.empty()) return "ANSWER: no input";

        std::string lastMsg = messages.back().content;
        std::string allHistory;
        for (auto& m : messages) allHistory += m.content + "\n";

        // If we already sent SQL and got results back, answer
        if (allHistory.find("I ran your SQL") != std::string::npos ||
            allHistory.find("rows):\n") != std::string::npos) {
            return "ANSWER: Based on the query results, there are records in the database.";
        }

        // If we got a scan result feedback
        if (allHistory.find("Scan completed") != std::string::npos ||
            allHistory.find("scan completed") != std::string::npos) {
            return "ANSWER: The scan completed successfully.";
        }

        // If asked about tables or schema
        if (lastMsg.find("table") != std::string::npos ||
            lastMsg.find("schema") != std::string::npos) {
            return "SQL: SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'";
        }

        // If asked to count something
        if (lastMsg.find("count") != std::string::npos ||
            lastMsg.find("how many") != std::string::npos) {
            return "SQL: SELECT COUNT(*) FROM scan_results";
        }

        // If asked to scan
        if (lastMsg.find("scan") != std::string::npos &&
            lastMsg.find("/") != std::string::npos) {
            auto slash = lastMsg.find('/');
            auto end = lastMsg.find(' ', slash);
            std::string path = (end != std::string::npos)
                ? lastMsg.substr(slash, end - slash) : lastMsg.substr(slash);
            return "SCAN: " + path;
        }

        // If asked to generate run ID
        if (lastMsg.find("run id") != std::string::npos ||
            lastMsg.find("run_id") != std::string::npos) {
            return "GENERATE_RUN_ID:";
        }

        // If asked with SQL: prefix already in the prompt (markdown wrapped)
        if (lastMsg.find("```sql") != std::string::npos) {
            return "ANSWER: I see SQL in the message.";
        }

        // Default answer
        return "ANSWER: " + lastMsg;
    }

    int callCount() const { return callCount_.load(); }

private:
    std::atomic<int> callCount_{0};
};

class FakeGhidraActionTool : public area::Tool {
 public:
    std::string name() const override { return "GHIDRA"; }

    std::string description() const override {
        return "<path> [| overview|imports|strings|xrefs|decompile]";
    }

    std::optional<area::ToolResult> tryExecute(const std::string& action,
                                               area::ToolContext&) override {
        if (!action.starts_with("GHIDRA:")) return std::nullopt;
        lastAction = action;
        actions.push_back(action);
        auto it = responses.find(action);
        if (it != responses.end()) {
            return area::ToolResult{it->second};
        }
        return area::ToolResult{"Ghidra observation for " + action};
    }

    std::string lastAction;
    std::vector<std::string> actions;
    std::map<std::string, std::string> responses;
};

// ---------------------------------------------------------------------------
// Test fixture: sets up an Agent with ScriptedMockBackend + ToolRegistry
// ---------------------------------------------------------------------------

class AgentE2E : public ::testing::Test {
protected:
    area::Database db_; // not connected — only for Agent construction
    area::AiEndpoint ep_{"test", "mock", "", "auto"};

    struct Result {
        std::vector<area::AgentMessage> messages;
        std::string lastAnswer() const {
            for (int i = (int)messages.size() - 1; i >= 0; i--) {
                if (messages[i].type == area::AgentMessage::ANSWER)
                    return messages[i].content;
            }
            return "";
        }
        bool hasType(area::AgentMessage::Type t) const {
            for (auto& m : messages) if (m.type == t) return true;
            return false;
        }
        std::string firstOfType(area::AgentMessage::Type t) const {
            for (auto& m : messages) if (m.type == t) return m.content;
            return "";
        }
    };

    Result runAgent(const std::string& query,
                    area::ConfirmCallback confirm = nullptr) {
        auto backend = std::make_unique<ScriptedMockBackend>(ep_);
        area::ToolRegistry tools;
        tools.add(std::make_unique<area::GenerateRunIdTool>());
        tools.add(std::make_unique<area::SqlTool>(db_));
        area::Agent agent(std::move(backend), tools);
        Result result;
        agent.process(query, [&](const area::AgentMessage& msg) {
            result.messages.push_back(msg);
        }, confirm);
        return result;
    }
};

// ---------------------------------------------------------------------------
// Agent tool routing tests
// ---------------------------------------------------------------------------

TEST_F(AgentE2E, DirectAnswerForSimpleQuery) {
    auto r = runAgent("hello");
    EXPECT_TRUE(r.hasType(area::AgentMessage::ANSWER));
    EXPECT_FALSE(r.lastAnswer().empty());
}

TEST_F(AgentE2E, RoutesToSqlForTableQuery) {
    // The scripted backend returns SQL: for "table" queries
    // But since DB isn't connected, execute will fail
    // Agent should emit SQL message then ERROR
    auto r = runAgent("what tables exist?");
    EXPECT_TRUE(r.hasType(area::AgentMessage::SQL));
    EXPECT_TRUE(r.hasType(area::AgentMessage::ERROR));
}

TEST_F(AgentE2E, RoutesToGenerateRunId) {
    auto r = runAgent("generate a run_id for me");
    // GENERATE_RUN_ID tool generates an ID and returns RESULT
    EXPECT_TRUE(r.hasType(area::AgentMessage::RESULT));
    auto result = r.firstOfType(area::AgentMessage::RESULT);
    EXPECT_TRUE(result.find("Generated run ID") != std::string::npos);
}

TEST_F(AgentE2E, ConfirmCallbackApprove) {
    int confirmCount = 0;
    auto r = runAgent("generate a run_id for me",
        [&](const std::string& desc) -> area::ConfirmResult {
            confirmCount++;
            return {area::ConfirmResult::APPROVE, ""};
        });
    EXPECT_GT(confirmCount, 0);
    EXPECT_TRUE(r.hasType(area::AgentMessage::RESULT));
}

TEST_F(AgentE2E, ConfirmCallbackDeny) {
    auto r = runAgent("generate a run_id for me",
        [](const std::string& desc) -> area::ConfirmResult {
            return {area::ConfirmResult::DENY, ""};
        });
    // Denied — should get an answer (the mock sees "User denied" feedback)
    EXPECT_TRUE(r.hasType(area::AgentMessage::ANSWER));
    // Should NOT have a RESULT (the tool was denied)
    EXPECT_FALSE(r.firstOfType(area::AgentMessage::RESULT).find("Generated run ID") != std::string::npos);
}

TEST_F(AgentE2E, ConfirmCallbackCustom) {
    auto r = runAgent("generate a run_id for me",
        [](const std::string& desc) -> area::ConfirmResult {
            return {area::ConfirmResult::CUSTOM, "Actually, just use run123"};
        });
    // Custom text fed back to agent as user message -> agent answers
    EXPECT_TRUE(r.hasType(area::AgentMessage::ANSWER));
}

TEST_F(AgentE2E, SqlMarkdownStripping) {
    // Test that extractSql strips ```sql ... ``` wrapping
    auto backend = std::make_unique<area::MockBackend>(ep_);
    backend->setResponses({
        "SQL: ```sql\nSELECT 1\n```",
        "ANSWER: done"
    });
    area::ToolRegistry tools;
    tools.add(std::make_unique<area::SqlTool>(db_));
    area::Agent agent(std::move(backend), tools);

    std::vector<area::AgentMessage> msgs;
    agent.process("test", [&](const area::AgentMessage& msg) {
        msgs.push_back(msg);
    });

    // Should have extracted "SELECT 1" from the markdown
    bool foundSql = false;
    for (auto& m : msgs) {
        if (m.type == area::AgentMessage::SQL) {
            // The SQL content should NOT contain backticks
            EXPECT_EQ(m.content.find("```"), std::string::npos);
            foundSql = true;
        }
    }
    EXPECT_TRUE(foundSql);
}

TEST_F(AgentE2E, SqlEmbeddedInText) {
    // Test that SQL: found in the middle of text is extracted
    auto backend = std::make_unique<area::MockBackend>(ep_);
    backend->setResponses({
        "Let me check the database.\n\nSQL: SELECT COUNT(*) FROM scan_results",
        "ANSWER: found it"
    });
    area::ToolRegistry tools;
    tools.add(std::make_unique<area::SqlTool>(db_));
    area::Agent agent(std::move(backend), tools);

    std::vector<area::AgentMessage> msgs;
    agent.process("check", [&](const area::AgentMessage& msg) {
        msgs.push_back(msg);
    });

    bool foundSql = false;
    for (auto& m : msgs) {
        if (m.type == area::AgentMessage::SQL) {
            EXPECT_TRUE(m.content.find("SELECT") != std::string::npos);
            foundSql = true;
        }
    }
    EXPECT_TRUE(foundSql);
}

TEST_F(AgentE2E, MaxIterationsReached) {
    // Agent should stop after MAX_ITERATIONS
    auto backend = std::make_unique<area::MockBackend>(ep_);
    // Always return SQL so agent never answers
    backend->setResponse("SQL: SELECT 1");
    area::ToolRegistry tools;
    tools.add(std::make_unique<area::SqlTool>(db_));
    area::Agent agent(std::move(backend), tools);

    std::vector<area::AgentMessage> msgs;
    agent.process("infinite loop", [&](const area::AgentMessage& msg) {
        msgs.push_back(msg);
    });

    // Should eventually get an answer about max iterations
    bool gotAnswer = false;
    for (auto& m : msgs) {
        if (m.type == area::AgentMessage::ANSWER) {
            gotAnswer = true;
        }
    }
    EXPECT_TRUE(gotAnswer);
}

TEST(AgentPrompting, BenchStylePromptAddsGhidraRuntimeGuidance) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();

    area::ToolRegistry tools;
    tools.add(std::make_unique<FakeGhidraActionTool>());

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\nGHIDRA DATA:\nOverview, imports, strings.\n"
        "Answer with entry point, interesting functions, suspicious strings, network IOCs, and malware behavior.",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    std::string system = backendPtr->lastSystem();
    EXPECT_NE(system.find("BINARY ANALYSIS WITH GHIDRA"), std::string::npos);
    EXPECT_NE(system.find("Pick 3-6 GHIDRA follow-up calls before answering."), std::string::npos);
    EXPECT_NE(system.find("GHIDRA xrefs on imports, strings, symbols, and addresses"), std::string::npos);
}

TEST(AgentPrompting, LargeBenchPromptAddsWrapUpRuntimeGuidance) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();

    area::ToolRegistry tools;
    tools.add(std::make_unique<FakeGhidraActionTool>());

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\nGHIDRA DATA:\nOverview, imports, strings.\n"
        "Answer with entry point, interesting functions, suspicious strings, network IOCs, and malware behavior.\n";
    prompt += std::string(21000, 'A');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    std::string system = backendPtr->lastSystem();
    EXPECT_NE(system.find("This prompt already contains prefetched Ghidra data."), std::string::npos);
    EXPECT_NE(system.find("answer instead of exhaustively exploring every suspicious string."),
              std::string::npos);
}

TEST(AgentPrompting, LargeBenchPromptCompactsUserMessageForModel) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    tools.add(std::make_unique<FakeGhidraActionTool>());

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Entry point: 1001516d (DLL entry) -> entry\n"
        "--- Named Functions / Exports (2) ---\n"
        "  StartEXS @ 10007ecb — undefined StartEXS(void)\n"
        "  ServiceMain @ 1000cf30 — undefined ServiceMain(void)\n"
        "--- Functions (40 shown) ---\n";
    for (int i = 0; i < 80; i++) {
        prompt += "  FUN_1000" + std::to_string(1000 + i) + " @ 1000abcd — undefined4 FUN(void)\n";
    }
    prompt +=
        "--- imports ---\n"
        "  connect [WS2_32.DLL] @ EXTERNAL:0000001a\n"
        "    callers: 11 | call sites: 12 — referenced by: StartEXS\n"
        "--- strings ---\n"
        "  [10017ff9] \"InstallSB\" (xrefs: 1)\n"
        "  [10019194] \"configuration block\" (xrefs: 1)\n"
        "  [10093654] \"version info\" (xrefs: 1) - used by: FUN_1000208f\n"
        "===================== END GHIDRA DATA =========================\n";
    prompt += std::string(21000, 'D');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    std::string sent = backendPtr->lastUserMessage().content;
    EXPECT_LT(sent.size(), prompt.size());
    EXPECT_NE(sent.find("GHIDRA DATA (COMPACTED)"), std::string::npos);
    EXPECT_NE(sent.find("Entry point: 1001516d"), std::string::npos);
    EXPECT_NE(sent.find("connect [WS2_32.DLL]"), std::string::npos);
    EXPECT_NE(sent.find("\"InstallSB\""), std::string::npos);
}

TEST(AgentPrompting, GenericPromptDoesNotAddGhidraRuntimeGuidance) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();

    area::ToolRegistry tools;
    tools.add(std::make_unique<FakeGhidraActionTool>());

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process("hello", [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastSystem().find("BINARY ANALYSIS WITH GHIDRA"), std::string::npos);
}

TEST(AgentPrompting, RuntimeGuidanceCanDriveGhidraFollowup) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    area::MockPromptEntry followup;
    followup.id = "bench-ghidra-followup";
    followup.match = {"BINARY ANALYSIS WITH GHIDRA"};
    followup.user_match = {"GHIDRA DATA", "interesting functions"};
    followup.response = "THOUGHT: I should verify an import caller first.\n"
                        "GHIDRA: /tmp/sample.dll | xrefs | Sleep";

    area::MockPromptEntry afterGhidra;
    afterGhidra.id = "after-ghidra";
    afterGhidra.match = {"Ghidra observation for GHIDRA: /tmp/sample.dll | xrefs | Sleep"};
    afterGhidra.response = "ANSWER: verified";

    backend->setPromptEntries({followup, afterGhidra});

    auto* backendPtr = backend.get();
    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: gethostbyname [WS2_32.DLL] @ EXTERNAL:00000016\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 100011af [COMPUTED_CALL]\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\nGHIDRA DATA:\nOverview, imports, strings.\n"
        "Describe interesting functions and suspicious strings.",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "after-ghidra");
    EXPECT_EQ(ghidraPtr->lastAction, "GHIDRA: /tmp/sample.dll | xrefs | Sleep");
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "verified");
}

TEST(AgentPrompting, LargeBenchPromptCompactsGhidraObservationsForModel) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    area::MockPromptEntry followup;
    followup.id = "large-observation-followup";
    followup.match = {"This prompt already contains prefetched Ghidra data."};
    followup.user_match = {"interesting functions"};
    followup.response = "THOUGHT: verify one import caller.\n"
                        "GHIDRA: /tmp/sample.dll | xrefs | connect";

    area::MockPromptEntry afterGhidra;
    afterGhidra.id = "after-compact-ghidra";
    afterGhidra.match = {"BOOTSTRAP EVIDENCE from GHIDRA: /tmp/sample.dll | xrefs | connect"};
    afterGhidra.response = "ANSWER: compacted";

    backend->setPromptEntries({followup, afterGhidra});
    auto* backendPtr = backend.get();

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    ghidraTool->responses["GHIDRA: /tmp/sample.dll | xrefs | connect"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: connect [WS2_32.DLL] @ EXTERNAL:0000001a\n"
        "Functions calling: 2 | Call sites: 2\n\n"
        "--- Callers (2) ---\n"
        "  StartEXS @ 10007ecb [COMPUTED_CALL]\n"
        "  FUN_1000208f @ 10002430 [COMPUTED_CALL]\n";
    auto* ghidraPtr = ghidraTool.get();
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Entry point: 1001516d (DLL entry) -> entry\n"
        "===================== END GHIDRA DATA =========================\n";
    prompt += std::string(21000, 'E');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "after-compact-ghidra");
    EXPECT_EQ(ghidraPtr->lastAction, "GHIDRA: /tmp/sample.dll | xrefs | connect");
    EXPECT_EQ(backendPtr->lastUserMessage().content.find("=== Ghidra Cross-References"),
              std::string::npos);
    EXPECT_NE(backendPtr->lastUserMessage().content.find("BOOTSTRAP EVIDENCE from GHIDRA"),
              std::string::npos);
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "compacted");
}

TEST(AgentPrompting, BenchStylePromptAutoRunsGhidraBootstrap) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: gethostbyname [WS2_32.DLL] @ EXTERNAL:00000016\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 100011af [COMPUTED_CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | Sleep"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 10001358 [COMPUTED_CALL]\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Likely DllMain: FUN_1000d02e @ 1000d02e\n"
        "--- imports ---\n"
        "  gethostbyname [WS2_32.DLL] (ordinal 52) @ EXTERNAL:00000016\n"
        "  Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_GE(backendPtr->callCount(), 1);
    EXPECT_EQ(ghidraPtr->actions.size(), 7u);
    EXPECT_EQ(ghidraPtr->actions[0], "GHIDRA: /tmp/sample.dll | decompile | 0x1000d02e");
    EXPECT_EQ(ghidraPtr->actions[1], "GHIDRA: /tmp/sample.dll | xrefs | gethostbyname");
    EXPECT_EQ(ghidraPtr->actions[2], "GHIDRA: /tmp/sample.dll | xrefs | Sleep");
    EXPECT_EQ(ghidraPtr->actions[3], "GHIDRA: /tmp/sample.dll | decompile | 0x100011af");
    EXPECT_EQ(ghidraPtr->actions[4], "GHIDRA: /tmp/sample.dll | disasm | 0x100011af");
    EXPECT_EQ(ghidraPtr->actions[5], "GHIDRA: /tmp/sample.dll | decompile | 0x10001358");
    EXPECT_EQ(ghidraPtr->actions[6], "GHIDRA: /tmp/sample.dll | disasm | 0x10001358");
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "done");
}

TEST(AgentPrompting, LargeBenchPromptSkipsGenericStringBootstrapSweep) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: gethostbyname [WS2_32.DLL] @ EXTERNAL:00000016\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 100011af [COMPUTED_CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | 0x100171f0"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Requested address: 0100171F0\n"
        "Data: 0100171F0 .. 0100171FF\n"
        "Type: string\n"
        "References: 1\n"
        "Referenced by: FUN_10002000 @ 010002040 [READ]\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- imports ---\n"
        "  gethostbyname [WS2_32.DLL] (ordinal 52) @ EXTERNAL:00000016\n"
        "--- strings ---\n"
        "  [100171f0] \"cmd.exe\"\n"
        "  [10017ff9] \"PSLIST\" (xrefs: 1)\n"
        "  [10017352] \"GetSystemDefaultLangID\"\n"
        "  [10017128] \"Sleep\"\n"
        "===================== END GHIDRA DATA =========================\n";
    prompt += std::string(21000, 'B');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"),
              ghidraPtr->actions.end());
    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | 0x100171f0"),
              ghidraPtr->actions.end());
    EXPECT_EQ(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | PSLIST"),
              ghidraPtr->actions.end());
    EXPECT_EQ(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | Sleep"),
              ghidraPtr->actions.end());
    EXPECT_EQ(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | GetSystemDefaultLangID"),
              ghidraPtr->actions.end());
}

TEST(AgentPrompting, LargeBenchPromptBootstrapsCmdShellFromStartxcmdString) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | cmd.exe"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Data: 010095B34 .. 010095B40\n"
        "Type: string (13 bytes)\n"
        "Value: \"\\\\cmd.exe /c \"\n\n"
        "--- Referencing Functions (1) ---\n"
        "  FUN_1000ff58 @ 1000ff58 - undefined4 FUN_1000ff58(char * param_1)\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x1000ff58"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_1000ff58 @ 1000ff58 (64 bytes) ---\n"
        "Likely command shell launcher: CreatePipe + CreateProcessA via \"\\\\cmd.exe /c \"\n"
        "Likely command dispatcher: robotwork, language\n"
        "Default injection target: iexplore.exe\n\n"
        "undefined4 FUN_1000ff58(char * param_1)\n"
        "{\n"
        "  CreatePipe((PHANDLE)&stack0xfffffff0,(PHANDLE)&stack0xffffffec,\n"
        "             (LPSECURITY_ATTRIBUTES)&stack0xffffffcc,0);\n"
        "  CreateProcessA((LPCSTR)0x0,&local_ac4,(LPSECURITY_ATTRIBUTES)0x0,\n"
        "                 (LPSECURITY_ATTRIBUTES)0x0,1,0,(LPVOID)0x0,(LPCSTR)0x0,\n"
        "                 (LPSTARTUPINFOA)&local_78,lpProcessInformation);\n"
        "}\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- strings ---\n"
        "  [100934b0] \"startxcmd\"\n"
        "===================== END GHIDRA DATA =========================\n";
    prompt += std::string(21000, 'C');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | cmd.exe"),
              ghidraPtr->actions.end());
    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | decompile | 0x1000ff58"),
              ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "done");
}

TEST(AgentPrompting, LargeBenchPromptCapsPostBootstrapGhidraActions) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setResponse("ANSWER: wrapped up");

    area::MockPromptEntry firstFollowup;
    firstFollowup.id = "large-ghidra-1";
    firstFollowup.match = {"This prompt already contains prefetched Ghidra data."};
    firstFollowup.user_match = {"Questions: interesting functions"};
    firstFollowup.response = "THOUGHT: verify the import caller.\n"
                             "GHIDRA: /tmp/sample.dll | xrefs | gethostbyname";

    area::MockPromptEntry secondFollowup;
    secondFollowup.id = "large-ghidra-2";
    secondFollowup.match = {"Ghidra observation for GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"};
    secondFollowup.response = "THOUGHT: inspect that function.\n"
                              "GHIDRA: /tmp/sample.dll | decompile | 0x10001074";

    area::MockPromptEntry thirdBlocked;
    thirdBlocked.id = "large-ghidra-3";
    thirdBlocked.match = {"Ghidra observation for GHIDRA: /tmp/sample.dll | decompile | 0x10001074"};
    thirdBlocked.response = "THOUGHT: inspect one more function.\n"
                            "GHIDRA: /tmp/sample.dll | decompile | 0x10002000";

    backend->setPromptEntries({firstFollowup, secondFollowup, thirdBlocked});

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- imports ---\n"
        "  gethostbyname [WS2_32.DLL] (ordinal 52) @ EXTERNAL:00000016\n"
        "===================== END GHIDRA DATA =========================\n";
    prompt += std::string(21000, 'C');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(ghidraPtr->actions.size(), 2u);
    EXPECT_EQ(ghidraPtr->actions[0], "GHIDRA: /tmp/sample.dll | xrefs | gethostbyname");
    EXPECT_EQ(ghidraPtr->actions[1], "GHIDRA: /tmp/sample.dll | decompile | 0x10001074");
    EXPECT_EQ(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | decompile | 0x10002000"),
              ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_FALSE(msgs.back().content.empty());
}

TEST(AgentPrompting, LargeBenchPromptXrefBootstrapPrefersCallerFunctionOverDirectCallee) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: gethostbyname [WS2_32.DLL] @ EXTERNAL:00000016\n"
        "Functions calling: 3 | Call sites: 8\n"
        "\n"
        "--- Caller Functions (2) ---\n"
        "  FUN_10001074 @ 10001074 - undefined4 FUN_10001074(void)\n"
        "    callsites (3): 100011af, 10001247, 100012df\n"
        "    direct callees: FUN_10001000 @ 10001000, Ordinal_52 @ EXTERNAL:00000016\n"
        "  FUN_1000208f @ 1000208f - undefined4 FUN_1000208f(void)\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001074"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_10001074 @ 10001074 (64 bytes) ---\n\n"
        "void FUN_10001074(void)\n"
        "{\n"
        "  Sleep(30000);\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | disasm | 0x10001074"] =
        "=== Ghidra Disassembly: sample.dll ===\n\n"
        "Requested address: 10001074\n"
        "Function: FUN_10001074 @ 10001074\n"
        "Instructions shown: 1 / 1\n"
        "\n"
        "=> 10001074: CALL Sleep [CALL]\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- imports ---\n"
        "  gethostbyname [WS2_32.DLL] (ordinal 52) @ EXTERNAL:00000016\n"
        "===================== END GHIDRA DATA =========================\n";
    prompt += std::string(21000, 'G');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"),
              ghidraPtr->actions.end());
    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | decompile | 0x10001074"),
              ghidraPtr->actions.end());
    EXPECT_EQ(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | decompile | 0x10001000"),
              ghidraPtr->actions.end());
    EXPECT_EQ(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | disasm | 0x10001000"),
              ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "done");
}

TEST(AgentPrompting, LargeBenchPromptBootstrapsThreadStartFromDllMain) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x1000d02e"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_1000d02e @ 01000D02E (64 bytes) ---\n\n"
        "int FUN_1000d02e(void)\n"
        "{\n"
        "  CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,(LPTHREAD_START_ROUTINE)&DAT_10001656,\n"
        "               (LPVOID)0x0,0,(LPDWORD)0x0);\n"
        "  return 1;\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001656"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- sub_10001620 @ 010001620 (64 bytes) ---\n\n"
        "void sub_10001620(void)\n"
        "{\n"
        "  Sleep(1000);\n"
        "}\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::string prompt =
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Likely DllMain: FUN_1000d02e @ 1000d02e\n"
        "===================== END GHIDRA DATA =========================\n";
    prompt += std::string(21000, 'F');

    std::vector<area::AgentMessage> msgs;
    agent.process(prompt, [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | decompile | 0x1000d02e"),
              ghidraPtr->actions.end());
    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | decompile | 0x10001656"),
              ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "done");
}

TEST(AgentPrompting, BenchStylePromptBootstrapsExplicitQuestionAddresses) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | function_at | 0x10001656"] =
        "=== Ghidra Function Lookup: sample.dll ===\n\n"
        "Requested address: 010001656\n"
        "Function: sub_10001620 @ 010001620\n"
        "Signature: void sub_10001620(void)\n"
        "Calling convention: __stdcall\n"
        "Size: 64 bytes\n"
        "Offset from entry: 54\n"
        "Callers: 3 | Callees: 2\n"
        "Thunk: no\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001656"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- sub_10001620 @ 010001620 (64 bytes) ---\n\n"
        "void sub_10001620(void)\n\n"
        "{\n"
        "  Sleep(1000);\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | disasm | 0x10001656"] =
        "=== Ghidra Disassembly: sample.dll ===\n\n"
        "Requested address: 010001656\n"
        "Function: sub_10001620 @ 010001620\n"
        "Offset from entry: 54\n"
        "Instructions shown: 1\n\n"
        "=> 010001656: CALL Sleep [CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | data_at | 0x1001d988"] =
        "=== Ghidra Data Lookup: sample.dll ===\n\n"
        "Requested address: 01001D988\n"
        "Data: 01001D980 .. 01001D99F\n"
        "Type: raw_bytes (32 bytes)\n"
        "Bytes: 3D 21 21 25 6F 7A 7A 36 67 7B 30 2D 34 38 25 39 30\n"
        "Likely single-byte XOR decode: key 0x55 -> \"http://c2.example\"\n"
        "Offset from start: 8\n"
        "References: 1\n"
        "Referenced by: sub_10001620 @ 010001656 [READ]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | 0x1001d988"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Requested address: 01001D988\n"
        "Data: 01001D980 .. 01001D99F\n"
        "Type: raw_bytes (32 bytes)\n"
        "References: 1\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions:\n"
        "1. What does the subroutine at 0x10001656 do?\n"
        "2. What is the data at 0x1001D988?\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Likely DllMain: FUN_1000d02e @ 1000d02e\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_GE(backendPtr->callCount(), 1);
    EXPECT_GE(ghidraPtr->actions.size(), 6u);
    EXPECT_EQ(ghidraPtr->actions[0], "GHIDRA: /tmp/sample.dll | function_at | 0x10001656");
    EXPECT_EQ(ghidraPtr->actions[1], "GHIDRA: /tmp/sample.dll | decompile | 0x10001656");
    EXPECT_EQ(ghidraPtr->actions[2], "GHIDRA: /tmp/sample.dll | disasm | 0x10001656");
    EXPECT_EQ(ghidraPtr->actions[3], "GHIDRA: /tmp/sample.dll | data_at | 0x1001d988");
    EXPECT_EQ(ghidraPtr->actions[4], "GHIDRA: /tmp/sample.dll | xrefs | 0x1001d988");
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "done");
}

TEST(AgentPrompting, BenchStylePromptBootstrapsHighSignalStrings) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponse("ANSWER: done");

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x1000d02e"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_1000d02e @ 1000d02e (32 bytes) ---\n\n"
        "void FUN_1000d02e(void) {}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | 0x100192ac"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Requested address: 0100192AC\n"
        "Data: 0100192AC .. 0100192B8\n"
        "Type: string (13 bytes)\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | cmd.exe"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Requested address: 010095B34\n"
        "Data: 010095B34 .. 010095B40\n"
        "Type: string (13 bytes)\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | PSLIST"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Function: PSLIST @ 10007025\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Likely DllMain: FUN_1000d02e @ 1000d02e\n"
        "--- strings ---\n"
        "  [10017ff9] \"PSLIST\" (xrefs: 1)\n"
        "  [100192ac] \"[This is CTI]30\" (xrefs: 1)\n"
        "  [100934b0] \"startxcmd\"\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_GE(backendPtr->callCount(), 1);
    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | 0x100192ac"),
              ghidraPtr->actions.end());
    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | cmd.exe"),
              ghidraPtr->actions.end());
    EXPECT_NE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                        "GHIDRA: /tmp/sample.dll | xrefs | PSLIST"),
              ghidraPtr->actions.end());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "done");
}

TEST(AgentPrompting, BootstrapEvidenceForcesAnswerRevision) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponses({
        "ANSWER: broad summary without exact evidence",
        "ANSWER: Import gethostbyname @ EXTERNAL:00000016. Functions calling: 1. "
        "Parameter count: 0. Sleep(iVar1 * 1000)."
    });

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: gethostbyname [WS2_32.DLL] @ EXTERNAL:00000016\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 100011af [COMPUTED_CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | Sleep"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 10001358 [COMPUTED_CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x100011af"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_10001074 @ 10001074 (32 bytes) ---\n\n"
        "undefined4 FUN_10001074(void)\n\n"
        "{\n"
        "  int iVar1;\n"
        "  Sleep(iVar1 * 1000);\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001358"] =
        ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x100011af"];
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- imports ---\n"
        "  gethostbyname [WS2_32.DLL] (ordinal 52) @ EXTERNAL:00000016\n"
        "  Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->callCount(), 2);
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content,
              "Import gethostbyname @ EXTERNAL:00000016. Functions calling: 1. "
              "Parameter count: 0. Sleep(iVar1 * 1000).");
}

TEST(AgentPrompting, BootstrapEvidenceCapturesCallerSummaries) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponses({
        "ANSWER: broad summary without exact evidence",
        "ANSWER: missing direct callees"
    });

    area::MockPromptEntry directCallees;
    directCallees.id = "caller-summary";
    directCallees.match = {
        "direct callees: socket @ EXTERNAL:00000017, connect @ EXTERNAL:00000004"
    };
    directCallees.response = "ANSWER: saw direct callees";
    backend->setPromptEntries({directCallees});

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | gethostbyname"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: gethostbyname [WS2_32.DLL] @ EXTERNAL:00000016\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 100011af [COMPUTED_CALL]\n"
        "\n--- Caller Functions (1) ---\n"
        "  FUN_10001074 @ 10001074 - undefined4 FUN_10001074(void)\n"
        "    callsites (1): 100011af\n"
        "    direct callees: socket @ EXTERNAL:00000017, connect @ EXTERNAL:00000004\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | Sleep"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 10001358 [COMPUTED_CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x100011af"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_10001074 @ 10001074 (32 bytes) ---\n\n"
        "undefined4 FUN_10001074(void)\n\n"
        "{\n"
        "  int iVar1;\n"
        "  Sleep(iVar1 * 1000);\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001358"] =
        ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x100011af"];
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- imports ---\n"
        "  gethostbyname [WS2_32.DLL] (ordinal 52) @ EXTERNAL:00000016\n"
        "  Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "caller-summary");
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "saw direct callees");
}

TEST(AgentPrompting, BootstrapEvidenceCapturesDisasmTargets) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponses({
        "ANSWER: broad summary without exact evidence",
        "ANSWER: missing disasm evidence"
    });

    area::MockPromptEntry disasmEvidence;
    disasmEvidence.id = "disasm-target";
    disasmEvidence.match = {
        "Target instruction: => 010001358: CALL Sleep [CALL]"
    };
    disasmEvidence.response = "ANSWER: saw disasm";
    backend->setPromptEntries({disasmEvidence});

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | Sleep"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Import: Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "Functions calling: 1 | Call sites: 1\n\n"
        "--- Callers (1) ---\n"
        "  FUN_10001074 @ 10001358 [COMPUTED_CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001358"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_10001074 @ 10001074 (32 bytes) ---\n\n"
        "undefined4 FUN_10001074(void)\n\n"
        "{\n"
        "  int iVar1;\n"
        "  Sleep(iVar1 * 1000);\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | disasm | 0x10001358"] =
        "=== Ghidra Disassembly: sample.dll ===\n\n"
        "Requested address: 010001358\n"
        "Function: FUN_10001074 @ 010001074\n"
        "Offset from entry: 52\n"
        "Instructions shown: 3\n\n"
        "   010001352: MOV ECX,dword ptr [EBP + 0x8] [FALL_THROUGH]\n"
        "=> 010001358: CALL Sleep [CALL]\n"
        "   01000135d: TEST EAX,EAX [FALL_THROUGH]\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions and malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- imports ---\n"
        "  Sleep [KERNEL32.DLL] @ EXTERNAL:00000078\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "disasm-target");
    EXPECT_TRUE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                          "GHIDRA: /tmp/sample.dll | disasm | 0x10001358")
                != ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "saw disasm");
}

TEST(AgentPrompting, BootstrapEvidenceCapturesLookupResults) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponses({
        "ANSWER: broad summary without exact evidence",
        "ANSWER: missing lookup evidence"
    });

    area::MockPromptEntry lookupEvidence;
    lookupEvidence.id = "lookup-evidence";
    lookupEvidence.match = {
        "Requested address: 010001656",
        "Function: sub_10001620 @ 010001620",
        "Likely single-byte XOR decode: key 0x55 -> \"http://c2.example\""
    };
    lookupEvidence.response = "ANSWER: saw lookup evidence";
    backend->setPromptEntries({lookupEvidence});

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | function_at | 0x10001656"] =
        "=== Ghidra Function Lookup: sample.dll ===\n\n"
        "Requested address: 010001656\n"
        "Function: sub_10001620 @ 010001620\n"
        "Signature: void sub_10001620(void)\n"
        "Calling convention: __stdcall\n"
        "Size: 64 bytes\n"
        "Offset from entry: 54\n"
        "Callers: 3 | Callees: 2\n"
        "Thunk: no\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001656"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- sub_10001620 @ 010001620 (64 bytes) ---\n\n"
        "void sub_10001620(void)\n\n"
        "{\n"
        "  Sleep(1000);\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | disasm | 0x10001656"] =
        "=== Ghidra Disassembly: sample.dll ===\n\n"
        "Requested address: 010001656\n"
        "Function: sub_10001620 @ 010001620\n"
        "Offset from entry: 54\n"
        "Instructions shown: 1\n\n"
        "=> 010001656: CALL Sleep [CALL]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | data_at | 0x1001d988"] =
        "=== Ghidra Data Lookup: sample.dll ===\n\n"
        "Requested address: 01001D988\n"
        "Data: 01001D980 .. 01001D99F\n"
        "Type: raw_bytes (32 bytes)\n"
        "Bytes: 3D 21 21 25 6F 7A 7A 36 67 7B 30 2D 34 38 25 39 30\n"
        "Likely single-byte XOR decode: key 0x55 -> \"http://c2.example\"\n"
        "Offset from start: 8\n"
        "References: 1\n"
        "Referenced by: sub_10001620 @ 010001656 [READ]\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | 0x1001d988"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Requested address: 01001D988\n"
        "Data: 01001D980 .. 01001D99F\n"
        "Type: raw_bytes (32 bytes)\n"
        "References: 1\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions:\n"
        "1. What does the subroutine at 0x10001656 do?\n"
        "2. What is the data at 0x1001D988?\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Likely DllMain: FUN_1000d02e @ 1000d02e\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "lookup-evidence");
    EXPECT_TRUE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                          "GHIDRA: /tmp/sample.dll | function_at | 0x10001656")
                != ghidraPtr->actions.end());
    EXPECT_TRUE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                          "GHIDRA: /tmp/sample.dll | data_at | 0x1001d988")
                != ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "saw lookup evidence");
}

TEST(AgentPrompting, BootstrapEvidenceCapturesRepeatingKeyXorDecode) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponses({
        "ANSWER: broad summary without exact evidence",
        "ANSWER: missing xor evidence"
    });

    area::MockPromptEntry xorEvidence;
    xorEvidence.id = "repeating-xor";
    xorEvidence.match = {
        "Likely repeating-key XOR decode: key 0x13 0x37 -> \"http://c2.example\""
    };
    xorEvidence.response = "ANSWER: saw repeating xor";
    backend->setPromptEntries({xorEvidence});

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | data_at | 0x1001d988"] =
        "=== Ghidra Data Lookup: sample.dll ===\n\n"
        "Requested address: 01001D988\n"
        "Data: 01001D988 .. 01001D998\n"
        "Type: raw_bytes (17 bytes)\n"
        "Bytes: 7B 43 67 47 29 18 3C 54 21 19 76 4F 72 5A 63 5B 76\n"
        "Likely repeating-key XOR decode: key 0x13 0x37 -> \"http://c2.example\"\n"
        "Offset from start: 0\n"
        "References: 0\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | 0x1001d988"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Requested address: 01001D988\n"
        "Data: 01001D988 .. 01001D998\n"
        "Type: raw_bytes (17 bytes)\n"
        "References: 0\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions:\n"
        "1. What is the data at 0x1001D988?\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Likely DllMain: FUN_1000d02e @ 1000d02e\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "repeating-xor");
    EXPECT_TRUE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                          "GHIDRA: /tmp/sample.dll | data_at | 0x1001d988")
                != ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "saw repeating xor");
}

TEST(AgentPrompting, BootstrapEvidenceCapturesStackStrings) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponses({
        "ANSWER: broad summary without exact evidence",
        "ANSWER: missing stack string"
    });

    area::MockPromptEntry stackStringEvidence;
    stackStringEvidence.id = "stack-string";
    stackStringEvidence.match = {"Likely stack string: \"cmd.exe\""};
    stackStringEvidence.response = "ANSWER: saw stack string";
    backend->setPromptEntries({stackStringEvidence});

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | function_at | 0x10001656"] =
        "=== Ghidra Function Lookup: sample.dll ===\n\n"
        "Requested address: 010001656\n"
        "Function: sub_10001620 @ 010001620\n"
        "Signature: void sub_10001620(void)\n"
        "Calling convention: __stdcall\n"
        "Size: 64 bytes\n"
        "Offset from entry: 54\n"
        "Callers: 3 | Callees: 2\n"
        "Thunk: no\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x10001656"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- sub_10001620 @ 010001620 (64 bytes) ---\n"
        "Likely stack string: \"cmd.exe\"\n\n"
        "void sub_10001620(void)\n\n"
        "{\n"
        "  undefined8 local_10;\n"
        "  local_10._0_4_ = 0x2e646d63;\n"
        "  local_10._4_4_ = 0x657865;\n"
        "}\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | disasm | 0x10001656"] =
        "=== Ghidra Disassembly: sample.dll ===\n\n"
        "Requested address: 010001656\n"
        "Function: sub_10001620 @ 010001620\n"
        "Offset from entry: 54\n"
        "Instructions shown: 1\n\n"
        "=> 010001656: MOV EAX,0x2E646D63 [FALL_THROUGH]\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions:\n"
        "1. What does the subroutine at 0x10001656 do?\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- overview ---\n"
        "Likely DllMain: FUN_1000d02e @ 1000d02e\n"
        "===================== END GHIDRA DATA =========================\n",
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "stack-string");
    EXPECT_TRUE(std::find(ghidraPtr->actions.begin(), ghidraPtr->actions.end(),
                          "GHIDRA: /tmp/sample.dll | decompile | 0x10001656")
                != ghidraPtr->actions.end());
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "saw stack string");
}

TEST(AgentPrompting, BootstrapEvidenceCapturesCommandShellInsights) {
    area::AiEndpoint ep{"test", "mock", "", "auto"};
    auto backend = std::make_unique<area::MockBackend>(ep);
    auto* backendPtr = backend.get();
    backend->setResponses({
        "ANSWER: broad summary without exact evidence",
        "ANSWER: missing command-shell evidence"
    });

    area::MockPromptEntry commandShellEvidence;
    commandShellEvidence.id = "command-shell-evidence";
    commandShellEvidence.match = {
        "Likely command shell launcher: CreatePipe + CreateProcessA via \"\\\\cmd.exe /c \"",
        "Likely command dispatcher: robotwork, language",
        "Default injection target: iexplore.exe"
    };
    commandShellEvidence.response = "ANSWER: saw command shell evidence";
    backend->setPromptEntries({commandShellEvidence});

    area::ToolRegistry tools;
    auto ghidraTool = std::make_unique<FakeGhidraActionTool>();
    auto* ghidraPtr = ghidraTool.get();
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | xrefs | cmd.exe"] =
        "=== Ghidra Cross-References: sample.dll ===\n\n"
        "Data: 010095B34 .. 010095B40\n"
        "Type: string (13 bytes)\n"
        "Value: \"\\\\cmd.exe /c \"\n\n"
        "--- Referencing Functions (1) ---\n"
        "  FUN_1000ff58 @ 1000ff58 - undefined4 FUN_1000ff58(char * param_1)\n";
    ghidraPtr->responses["GHIDRA: /tmp/sample.dll | decompile | 0x1000ff58"] =
        "=== Ghidra Decompilation: sample.dll ===\n\n"
        "--- FUN_1000ff58 @ 1000ff58 (64 bytes) ---\n"
        "Likely command shell launcher: CreatePipe + CreateProcessA via \"\\\\cmd.exe /c \"\n"
        "Likely command dispatcher: robotwork, language\n"
        "Default injection target: iexplore.exe\n\n"
        "undefined4 FUN_1000ff58(char * param_1)\n"
        "{\n"
        "  CreatePipe((PHANDLE)&stack0xfffffff0,(PHANDLE)&stack0xffffffec,\n"
        "             (LPSECURITY_ATTRIBUTES)&stack0xffffffcc,0);\n"
        "  CreateProcessA((LPCSTR)0x0,&local_ac4,(LPSECURITY_ATTRIBUTES)0x0,\n"
        "                 (LPSECURITY_ATTRIBUTES)0x0,1,0,(LPVOID)0x0,(LPCSTR)0x0,\n"
        "                 (LPSTARTUPINFOA)&local_78,lpProcessInformation);\n"
        "}\n";
    tools.add(std::move(ghidraTool));

    area::Agent agent(std::move(backend), tools);
    std::vector<area::AgentMessage> msgs;
    agent.process(
        "Analyze /tmp/sample.dll.\n\n"
        "Questions: interesting functions, suspicious strings, malware behavior.\n"
        "========================= GHIDRA DATA =========================\n"
        "========== GHIDRA: /tmp/sample.dll ==========\n"
        "--- strings ---\n"
        "  [100934b0] \"startxcmd\"\n"
        "===================== END GHIDRA DATA =========================\n"
        + std::string(21000, 'D'),
        [&](const area::AgentMessage& msg) { msgs.push_back(msg); });

    EXPECT_EQ(backendPtr->lastMatchedId(), "command-shell-evidence");
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().type, area::AgentMessage::ANSWER);
    EXPECT_EQ(msgs.back().content, "saw command shell evidence");
}

// ---------------------------------------------------------------------------
// IPC tests
// ---------------------------------------------------------------------------

class IPCE2E : public ::testing::Test {
protected:
    std::string sockPath_;

    void SetUp() override {
        sockPath_ = "/tmp/area_test_" + std::to_string(getpid()) + ".sock";
        area::ipc::removeSock(sockPath_);
    }

    void TearDown() override {
        area::ipc::removeSock(sockPath_);
    }
};

TEST_F(IPCE2E, ListenAndConnect) {
    int listenFd = area::ipc::createListener(sockPath_);
    ASSERT_GE(listenFd, 0);

    int clientFd = area::ipc::connectTo(sockPath_);
    ASSERT_GE(clientFd, 0);

    area::ipc::closeFd(clientFd);
    area::ipc::closeFd(listenFd);
}

TEST_F(IPCE2E, SendAndReceive) {
    int listenFd = area::ipc::createListener(sockPath_);
    ASSERT_GE(listenFd, 0);

    int clientFd = area::ipc::connectTo(sockPath_);
    ASSERT_GE(clientFd, 0);

    int serverFd = accept(listenFd, nullptr, nullptr);
    ASSERT_GE(serverFd, 0);

    // Client sends, server receives
    nlohmann::json msg = {{"type", "test"}, {"value", 42}};
    EXPECT_TRUE(area::ipc::sendLine(clientFd, msg));

    // Small delay for data to arrive
    usleep(10000);

    auto received = area::ipc::readLine(serverFd);
    ASSERT_TRUE(received.has_value());
    EXPECT_EQ(received->value("type", ""), "test");
    EXPECT_EQ(received->value("value", 0), 42);

    area::ipc::closeFd(serverFd);
    area::ipc::closeFd(clientFd);
    area::ipc::closeFd(listenFd);
}

TEST_F(IPCE2E, MultipleMessages) {
    int listenFd = area::ipc::createListener(sockPath_);
    int clientFd = area::ipc::connectTo(sockPath_);
    int serverFd = accept(listenFd, nullptr, nullptr);

    for (int i = 0; i < 10; i++) {
        EXPECT_TRUE(area::ipc::sendLine(clientFd, {{"i", i}}));
    }

    usleep(10000);

    for (int i = 0; i < 10; i++) {
        auto msg = area::ipc::readLine(serverFd);
        ASSERT_TRUE(msg.has_value());
        EXPECT_EQ(msg->value("i", -1), i);
    }

    area::ipc::closeFd(serverFd);
    area::ipc::closeFd(clientFd);
    area::ipc::closeFd(listenFd);
}

TEST_F(IPCE2E, ConnectToNonexistent) {
    int fd = area::ipc::connectTo("/tmp/nonexistent_area_test.sock");
    EXPECT_LT(fd, 0);
}

// ---------------------------------------------------------------------------
// Server E2E tests (full round-trip: server + IPC + agent)
// ---------------------------------------------------------------------------

class ServerE2E : public ::testing::Test {
protected:
    std::string dataDir_;
    std::unique_ptr<area::AreaServer> server_;
    std::thread serverThread_;

    void SetUp() override {
        dataDir_ = "/tmp/area_e2e_" + std::to_string(getpid());
        fs::create_directories(dataDir_);

        // Write minimal config
        nlohmann::json cfg;
        cfg["postgres_url"] = "";
        cfg["postgres_cert"] = "";
        cfg["ai_endpoints"] = nlohmann::json::array({
            {{"id", "mock"}, {"provider", "mock"}, {"url", ""}, {"model", "auto"}}
        });
        cfg["theme"] = "dark";
        std::ofstream(dataDir_ + "/config.json") << cfg.dump(2);

        // Write ddl.sql (empty, no DB)
        std::ofstream(dataDir_ + "/ddl.sql") << "";

        area::Config config;
        config.ai_endpoints.push_back({"mock", "mock", "", "auto"});
        config.theme = "dark";

        server_ = std::make_unique<area::AreaServer>(std::move(config), dataDir_);
    }

    void TearDown() override {
        server_->shutdown();
        if (serverThread_.joinable()) serverThread_.join();
        fs::remove_all(dataDir_);
    }

    void startServer() {
        serverThread_ = std::thread([this]() { server_->run(); });
        // Wait for socket
        for (int i = 0; i < 50; i++) {
            if (fs::exists(dataDir_ + "/area.sock")) break;
            usleep(50000);
        }
    }

    std::string sockPath() { return dataDir_ + "/area.sock"; }

    // Send a message and collect responses until "done" state
    std::vector<nlohmann::json> roundTrip(int fd, const std::string& query,
                                           const std::string& chatId = "default",
                                           int timeoutMs = 5000) {
        area::ipc::sendLine(fd, {{"type", "user_input"}, {"chat_id", chatId}, {"content", query}});

        std::vector<nlohmann::json> responses;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
        while (std::chrono::steady_clock::now() < deadline) {
            struct pollfd pfd = {fd, POLLIN, 0};
            int remaining = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) break;
            if (poll(&pfd, 1, std::min(remaining, 100)) > 0) {
                while (auto msg = area::ipc::readLine(fd)) {
                    responses.push_back(*msg);
                    if (msg->value("type", "") == "state" && !msg->value("processing", true)) {
                        return responses;
                    }
                }
            }
        }
        return responses;
    }
};

TEST_F(ServerE2E, StartAndStop) {
    startServer();
    EXPECT_TRUE(fs::exists(sockPath()));
    server_->shutdown();
    serverThread_.join();
    // Socket should be cleaned up
    usleep(200000);
}

TEST_F(ServerE2E, ConnectAndAttach) {
    startServer();
    int fd = area::ipc::connectTo(sockPath());
    ASSERT_GE(fd, 0);

    area::ipc::sendLine(fd, {{"type", "attach"}, {"chat_id", "default"}});

    // Wait for responses with poll
    bool gotHistory = false, gotState = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd pfd = {fd, POLLIN, 0};
        if (poll(&pfd, 1, 200) > 0) {
            while (auto msg = area::ipc::readLine(fd)) {
                if (msg->value("type", "") == "history") gotHistory = true;
                if (msg->value("type", "") == "state") gotState = true;
            }
            if (gotHistory && gotState) break;
        }
    }
    EXPECT_TRUE(gotHistory);
    EXPECT_TRUE(gotState);

    area::ipc::closeFd(fd);
}

TEST_F(ServerE2E, SendQueryGetAnswer) {
    startServer();
    int fd = area::ipc::connectTo(sockPath());
    ASSERT_GE(fd, 0);

    // Attach and drain
    area::ipc::sendLine(fd, {{"type", "attach"}, {"chat_id", "default"}});
    { struct pollfd p = {fd, POLLIN, 0}; poll(&p, 1, 500); }
    while (area::ipc::readLine(fd)) {}

    auto responses = roundTrip(fd, "hello");

    bool gotAnswer = false;
    for (auto& r : responses) {
        if (r.value("type", "") == "agent_msg") {
            if (r["msg"].value("type", "") == "answer") {
                gotAnswer = true;
                EXPECT_FALSE(r["msg"].value("content", "").empty());
            }
        }
    }
    EXPECT_TRUE(gotAnswer);

    area::ipc::closeFd(fd);
}

TEST_F(ServerE2E, ListChats) {
    startServer();
    int fd = area::ipc::connectTo(sockPath());
    ASSERT_GE(fd, 0);

    area::ipc::sendLine(fd, {{"type", "list_chats"}});
    struct pollfd p = {fd, POLLIN, 0}; poll(&p, 1, 1000);

    auto msg = area::ipc::readLine(fd);
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->value("type", ""), "chat_list");
    auto chats = (*msg)["chats"];
    EXPECT_GE(chats.size(), 1);

    area::ipc::closeFd(fd);
}

TEST_F(ServerE2E, CreateAndAttachChat) {
    startServer();
    int fd = area::ipc::connectTo(sockPath());
    ASSERT_GE(fd, 0);

    area::ipc::sendLine(fd, {{"type", "create_chat"}, {"name", "test chat"}});
    { struct pollfd p = {fd, POLLIN, 0}; poll(&p, 1, 1000); }

    auto created = area::ipc::readLine(fd);
    ASSERT_TRUE(created.has_value());
    EXPECT_EQ(created->value("type", ""), "chat_created");
    std::string chatId = created->value("chat_id", "");
    EXPECT_FALSE(chatId.empty());

    area::ipc::sendLine(fd, {{"type", "attach"}, {"chat_id", chatId}});

    bool gotHistory = false;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        struct pollfd p = {fd, POLLIN, 0};
        if (poll(&p, 1, 200) > 0) {
            while (auto msg = area::ipc::readLine(fd)) {
                if (msg->value("type", "") == "history") {
                    gotHistory = true;
                    EXPECT_EQ((*msg)["messages"].size(), 0);
                }
            }
            if (gotHistory) break;
        }
    }
    EXPECT_TRUE(gotHistory);

    area::ipc::closeFd(fd);
}

TEST_F(ServerE2E, DangerousMode) {
    startServer();
    int fd = area::ipc::connectTo(sockPath());
    ASSERT_GE(fd, 0);

    area::ipc::sendLine(fd, {{"type", "attach"}, {"chat_id", "default"}});
    area::ipc::sendLine(fd, {{"type", "set_dangerous"}, {"chat_id", "default"}, {"enabled", true}});
    { struct pollfd p = {fd, POLLIN, 0}; poll(&p, 1, 500); }
    while (area::ipc::readLine(fd)) {}

    // With dangerous mode, tool calls should auto-execute (no confirm_req)
    auto responses = roundTrip(fd, "generate a run_id for me");

    bool gotConfirm = false;
    for (auto& r : responses) {
        if (r.value("type", "") == "confirm_req") gotConfirm = true;
    }
    EXPECT_FALSE(gotConfirm); // should not get confirm in dangerous mode

    area::ipc::closeFd(fd);
}

TEST_F(ServerE2E, SessionPersistsAfterDisconnect) {
    startServer();

    // First connection: send a query
    {
        int fd = area::ipc::connectTo(sockPath());
        ASSERT_GE(fd, 0);
        area::ipc::sendLine(fd, {{"type", "attach"}, {"chat_id", "default"}});
        { struct pollfd p = {fd, POLLIN, 0}; poll(&p, 1, 500); }
        while (area::ipc::readLine(fd)) {}

        auto responses = roundTrip(fd, "hello from first session");
        area::ipc::closeFd(fd);
    }

    usleep(500000);

    // Second connection: should see history
    {
        int fd = area::ipc::connectTo(sockPath());
        ASSERT_GE(fd, 0);
        area::ipc::sendLine(fd, {{"type", "attach"}, {"chat_id", "default"}});

        bool gotHistoryWithContent = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            struct pollfd p = {fd, POLLIN, 0};
            if (poll(&p, 1, 200) > 0) {
                while (auto msg = area::ipc::readLine(fd)) {
                    if (msg->value("type", "") == "history") {
                        if ((*msg)["messages"].size() >= 2) gotHistoryWithContent = true;
                    }
                }
                if (gotHistoryWithContent) break;
            }
        }
        EXPECT_TRUE(gotHistoryWithContent);

        area::ipc::closeFd(fd);
    }
}

TEST_F(ServerE2E, ShutdownViaSocket) {
    startServer();
    int fd = area::ipc::connectTo(sockPath());
    ASSERT_GE(fd, 0);

    area::ipc::sendLine(fd, {{"type", "shutdown"}});
    usleep(200000); // let server process before closing
    area::ipc::closeFd(fd);

    serverThread_.join();
    // Server should have exited
}
