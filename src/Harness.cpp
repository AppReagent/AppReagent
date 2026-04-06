#include "Harness.h"

#include <algorithm>
#include <fstream>
#include <sstream>

#include "util/file_io.h"

namespace area {

std::string Harness::guideText() const {
    if (guides_.empty()) return "";
    std::ostringstream out;
    for (auto& g : guides_) {
        out << g.content << "\n\n";
    }
    return out.str();
}

std::string Harness::runSensors(const std::string& trigger,
                                 const std::string& action,
                                 const std::string& observation) const {
    std::ostringstream feedback;
    for (auto& s : sensors_) {
        if (s.trigger != trigger) continue;
        std::string result = s.check(action, observation);
        if (!result.empty()) {
            feedback << "[" << s.name << "] " << result << "\n";
        }
    }
    return feedback.str();
}

void Harness::loadConstitution(const std::string& path) {
    std::string content = util::readFile(path);
    if (content.empty()) return;
    guides_.insert(guides_.begin(), {"constitution", content});
}

Harness Harness::createDefault() {
    Harness h;

    h.addGuide({"agent_loop",
        "You are a ReAct agent that works autonomously to answer questions about "
        "Android applications. You persist until the question is fully answered.\n"
        "\n"
        "FORMAT — every response must follow this structure:\n"
        "\n"
        "THOUGHT: <your reasoning — what you know, what you need, your plan>\n"
        "ACTION: <tool call>\n"
        "\n"
        "Or when done:\n"
        "\n"
        "THOUGHT: <why you can answer now, summarize evidence>\n"
        "ANSWER: <complete answer with evidence>\n"
        "\n"
        "PHASES — work through these in order (BMAD cycle):\n"
        "1. ANALYZE: Understand the question. What files, data, or context do you need?\n"
        "2. PLAN: Decide which tools to use and in what order. State your plan in THOUGHT.\n"
        "3. EXECUTE: Run scans, queries, or shell commands. One tool per turn.\n"
        "4. SYNTHESIZE: When you have enough data, combine findings into a complete answer.\n"
        "\n"
        "PERSISTENCE — don't stop prematurely:\n"
        "- After a scan, query the database to examine the actual findings\n"
        "- After a query, consider whether you need more data or a different angle\n"
        "- Cross-reference across multiple sources before concluding\n"
        "- Only ANSWER when you have concrete evidence, not just a single tool result\n"
    });

    h.addGuide({"error_recovery",
        "When a tool returns an error:\n"
        "1. Diagnose WHY it failed in your THOUGHT\n"
        "2. Fix the root cause, don't retry the same action\n"
        "3. SQL errors: check the error message, fix syntax, verify table/column names\n"
        "4. Scan errors: verify path exists and contains .smali files\n"
        "5. Shell errors: check exit code and stderr, fix the command\n"
    });

    h.addGuide({"improve_tool",
        "IMPROVE tool — use this whenever the user asks to improve, optimize, evaluate, "
        "or self-improve the pipeline, prompts, or codebase.\n"
        "Do NOT use SHELL to run improve commands. Use IMPROVE directly.\n"
        "\n"
        "Modes:\n"
        "- IMPROVE: evaluate — run the corpus evaluation and report the current score\n"
        "- IMPROVE: <task description> — run the full improvement cycle "
        "(evaluate → Claude Code → rebuild → re-evaluate → commit/revert)\n"
        "\n"
        "Examples:\n"
        "- User: \"evaluate the corpus\" → IMPROVE: evaluate\n"
        "- User: \"run the improve tool\" → IMPROVE: evaluate\n"
        "- User: \"improve triage accuracy\" → IMPROVE: improve triage accuracy for crypto mining\n"
    });

    h.addSensor({"sql_read_only", "sql",
        [](const std::string& action, const std::string&) -> std::string {
            std::string upper;
            for (size_t i = 0; i < std::min(action.size(), (size_t)20); i++)
                upper += std::toupper(action[i]);
            if (upper.find("DROP") != std::string::npos ||
                upper.find("TRUNCATE") != std::string::npos ||
                upper.find("ALTER") != std::string::npos) {
                return "BLOCKED: destructive SQL is not allowed.";
            }
            return "";
        }
    });

    h.addSensor({"sql_error_hint", "sql",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("ERROR:") == std::string::npos) return "";
            if (observation.find("does not exist") != std::string::npos) {
                return "HINT: Table or column not found. Try: SELECT table_name FROM information_schema.tables WHERE table_schema='public'";
            }
            if (observation.find("syntax error") != std::string::npos) {
                return "HINT: SQL syntax error. Check quotes, parentheses, keywords.";
            }
            return "";
        }
    });

    h.addSensor({"scan_quality", "scan",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("Total files: 0") != std::string::npos ||
                observation.find("No .smali files") != std::string::npos) {
                return "WARNING: No files found. Check path.";
            }
            return "";
        }
    });

    h.addSensor({"shell_error", "shell",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("exit code: 0") != std::string::npos) return "";
            if (observation.find("Sandbox not available") != std::string::npos) {
                return "WARNING: Docker sandbox not available.";
            }
            if (observation.find("exit code: 137") != std::string::npos) {
                return "WARNING: OOM killed. Use less memory.";
            }
            if (observation.find("exit code: 124") != std::string::npos) {
                return "WARNING: Timed out.";
            }
            return "";
        }
    });

    return h;
}

} // namespace area
