#pragma once

#include "infra/tools/Tool.h"
#include "infra/config/Config.h"
#include "infra/db/Database.h"

#include <nlohmann/json.hpp>

namespace area {

// IMPROVE tool: launches Claude Code to modify this codebase, then evaluates
// the changes against the autoresearch corpus. Streams Claude's output to the TUI.
class ImproveTool : public Tool {
public:
    ImproveTool(Config* config, Database& db, const std::string& repoDir);

    std::string name() const override { return "IMPROVE"; }
    std::string description() const override {
        return "<task> — evaluate or improve the scan pipeline. "
               "Use 'IMPROVE: evaluate' to score the corpus (no external tools needed). "
               "Use 'IMPROVE: <task>' for full improvement cycle (evaluate → Claude Code → rebuild → re-evaluate). "
               "Example: IMPROVE: evaluate | IMPROVE: improve triage accuracy for crypto mining detection";
    }
    std::optional<ToolResult> tryExecute(const std::string& action, ToolContext& ctx) override;

private:
    // Run a shell command, return {output, exitCode}
    struct CmdResult { std::string output; int exitCode; };
    static CmdResult exec(const std::string& cmd);

    // Launch a coding agent locally via fork+pipe (headless). Returns exit code.
    int runAgentLocal(const std::string& prompt, std::function<void(const std::string&)> onLine);

    // Launch a coding agent in Docker. headful=true allocates a TTY. Returns exit code.
    int runAgentDocker(const std::string& prompt, bool headful,
                       std::function<void(const std::string&)> onLine);

    // Evaluate current prompts against the corpus. Returns score 0-100 or negative on failure.
    struct EvalResult {
        double score = -1;
        std::string breakdown;
        std::string failReason;
        int llmCalls = 0;
    };
    EvalResult evaluate();

    // Score one file's result against its label
    struct FileScore {
        double classification = 0;
        double calibration = 0;
        double evidence = 0;
        double total = 0;
        std::string detail;
    };
    FileScore scoreFile(const std::string& key, const nlohmann::json& label,
                        const std::string& relevance, int riskScore,
                        const std::string& profileJson);

    // Check if a coding agent CLI is available on PATH
    bool agentAvailable();

    // Run the coding agent (dispatches to runAgentLocal or runAgentDocker based on mode)
    int runClaude(const std::string& prompt, std::function<void(const std::string&)> onLine);

    // Resolve which agent to use and which mode (local/docker/docker-headful)
    std::string agentName() const;
    std::string improveMode() const;

    // Git helpers
    void gitCommit(const std::string& msg);
    void gitRevert();

    Config* config_;
    Database& db_;
    std::string repoDir_;
    std::string corpusDir_;
    std::string labelsPath_;
};

} // namespace area
