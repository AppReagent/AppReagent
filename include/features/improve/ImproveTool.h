#pragma once

#include <functional>
#include <optional>
#include <string>

#include "infra/tools/Tool.h"
#include "infra/config/Config.h"
#include "infra/db/Database.h"
#include <nlohmann/json.hpp>

namespace area {
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
    struct CmdResult { std::string output; int exitCode; };
    static CmdResult exec(const std::string& cmd);

    int runAgentLocal(const std::string& prompt, std::function<void(const std::string&)> onLine);

    int runAgentDocker(const std::string& prompt, bool headful,
                       std::function<void(const std::string&)> onLine);

    struct EvalResult {
        double score = -1;
        std::string breakdown;
        std::string failReason;
        int llmCalls = 0;
    };
    EvalResult evaluate();

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

    bool agentAvailable();

    int runClaude(const std::string& prompt, std::function<void(const std::string&)> onLine);

    std::string agentName() const;
    std::string improveMode() const;

    void gitCommit(const std::string& msg);
    void gitRevert();

    Config* config_;
    Database& db_;
    std::string repoDir_;
    std::string corpusDir_;
    std::string labelsPath_;
};
}  // namespace area
