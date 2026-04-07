#include "features/improve/ImproveTool.h"
#include "infra/tools/ToolContext.h"
#include "infra/agent/Agent.h"
#include "infra/agent/Harness.h"
#include "features/scan/ScanCommand.h"
#include "features/scan/ScanLog.h"
#include "util/string_util.h"

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <iostream>
#include <signal.h>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace area {

// Alias for brevity — escapes single quotes for use inside shell strings.
static inline std::string escapeShell(const std::string& s) {
    return util::shellEscape(s);
}

ImproveTool::ImproveTool(Config* config, Database& db, const std::string& repoDir)
    : config_(config), db_(db), repoDir_(repoDir) {
    if (auto env = std::getenv("AREA_CORPUS_DIR")) {
        corpusDir_ = env;
    } else {
        corpusDir_ = repoDir_ + "/autoresearch/corpus";
    }
    labelsPath_ = corpusDir_ + "/labels.json";
}

ImproveTool::CmdResult ImproveTool::exec(const std::string& cmd) {
    std::string result;
    FILE* pipe = popen((cmd + " 2>&1").c_str(), "r");
    if (!pipe) return {"popen failed", -1};
    // RAII guard to ensure pclose is called even if an exception occurs
    auto pcloseDeleter = [](FILE* f) { return pclose(f); };
    std::unique_ptr<FILE, decltype(pcloseDeleter)> pipeGuard(pipe, pcloseDeleter);
    std::array<char, 4096> buf;
    while (fgets(buf.data(), buf.size(), pipeGuard.get())) {
        result += buf.data();
    }
    int status = pclose(pipeGuard.release());
    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    while (!result.empty() && result.back() == '\n') result.pop_back();
    return {result, exitCode};
}

std::string ImproveTool::agentName() const {
    const char* env = std::getenv("AGENT");
    return env ? env : "claude";
}

std::string ImproveTool::improveMode() const {
    const char* env = std::getenv("IMPROVE_MODE");
    return env ? env : "local";
}

// Launch a coding agent locally via fork+pipe (headless). Returns exit code.
int ImproveTool::runAgentLocal(const std::string& prompt,
                               std::function<void(const std::string&)> onLine) {
    std::string promptFile = "/tmp/area-improve-prompt-" + std::to_string(getpid()) + ".md";
    {
        std::ofstream f(promptFile);
        f << prompt;
    }

    int outPipe[2];
    if (pipe(outPipe) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(outPipe[0]);
        close(outPipe[1]);
        return -1;
    }

    if (pid == 0) {
        close(outPipe[0]);
        dup2(outPipe[1], STDOUT_FILENO);
        dup2(outPipe[1], STDERR_FILENO);
        close(outPipe[1]);
        if (chdir(repoDir_.c_str()) != 0) _exit(1);

        std::string agent = agentName();
        if (agent == "claude") {
            execlp("claude", "claude", "-p", promptFile.c_str(),
                   "--dangerously-skip-permissions", nullptr);
        } else if (agent == "codex") {
            execlp("codex", "codex", "-q", promptFile.c_str(),
                   "--full-auto", nullptr);
        }
        _exit(127);
    }

    close(outPipe[1]);
    FILE* fp = fdopen(outPipe[0], "r");
    if (fp) {
        std::array<char, 4096> buf;
        while (fgets(buf.data(), buf.size(), fp)) {
            std::string line(buf.data());
            while (!line.empty() && line.back() == '\n') line.pop_back();
            if (!line.empty() && onLine) onLine(line);
        }
        fclose(fp);
    } else {
        close(outPipe[0]);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    std::remove(promptFile.c_str());
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Launch a coding agent in a Docker container. Returns exit code.
int ImproveTool::runAgentDocker(const std::string& prompt, bool headful,
                                std::function<void(const std::string&)> onLine) {
    std::string agent = agentName();
    std::string image = "area-improve-" + agent;

    // Write prompt to workspace so the container can read it
    std::string promptFile = repoDir_ + "/.task.md";
    {
        std::ofstream f(promptFile);
        f << prompt;
    }

    // Build image if needed
    std::string buildCmd = "sudo docker build -f '" + escapeShell(repoDir_) + "/Dockerfile.improve'"
        + " -t '" + escapeShell(image) + "'"
        + " --build-arg AGENT='" + escapeShell(agent) + "'"
        + " -q '" + escapeShell(repoDir_) + "'";
    auto buildResult = exec(buildCmd);
    if (buildResult.exitCode != 0) {
        if (onLine) onLine("Docker build failed: " + buildResult.output);
        std::remove(promptFile.c_str());
        return -1;
    }

    // Launch container
    std::ostringstream runCmd;
    // Truncate and escape prompt for use as env var
    std::string taskSnippet = escapeShell(prompt.substr(0, 200));

    if (headful) {
        // Detached with TTY — user can docker attach to watch
        runCmd << "sudo docker run -dt --rm"
               << " --network host"
               << " -v '" << escapeShell(repoDir_) << ":/workspace'"
               << " -e AGENT='" << escapeShell(agent) << "'"
               << " -e AGENT_MODE=interactive"
               << " -e TASK='" << taskSnippet << "'"
               << " -e ANTHROPIC_API_KEY -e OPENAI_API_KEY"
               << " '" << escapeShell(image) << "'";
    } else {
        // Headless — capture output directly
        runCmd << "sudo docker run --rm"
               << " --network host"
               << " -v '" << escapeShell(repoDir_) << ":/workspace'"
               << " -e AGENT='" << escapeShell(agent) << "'"
               << " -e AGENT_MODE=headless"
               << " -e TASK='" << taskSnippet << "'"
               << " -e ANTHROPIC_API_KEY -e OPENAI_API_KEY"
               << " '" << escapeShell(image) << "'";
    }

    if (headful) {
        // Launch detached, report container ID, then follow logs
        auto startResult = exec(runCmd.str());
        if (startResult.exitCode != 0) {
            if (onLine) onLine("Docker run failed: " + startResult.output);
            std::remove(promptFile.c_str());
            return -1;
        }
        std::string containerId = startResult.output;

        if (onLine) onLine("Agent running in container: " + containerId);
        if (onLine) onLine("Attach with: sudo docker attach " + containerId);

        // Follow logs until container exits
        std::string logsCmd = "sudo docker logs --follow '" + escapeShell(containerId) + "' 2>&1";
        FILE* logFp = popen(logsCmd.c_str(), "r");
        if (logFp) {
            std::array<char, 4096> buf;
            while (fgets(buf.data(), buf.size(), logFp)) {
                std::string line(buf.data());
                while (!line.empty() && line.back() == '\n') line.pop_back();
                if (!line.empty() && onLine) onLine(line);
            }
            pclose(logFp);
        }

        auto waitResult = exec("sudo docker wait '" + escapeShell(containerId) + "' 2>/dev/null");
        std::remove(promptFile.c_str());
        try { return std::stoi(waitResult.output); } catch (...) { return -1; }
    } else {
        // Headless — run synchronously and stream output
        FILE* fp = popen((runCmd.str() + " 2>&1").c_str(), "r");
        if (!fp) {
            std::remove(promptFile.c_str());
            return -1;
        }
        std::array<char, 4096> buf;
        while (fgets(buf.data(), buf.size(), fp)) {
            std::string line(buf.data());
            while (!line.empty() && line.back() == '\n') line.pop_back();
            if (!line.empty() && onLine) onLine(line);
        }
        int status = pclose(fp);
        std::remove(promptFile.c_str());
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
}

ImproveTool::FileScore ImproveTool::scoreFile(
    const std::string& key, const nlohmann::json& label,
    const std::string& relevance, int riskScore,
    const std::string& profileJson) {

    FileScore fs;
    std::string expectedClass = label.value("expected_class", "");
    int minScore = label.value("min_risk_score", 0);
    int maxScore = label.value("max_risk_score", 100);

    // Classification (0 or 1)
    if (expectedClass == "relevant") {
        fs.classification = (relevance == "relevant") ? 1.0 : 0.0;
    } else if (expectedClass == "not_relevant") {
        fs.classification = (relevance == "not_relevant") ? 1.0 : 0.0;
    } else if (expectedClass == "partially_relevant") {
        fs.classification = (relevance == "relevant" || relevance == "partially_relevant") ? 1.0 : 0.0;
    }

    // Calibration (0.0 to 1.0)
    if (expectedClass == "relevant") {
        fs.calibration = (riskScore >= minScore) ? 1.0 : static_cast<double>(riskScore) / minScore;
    } else if (expectedClass == "not_relevant") {
        fs.calibration = (riskScore <= maxScore) ? 1.0
            : (riskScore > 0) ? static_cast<double>(maxScore) / riskScore : 1.0;
    } else {
        if (riskScore >= minScore && riskScore <= maxScore) {
            fs.calibration = 1.0;
        } else if (riskScore < minScore) {
            fs.calibration = (minScore > 0) ? static_cast<double>(riskScore) / minScore : 0.0;
        } else {
            int over = riskScore - maxScore;
            int range = 100 - maxScore;
            fs.calibration = (range > 0) ? std::max(0.0, 1.0 - static_cast<double>(over) / range) : 0.0;
        }
    }

    // Evidence quality
    std::string profileLower = profileJson;
    std::transform(profileLower.begin(), profileLower.end(), profileLower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    int hits = 0, total = 0;
    if (label.contains("must_mention")) {
        for (auto& kw : label["must_mention"]) {
            total++;
            if (profileLower.find(kw.get<std::string>()) != std::string::npos)
                hits++;
        }
    }
    fs.evidence = (total > 0) ? static_cast<double>(hits) / total : 1.0;

    if (label.contains("must_not_mention")) {
        int violations = 0;
        for (auto& kw : label["must_not_mention"]) {
            if (profileLower.find(kw.get<std::string>()) != std::string::npos)
                violations++;
        }
        if (violations > 0)
            fs.evidence = std::max(0.0, fs.evidence - violations * 0.25);
    }

    fs.total = 0.50 * fs.classification + 0.30 * fs.calibration + 0.20 * fs.evidence;

    std::ostringstream det;
    det << key << ": class=" << fs.classification
        << " cal=" << std::fixed << std::setprecision(2) << fs.calibration
        << " ev=" << fs.evidence
        << " -> " << fs.total
        << " (rel=" << relevance << " score=" << riskScore << ")";
    fs.detail = det.str();

    return fs;
}

ImproveTool::EvalResult ImproveTool::evaluate() {
    EvalResult result;

    if (!fs::exists(labelsPath_)) {
        result.failReason = "MISSING_LABELS";
        return result;
    }

    // Load labels
    nlohmann::json labels;
    {
        std::ifstream f(labelsPath_);
        if (!f.is_open()) { result.failReason = "CANNOT_READ_LABELS"; return result; }
        f >> labels;
    }

    // Run scan on corpus
    std::string runId = "eval-" + std::to_string(time(nullptr)) + "-" + std::to_string(getpid());

    ScanCommand scan(*config_, db_);
    auto summary = scan.run(corpusDir_, runId);

    // Query results
    auto qr = db_.executeParams(
        "SELECT file_path, risk_score, risk_profile::text "
        "FROM scan_results WHERE run_id = $1",
        {runId});

    if (!qr.ok() || qr.rows.empty()) {
        result.failReason = "NO_RESULTS";
        ScanLog(db_).deleteRun(runId);
        return result;
    }

    // Count LLM calls
    auto countQr = db_.executeParams("SELECT COUNT(*) FROM llm_calls WHERE run_id = $1", {runId});
    if (countQr.ok() && !countQr.rows.empty() && !countQr.rows[0].empty())
        result.llmCalls = std::stoi(countQr.rows[0][0]);

    // Score each file
    double totalScore = 0;
    int fileCount = 0;
    std::ostringstream breakdown;

    for (auto& [key, label] : labels.items()) {
        std::string filename = fs::path(key).filename().string();

        // Find matching result row
        std::string relevance = "unknown";
        int riskScore = 0;
        std::string profileJson = "{}";
        bool found = false;

        for (auto& row : qr.rows) {
            if (row.size() >= 3 && row[0].find(filename) != std::string::npos) {
                riskScore = std::stoi(row[1]);
                profileJson = row[2];
                try {
                    auto profile = nlohmann::json::parse(profileJson);
                    relevance = profile.value("overall_relevance", "unknown");
                } catch (...) {}
                found = true;
                break;
            }
        }

        if (!found) {
            breakdown << "  " << key << ": MISSING (scan error) -> 0.00\n";
            fileCount++;
            continue;
        }

        // Hard-fail: benign classified as relevant with high score
        if (label.value("expected_class", "") == "not_relevant" &&
            relevance == "relevant" && riskScore > 40) {
            result.failReason = "FALSE_POSITIVE:" + key + "(score=" + std::to_string(riskScore) + ")";
            ScanLog(db_).deleteRun(runId);
            return result;
        }

        auto fs = scoreFile(key, label, relevance, riskScore, profileJson);
        totalScore += fs.total;
        fileCount++;
        breakdown << "  " << fs.detail << "\n";
    }

    result.score = (fileCount > 0) ? (totalScore / fileCount) * 100.0 : 0;
    result.breakdown = breakdown.str();

    // Cleanup eval data
    ScanLog(db_).deleteRun(runId);
    return result;
}

void ImproveTool::gitCommit(const std::string& msg) {
    exec("cd '" + escapeShell(repoDir_) + "' && git add prompts/ src/graph/graphs/scan_task_graph.cpp && git commit -m '" + escapeShell(msg) + "'");
}

void ImproveTool::gitRevert() {
    exec("cd '" + escapeShell(repoDir_) + "' && git checkout -- prompts/ src/graph/graphs/scan_task_graph.cpp");
}

bool ImproveTool::agentAvailable() {
    std::string agent = agentName();
    auto r = exec("command -v '" + escapeShell(agent) + "'");
    if (r.exitCode == 0 && !r.output.empty()) return true;
    // Also check if Docker image exists
    auto dr = exec("sudo docker image inspect 'area-improve-" + escapeShell(agent) + "' >/dev/null 2>&1");
    return dr.exitCode == 0;
}

int ImproveTool::runClaude(const std::string& prompt,
                           std::function<void(const std::string&)> onLine) {
    std::string mode = improveMode();
    if (mode == "docker") {
        return runAgentDocker(prompt, false, onLine);
    } else if (mode == "docker-headful") {
        return runAgentDocker(prompt, true, onLine);
    } else {
        return runAgentLocal(prompt, onLine);
    }
}

std::optional<ToolResult> ImproveTool::tryExecute(const std::string& action, ToolContext& ctx) {
    if (action.find("IMPROVE:") != 0)
        return std::nullopt;

    std::string task = action.substr(8);
    while (!task.empty() && task[0] == ' ') task.erase(0, 1);

    // Determine mode: eval-only or full improvement cycle
    bool evalOnly = false;
    {
        std::string lower = task;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        evalOnly = lower.empty() || lower == "evaluate" || lower == "eval"
                || lower == "score" || lower == "baseline" || lower == "run"
                || lower == "run the improve tool" || lower == "run improve";
    }

    if (!fs::exists(corpusDir_)) {
        return ToolResult{"OBSERVATION: Error — autoresearch corpus not found at " + corpusDir_ +
            ". Create the corpus directory with labeled smali files and labels.json."};
    }

    // 1. Run baseline evaluation
    ctx.cb({AgentMessage::THINKING, "Running corpus evaluation..."});
    auto baseline = evaluate();

    if (!baseline.failReason.empty()) {
        return ToolResult{"OBSERVATION: Evaluation failed: " + baseline.failReason +
            ". Check that the database is connected and LLM endpoints are configured."};
    }

    std::ostringstream scoreMsg;
    scoreMsg << std::fixed << std::setprecision(1)
             << "Corpus score: " << baseline.score << "/100 ("
             << baseline.llmCalls << " LLM calls)";
    ctx.cb({AgentMessage::THINKING, scoreMsg.str()});

    // Eval-only mode: just return the score and breakdown
    if (evalOnly) {
        std::ostringstream result;
        result << std::fixed << std::setprecision(1)
               << "OBSERVATION: Corpus evaluation complete.\n"
               << "  Score: " << baseline.score << "/100\n"
               << "  LLM calls: " << baseline.llmCalls << "\n\n"
               << "Per-file breakdown:\n" << baseline.breakdown;

        ctx.cb({AgentMessage::RESULT, "Corpus score: " +
            std::to_string((int)baseline.score) + "/100"});
        return ToolResult{result.str()};
    }

    // Full improvement cycle — check for coding agent
    if (!agentAvailable()) {
        std::ostringstream result;
        result << std::fixed << std::setprecision(1)
               << "OBSERVATION: Corpus baseline is " << baseline.score << "/100.\n"
               << "Per-file breakdown:\n" << baseline.breakdown << "\n"
               << "No coding agent available (checked: " << agentName() << " CLI and Docker image). "
               << "Install a coding agent or build the Docker image to run the full improvement cycle, "
               << "or edit prompts manually and re-run 'IMPROVE: evaluate' to check your score.";

        ctx.cb({AgentMessage::RESULT, "Baseline: " + std::to_string((int)baseline.score) +
            "/100 (no coding agent available for auto-improvement)"});
        return ToolResult{result.str()};
    }

    // 2. Build the prompt for Claude Code
    std::string programMd;
    {
        std::ifstream f(repoDir_ + "/autoresearch/program.md");
        if (f.is_open()) {
            std::ostringstream ss;
            ss << f.rdbuf();
            programMd = ss.str();
        }
    }

    std::ostringstream prompt;
    prompt << "You are improving AppReagent, a malware analysis platform.\n\n"
           << "## Task\n" << task << "\n\n"
           << "## Research Program\n" << programMd << "\n\n"
           << "## Current Evaluation (baseline: " << std::fixed << std::setprecision(1)
           << baseline.score << "/100)\n"
           << baseline.breakdown << "\n"
           << "Make ONE targeted change to improve the score. "
           << "Edit prompt files in prompts/ or code in src/graph/graphs/scan_task_graph.cpp. "
           << "Explain what you changed and why.\n";

    // 3. Launch coding agent
    std::string agent = agentName();
    std::string mode = improveMode();
    ctx.cb({AgentMessage::THINKING, "Launching " + agent + " (" + mode + ") to work on: " + task});

    int agentExit;
    auto lineCb = [&ctx, &agent](const std::string& line) {
        ctx.cb({AgentMessage::THINKING, "[" + agent + "] " + line});
    };

    if (mode == "docker" || mode == "docker-headful") {
        agentExit = runAgentDocker(prompt.str(), mode == "docker-headful", lineCb);
    } else {
        agentExit = runAgentLocal(prompt.str(), lineCb);
    }

    if (agentExit != 0) {
        ctx.cb({AgentMessage::ERROR, agent + " exited with code " + std::to_string(agentExit)});
        gitRevert();
        return ToolResult{"OBSERVATION: " + agent + " failed (exit " + std::to_string(agentExit) + "). Changes reverted."};
    }

    // 4. Rebuild if C++ was changed
    auto diffResult = exec("cd '" + escapeShell(repoDir_) + "' && git diff --name-only -- src/ include/");
    if (!diffResult.output.empty()) {
        ctx.cb({AgentMessage::THINKING, "C++ files changed, rebuilding..."});
        auto buildResult = exec("cd '" + escapeShell(repoDir_) + "' && make -j$(nproc) 2>&1 | tail -5");
        if (buildResult.exitCode != 0) {
            ctx.cb({AgentMessage::ERROR, "Build failed:\n" + buildResult.output});
            gitRevert();
            return ToolResult{"OBSERVATION: Build failed after Claude's changes. Reverted.\n" + buildResult.output};
        }
        ctx.cb({AgentMessage::THINKING, "Build succeeded."});
    }

    // 5. Re-evaluate
    ctx.cb({AgentMessage::THINKING, "Evaluating changes..."});
    auto after = evaluate();

    if (!after.failReason.empty()) {
        ctx.cb({AgentMessage::ERROR, "Evaluation failed: " + after.failReason});
        gitRevert();
        return ToolResult{"OBSERVATION: Evaluation failed after changes: " + after.failReason + ". Reverted."};
    }

    double delta = after.score - baseline.score;
    std::ostringstream resultStr;
    resultStr << std::fixed << std::setprecision(1);

    if (delta > 0) {
        resultStr << "OBSERVATION: Improvement detected!\n"
                  << "  Before: " << baseline.score << "\n"
                  << "  After:  " << after.score << " (+" << delta << ")\n\n"
                  << "Per-file breakdown:\n" << after.breakdown;

        gitCommit("improve: " + task + " (" + std::to_string((int)after.score) + ")");
        ctx.cb({AgentMessage::RESULT,
            "Score improved: " + std::to_string((int)baseline.score) + " -> " +
            std::to_string((int)after.score) + " (+" + std::to_string((int)delta) + ")"});
    } else {
        resultStr << "OBSERVATION: No improvement.\n"
                  << "  Before: " << baseline.score << "\n"
                  << "  After:  " << after.score << " (" << delta << ")\n\n"
                  << "Per-file breakdown:\n" << after.breakdown << "\n"
                  << "Changes have been reverted.";

        gitRevert();
        ctx.cb({AgentMessage::RESULT,
            "No improvement: " + std::to_string((int)baseline.score) + " -> " +
            std::to_string((int)after.score) + ". Reverted."});
    }

    return ToolResult{resultStr.str()};
}

} // namespace area
