#include "features/scan/ScanCommand.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <cstdlib>
#include <exception>
#include <map>
#include <optional>
#include <system_error>
#include <unordered_map>
#include <utility>

#include "infra/events/EventBus.h"
#include "util/file_io.h"
#include "util/string_util.h"
#include "domains/graph/engine/graph_runner.h"
#include "domains/graph/graphs/scan_task_graph.h"
#include "domains/graph/graphs/tier_pool.h"
#include "domains/graph/nodes/llm_call_node.h"
#include "domains/graph/util/json_extract.h"
#include "domains/graph/engine/task_context.h"
#include "domains/graph/engine/task_graph.h"
#include "infra/llm/LLMBackend.h"
#include "nlohmann/detail/iterators/iter_impl.hpp"
#include "nlohmann/json.hpp"

namespace fs = std::filesystem;

namespace area {
ScanCommand::ScanCommand(const Config& config, Database& db)
    : config_(config), db_(db), log_(db) {
    if (config.embedding.has_value()) {
        try {
            embeddingBackend_ = EmbeddingBackend::create(*config.embedding);
            embeddingStore_ = std::make_unique<EmbeddingStore>(db, embeddingBackend_.get());
        } catch (const std::exception& e) {
            std::cerr << "[scan] embedding init failed: " << e.what() << std::endl;
        }
    }
}

static bool fileHasElfMagic(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    char buf[4];
    f.read(buf, 4);
    return f.gcount() == 4 &&
           buf[0] == '\x7f' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F';
}

std::vector<std::string> ScanCommand::findScanFiles(const std::string& dir) {
    std::vector<std::string> files;

    if (!fs::exists(dir)) return files;

    if (fs::is_regular_file(dir)) {
        if (dir.ends_with(".smali") || fileHasElfMagic(dir)) {
            files.push_back(dir);
        }
        return files;
    }

    if (!fs::is_directory(dir)) return files;

    std::error_code ec;
    auto it = fs::recursive_directory_iterator(
        dir, fs::directory_options::skip_permission_denied, ec);
    if (ec) return files;

    for (; it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            ec.clear(); continue;
        }
        if (!it->is_regular_file(ec) || ec) {
            ec.clear(); continue;
        }
        if (it->path().extension() == ".smali") {
            files.push_back(it->path().string());
        } else if (fileHasElfMagic(it->path().string())) {
            files.push_back(it->path().string());
        }
    }

    std::sort(files.begin(), files.end());
    return files;
}

std::string ScanCommand::readFile(const std::string& path) {
    return util::readFile(path);
}

void ScanCommand::emitLog(const std::string& msg) {
    if (logCb_) logCb_(msg);
    else std::cerr << msg << std::endl;
}

std::string ScanCommand::expandGoal(const std::string& goal, const std::string& promptsDir,
                                    const graph::TierBackends& backends) {
    if (goal.size() >= 150 || !fs::exists(promptsDir + "/goal_expand.prompt")) {
        return goal;
    }

    try {
        std::string expandPromptTmpl = graph::loadPrompt(promptsDir + "/goal_expand.prompt");
        graph::TaskContext goalCtx;
        goalCtx.set("user_goal", goal);
        std::string expandPrompt = graph::resolveTemplate(expandPromptTmpl, goalCtx);

        auto* goalBackend = backends.at(1);
        std::string goalSystem = graph::loadPrompt(promptsDir + "/goal_expand_system.prompt");
        std::string expanded = goalBackend->chat(goalSystem, {{"user", expandPrompt}});
        util::rtrimInPlace(expanded);
        if (!expanded.empty()) {
            emitLog("Expanded goal: " + expanded.substr(0, 120) + "...");
            return expanded;
        }
    } catch (const std::exception& e) {
        emitLog("Goal expansion failed (using original): " + std::string(e.what()));
    }
    return goal;
}

void ScanCommand::processFile(const std::string& filePath, const std::string& runId,
                               const std::string& scanGoal, graph::GraphRunner& runner,
                               const graph::TaskGraph& graph, ScanSummary& summary,
                               std::vector<nlohmann::json>& fileProfiles) {
    std::string contents = readFile(filePath);
    std::string fileHash = ScanLog::sha256(contents);

    log_.storeFile(runId, filePath, fileHash, contents);

    if (completedHashes_.count(fileHash) || log_.fileCompleted(runId, fileHash)) {
        summary.files_skipped++;

        log_.logScanResult(runId, filePath, fileHash, "{}", "duplicate of already-scanned file", -1);
        return;
    }

    std::string fileName = fs::path(filePath).filename().string();
    if (events_) events_->emit({EventType::SCAN_FILE_START, fileName, filePath});
    emitLog("Analyzing " + fileName + " (" +
            std::to_string(summary.files_scanned + 1) + "/" +
            std::to_string(summary.files_total) + ")");

    graph::TaskContext initial;
    initial.set("file_path", filePath);
    initial.set("file_hash", fileHash);
    initial.set("scan_goal", scanGoal);

    graph::TaskContext result;
    try {
        result = runner.run(graph, std::move(initial));
    } catch (const std::exception& e) {
        emitLog("Error: " + std::string(e.what()));
        summary.files_error++;
        return;
    }

    summary.files_scanned++;
    if (progressCb_) progressCb_(summary.files_scanned, summary.files_total);

    if (result.discarded) {
        emitLog(fileName + ": skipped (" + result.discard_reason + ")");
        summary.files_irrelevant++;
        log_.logScanResult(runId, filePath, fileHash, "{}", "skipped", 0);
        output_.writeFileResult(filePath, fileHash, "skipped", 0, "skipped", {}, 0);
        return;
    }

    if (!result.has("risk_profile")) {
        emitLog(fileName + ": no results");
        summary.files_error++;
        log_.logScanResult(runId, filePath, fileHash, "{}", "error", 0);
        output_.writeFileResult(filePath, fileHash, "error", 0, "error", {}, 0);
        return;
    }

    auto profile = result.get("risk_profile");
    if (!profile.is_object()) {
        emitLog(fileName + ": risk_profile parse error");
        summary.files_error++;
        log_.logScanResult(runId, filePath, fileHash, "{}", "error", 0);
        output_.writeFileResult(filePath, fileHash, "error", 0, "error", {}, 0);
        return;
    }
    std::string relevance = profile.value("overall_relevance", "unknown");
    std::string recommendation = profile.value("recommendation", "unknown");
    int score = profile.value("relevance_score", 0);

    emitLog(fileName + ": " + relevance + " (score=" + std::to_string(score) + ")");

    if (relevance == "relevant") summary.files_relevant++;
    else if (relevance == "partially_relevant") summary.files_partial++;
    else summary.files_irrelevant++;

    if (relevance == "relevant" || relevance == "partially_relevant") {
        nlohmann::json entry;
        entry["file_path"] = filePath;
        entry["file_name"] = fs::path(filePath).filename().string();
        entry["answer"] = profile.value("answer", "");
        entry["evidence_summary"] = profile.value("evidence_summary", "");
        entry["relevance_score"] = score;
        entry["relevant_methods"] = profile.value("relevant_methods", nlohmann::json::array());
        fileProfiles.push_back(std::move(entry));
    }

    log_.logScanResult(runId, filePath, fileHash, profile.dump(), recommendation, score);
    output_.writeFileResult(filePath, fileHash, relevance, score, recommendation, profile, 0);
}

void ScanCommand::synthesizeResults(const std::string& runId, const std::string& scanGoal,
                                     const std::string& promptsDir,
                                     const graph::TierBackends& backends,
                                     std::vector<nlohmann::json>& fileProfiles,
                                     ScanSummary& summary) {
    if (summary.files_relevant + summary.files_partial == 0
        || !fs::exists(promptsDir + "/scan_synthesis.prompt")) {
        summary.answer = "No relevant findings across scanned files.";
        return;
    }

    emitLog("Synthesizing cross-file findings...");

    std::sort(fileProfiles.begin(), fileProfiles.end(),
              [](const nlohmann::json& a, const nlohmann::json& b) {
                  return a.value("relevance_score", 0) > b.value("relevance_score", 0);
              });

    std::ostringstream summariesStream;
    int maxFull = 30;
    for (int i = 0; i < static_cast<int>(fileProfiles.size()) && i < maxFull; i++) {
        summariesStream << fileProfiles[i].dump(2) << "\n---\n";
    }
    if (static_cast<int>(fileProfiles.size()) > maxFull) {
        summariesStream << "(+" << (fileProfiles.size() - maxFull)
                        << " additional files with lower scores omitted)\n";
    }

    try {
        std::string synthPromptTmpl = graph::loadPrompt(promptsDir + "/scan_synthesis.prompt");
        graph::TaskContext synthCtx;
        synthCtx.set("scan_goal", scanGoal);
        synthCtx.set("file_summaries", summariesStream.str());
        synthCtx.set("files_relevant", summary.files_relevant + summary.files_partial);
        synthCtx.set("files_total", summary.files_total);
        std::string expandedPrompt = graph::resolveTemplate(synthPromptTmpl, synthCtx);

        auto* synthBackend = backends.at(2);
        std::string system = graph::loadPrompt(promptsDir + "/scan_synthesis_system.prompt");
        std::string response = synthBackend->chat(system, {{"user", expandedPrompt}});

        auto synthJson = nlohmann::json::parse(graph::extractJson(response));
        summary.answer = synthJson.value("answer", response);
        summary.risk_score = synthJson.value("risk_score", 0);

        auto promptHash = ScanLog::sha256(expandedPrompt);
        log_.logLLMCall(runId, "", "", "scan_synthesis", 2,
                        expandedPrompt, promptHash, response, 0);
        output_.writeSynthesis(response, synthJson);

        emitLog("Synthesis complete (risk=" + std::to_string(summary.risk_score) + ")");
    } catch (const std::exception& e) {
        emitLog("Cross-file synthesis failed: " + std::string(e.what()));
        summary.answer = "Cross-file synthesis failed: " + std::string(e.what());
    }
}

ScanSummary ScanCommand::run(const std::string& target_path, const std::string& resumeId,
                             const std::string& goal) {
    ScanSummary summary;

    log_.ensureTables();

    auto files = findScanFiles(target_path);
    if (files.empty()) {
        emitLog("No scannable files found in " + target_path);
        return summary;
    }

    std::string runId = resumeId.empty() ? ScanLog::generateRunId() : resumeId;
    summary.run_id = runId;
    summary.files_total = static_cast<int>(files.size());

    std::string scanGoal = goal.empty()
        ? "Identify malware indicators including C2 communication, data exfiltration, "
          "SMS abuse, dynamic code loading, reflection-based evasion, native exploits, "
          "and privilege escalation in this Android application."
        : goal;

    graph::TierPool pool(config_.ai_endpoints);
    auto backends = pool.backends();

    std::string promptsDir = "prompts";
    if (auto envDir = std::getenv("AREA_PROMPTS_DIR")) {
        promptsDir = envDir;
    }
    if (!promptsOverride_.empty() && fs::exists(promptsOverride_)) {
        promptsDir = promptsOverride_;
    }

    scanGoal = expandGoal(scanGoal, promptsDir, backends);

    output_.open(runId);
    output_.writeMetadata(target_path, runId, scanGoal);

    emitLog("Scanning " + std::to_string(files.size()) + " files (run " + runId + ")");

    graph::TaskGraph graph = graph::buildScanTaskGraph(backends, promptsDir, embeddingStore_.get());
    graph::GraphRunner runner;

    runner.setMaxParallel(pool.totalConcurrency());

    runner.onNodeStart([this](const std::string& nodeName, const graph::TaskContext& ctx) {
        if (events_) events_->emit({EventType::NODE_START, nodeName, ""});
        if (nodeName == "triage" || nodeName == "deep_analysis" || nodeName == "synthesize") {
            std::string label = nodeName;
            if (ctx.has("method_name")) label += ": " + ctx.get("method_name").get<std::string>();
            emitLog(label);
        }
    });

    struct CallEdgeState {
        std::unordered_set<std::string> logged;
        std::mutex mu;
    };
    auto callEdges = std::make_shared<CallEdgeState>();

    runner.onNodeEnd([this, runId, callEdges](const std::string& nodeName, const graph::TaskContext& ctx) {
        if (events_) events_->emit({EventType::NODE_END, nodeName, ""});

        if (nodeName == "triage" && ctx.has("llm_response") && ctx.has("method_name")) {
            try {
                auto j = nlohmann::json::parse(graph::extractJson(ctx.get("llm_response").get<std::string>()));
                std::string className = ctx.has("class_name") ? ctx.get("class_name").get<std::string>() : "";
                std::string methodName = ctx.get("method_name").get<std::string>();
                std::string fp = ctx.has("file_path") ? ctx.get("file_path").get<std::string>() : "";
                std::string fh = ctx.has("file_hash") ? ctx.get("file_hash").get<std::string>() : "";

                std::string apiCalls;
                if (j.contains("api_calls") && j["api_calls"].is_array()) {
                    for (auto& a : j["api_calls"]) {
                        if (!apiCalls.empty()) apiCalls += ", ";
                        apiCalls += a.get<std::string>();
                    }
                }

                std::string findings;
                if (j.contains("findings") && j["findings"].is_array()) {
                    for (auto& f : j["findings"]) {
                        if (!findings.empty()) findings += "; ";
                        findings += f.get<std::string>();
                    }
                }

                std::string reasoning = j.value("reasoning", "");
                bool relevant = j.value("relevant", false);
                double confidence = j.value("confidence", 0.0);
                std::string threatCategory = j.value("threat_category", "none");

                log_.logMethodFinding(runId, fp, fh, className, methodName,
                                      apiCalls, findings, reasoning, relevant, confidence,
                                      threatCategory);
            } catch (...) {
            }
        }

        if (ctx.has("method_calls") && ctx.has("class_name") && ctx.has("method_name")) {
            std::string callerClass = ctx.get("class_name").get<std::string>();
            std::string callerMethod = ctx.get("method_name").get<std::string>();
            std::string edgeKey = callerClass + "::" + callerMethod;
            std::string fp = ctx.has("file_path") ? ctx.get("file_path").get<std::string>() : "";
            std::string fh = ctx.has("file_hash") ? ctx.get("file_hash").get<std::string>() : "";

            {
                std::lock_guard lk(callEdges->mu);
                if (callEdges->logged.insert(edgeKey).second) {
                    auto calls = ctx.get("method_calls");
                    for (auto& c : calls) {
                        log_.logMethodCall(runId, fp, fh,
                            callerClass, callerMethod,
                            c.value("target_class", ""),
                            c.value("target_method", ""),
                            c.value("invoke_type", ""));
                    }
                }
            }
        }

        if (ctx.has("llm_response") && ctx.has("llm_prompt")) {
            auto prompt = ctx.get("llm_prompt").get<std::string>();
            auto response = ctx.get("llm_response").get<std::string>();
            auto promptHash = ScanLog::sha256(prompt);
            std::string filePath = ctx.has("file_path") ? ctx.get("file_path").get<std::string>() : "";
            std::string fileHash = ctx.has("file_hash") ? ctx.get("file_hash").get<std::string>() : "";

            if (events_) events_->emit({EventType::LLM_CALL, nodeName, filePath});
            log_.logLLMCall(runId, filePath, fileHash, nodeName, 0,
                prompt, promptHash, response, 0);
            output_.writeLLMCall(filePath, fileHash, nodeName, prompt, response, 0);

            if (nodeName == "deep_analysis" && embeddingStore_ && embeddingStore_->hasBackend()) {
                std::string className = ctx.has("class_name") ? ctx.get("class_name").get<std::string>() : "";
                std::string methodName = ctx.has("method_name") ? ctx.get("method_name").get<std::string>() : "";
                std::string methodBody = ctx.has("method_body") ? ctx.get("method_body").get<std::string>() : "";

                std::string content = methodBody + "\n\n--- Analysis ---\n" + response;
                embeddingStore_->embedAndStore(runId, filePath, fileHash,
                                              className, methodName, content);
            }
        }
    });

    std::vector<nlohmann::json> fileProfiles;

    for (auto& filePath : files) {
        if (interrupt_ && interrupt_->load()) {
            emitLog("Scan paused at " + std::to_string(summary.files_scanned) +
                    "/" + std::to_string(summary.files_total) + " files");
            summary.paused = true;
            break;
        }
        processFile(filePath, runId, scanGoal, runner, graph, summary, fileProfiles);
    }

    if (!summary.paused) {
        synthesizeResults(runId, scanGoal, promptsDir, backends, fileProfiles, summary);
    }

    int totalPrompt = 0, totalCompletion = 0;
    std::unordered_set<area::LLMBackend*> seen;
    for (auto& [tier, backend] : backends.backends) {
        if (backend && seen.insert(backend).second) {
            totalPrompt += backend->totalPromptTokens.load();
            totalCompletion += backend->totalCompletionTokens.load();
        }
    }

    emitLog("Complete: " + std::to_string(summary.files_scanned) + " scanned, "
          + std::to_string(summary.files_relevant) + " relevant, "
          + std::to_string(summary.files_partial) + " partial, "
          + std::to_string(summary.files_irrelevant) + " irrelevant ("
          + std::to_string(totalPrompt + totalCompletion) + " tokens)");

    return summary;
}

ScanSummary ScanCommand::runFromFile(const std::string& jsonl_path) {
    auto loaded = ScanOutputFile::load(jsonl_path);
    completedHashes_ = std::move(loaded.completed_hashes);
    emitLog("Resuming from " + jsonl_path + " (" + std::to_string(completedHashes_.size()) + " files already done)");
    return run(loaded.target_path, loaded.run_id);
}
}  // namespace area
