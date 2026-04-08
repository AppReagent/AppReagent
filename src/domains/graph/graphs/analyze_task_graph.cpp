#include "domains/graph/graphs/analyze_task_graph.h"

#include <stddef.h>

#include <exception>
#include <iostream>
#include <map>
#include <sstream>
#include <utility>
#include <vector>

#include "domains/graph/engine/task_context.h"
#include "domains/graph/nodes/code_node.h"
#include "domains/graph/nodes/splitter_node.h"
#include "domains/graph/nodes/supervised_llm_call_node.h"
#include "domains/graph/util/json_extract.h"
#include "nlohmann/detail/iterators/iter_impl.hpp"
#include "nlohmann/json.hpp"
namespace area::graph {
TaskGraph buildAnalyzeTaskGraph(const TierBackends& backends,
                                Database& db,
                                EmbeddingStore* embeddingStore,
                                const std::string& prompts_dir) {
    TaskGraph g("AnalyzeTask");

    auto load_results = g.add<CodeNode>("load_results", [&db](TaskContext ctx) {
        std::string runId = ctx.get("run_id").get<std::string>();

        auto sr = db.executeParams(
            "SELECT sr.file_path, sr.file_hash, sr.risk_profile, sr.risk_score, "
            "sr.recommendation "
            "FROM scan_results sr "
            "WHERE sr.run_id = $1 "
            "AND sr.risk_score > 0 "
            "ORDER BY sr.risk_score DESC",
            {runId});

        if (!sr.ok() || sr.rows.empty()) {
            ctx.discarded = true;
            ctx.discard_reason = "no scan results found for run " + runId;
            return ctx;
        }

        nlohmann::json results = nlohmann::json::array();
        for (auto& row : sr.rows) {
            if (row.size() < 5) continue;
            nlohmann::json entry;
            entry["file_path"] = row[0];
            entry["file_hash"] = row[1];
            try {
                entry["risk_profile"] = nlohmann::json::parse(row[2]);
            } catch (...) {
                entry["risk_profile"] = row[2];
            }
            try {
                entry["risk_score"] = std::stoi(row[3]); } catch (...) { entry["risk_score"] = 0;
            }
            entry["recommendation"] = row[4];
            results.push_back(std::move(entry));
        }

        ctx.set("scan_results", results);
        ctx.set("files_analyzed", static_cast<int>(results.size()));
        return ctx;
    });

    auto split_findings = g.add<SplitterNode>("split_findings", [](const TaskContext& ctx) {
        auto results = ctx.get("scan_results");
        std::string runId = ctx.get("run_id").get<std::string>();
        std::string scanGoal = ctx.has("scan_goal") ? ctx.get("scan_goal").get<std::string>() : "";

        std::vector<TaskContext> items;
        for (auto& result : results) {
            auto& profile = result["risk_profile"];
            auto methods = profile.value("relevant_methods", nlohmann::json::array());

            std::string filePath = result.value("file_path", "");
            std::string className = "";

            auto slash = filePath.rfind('/');
            auto dot = filePath.rfind('.');
            if (dot != std::string::npos) {
                className = filePath.substr(slash != std::string::npos ? slash + 1 : 0,
                                            dot - (slash != std::string::npos ? slash + 1 : 0));
            }

            if (methods.empty()) {
                TaskContext item;
                item.set("run_id", runId);
                item.set("scan_goal", scanGoal);
                item.set("file_path", filePath);
                item.set("class_name", className);
                item.set("method_name", "");
                item.set("finding", profile.dump(2));
                items.push_back(std::move(item));
            } else {
                for (auto& m : methods) {
                    TaskContext item;
                    item.set("run_id", runId);
                    item.set("scan_goal", scanGoal);
                    item.set("file_path", filePath);
                    item.set("class_name", className);
                    item.set("method_name", m.value("method", ""));
                    std::string finding = m.dump(2);
                    if (profile.contains("evidence_summary")) {
                        finding += "\n\nEvidence: " + profile.value("evidence_summary", "");
                    }
                    item.set("finding", finding);
                    items.push_back(std::move(item));
                }
            }
        }

        if (items.empty()) {
            TaskContext empty;
            empty.set("run_id", runId);
            empty.set("scan_goal", scanGoal);
            empty.discarded = true;
            empty.discard_reason = "no findings to analyze";
            items.push_back(std::move(empty));
        }

        int total = static_cast<int>(items.size());
        for (int i = 0; i < static_cast<int>(items.size()); i++) {
            items[i].set("finding_index", i + 1);
            items[i].set("total_findings", total);
        }

        return items;
    });

    auto rag_retrieve = g.add<CodeNode>("rag_retrieve", [embeddingStore](TaskContext ctx) {
        std::string finding = ctx.has("finding") ? ctx.get("finding").get<std::string>() : "";
        std::string runId = ctx.has("run_id") ? ctx.get("run_id").get<std::string>() : "";

        std::string ragContext = "(no similar methods found in corpus)";

        if (embeddingStore && embeddingStore->hasBackend() && !finding.empty()) {
            try {
                auto results = embeddingStore->searchByText(finding, 5, runId);

                if (!results.empty()) {
                    std::ostringstream ss;
                    for (size_t i = 0; i < results.size(); i++) {
                        auto& r = results[i];
                        ss << "--- Similar method " << (i + 1)
                           << " (similarity=" << static_cast<int>((r.similarity * 100)) << "%, "
                           << "run=" << r.run_id << ") ---\n"
                           << "Class: " << r.class_name << "\n"
                           << "Method: " << r.method_name << "\n"
                           << "File: " << r.file_path << "\n"
                           << r.content.substr(0, 2000) << "\n\n";
                    }
                    ragContext = ss.str();
                }
            } catch (const std::exception& e) {
                std::cerr << "[analyze] RAG retrieval failed: " << e.what() << std::endl;
            }
        }

        ctx.set("rag_context", ragContext);
        return ctx;
    });

    std::string analyzePrompt = loadPrompt(prompts_dir + "/analyze.prompt");
    std::string analyzeFindingSystem = loadPrompt(prompts_dir + "/analyze_finding_system.prompt");
    std::string analyzeFindingSupervisor = loadPrompt(prompts_dir + "/analyze_finding_supervisor.prompt");

    auto analyze_finding = g.add<SupervisedLLMCallNode>("analyze_finding",
        SupervisedLLMCallConfig{
            .tier = 1,
            .prompt_template = analyzePrompt,
            .system_prompt = analyzeFindingSystem,
            .supervisor_prompt = analyzeFindingSupervisor,
            .max_retries = 1,
        },
        backends.at(2),
        backends.at(1),
        nullptr);

    auto collector = g.add<CollectorNode>("collect_analyses", [](const std::vector<TaskContext>& items) {
        TaskContext result;
        nlohmann::json collected = nlohmann::json::array();
        for (auto& item : items) {
            nlohmann::json entry;
            entry["file_path"] = item.has("file_path") ? item.get("file_path") : "";
            entry["class_name"] = item.has("class_name") ? item.get("class_name") : "";
            entry["method_name"] = item.has("method_name") ? item.get("method_name") : "";
            if (item.has("llm_response")) {
                try {
                    entry["analysis"] = nlohmann::json::parse(
                        extractJson(item.get("llm_response").get<std::string>()));
                } catch (...) {
                    entry["analysis"] = item.get("llm_response");
                }
            }
            collected.push_back(std::move(entry));
        }
        result.set("collected", collected);

        if (!items.empty()) {
            if (items[0].has("run_id")) result.set("run_id", items[0].get("run_id"));
            if (items[0].has("scan_goal")) result.set("scan_goal", items[0].get("scan_goal"));
        }

        result.set("files_analyzed", static_cast<int>(collected.size()));
        return result;
    });

    std::string synthPrompt = loadPrompt(prompts_dir + "/analyze_synthesis.prompt");
    std::string analyzeSynthesisSystem = loadPrompt(prompts_dir + "/analyze_synthesis_system.prompt");

    auto final_synthesis = g.add<SupervisedLLMCallNode>("analyze_synthesis",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = synthPrompt,
            .system_prompt = analyzeSynthesisSystem,
            .supervisor_prompt = "",
            .max_retries = 1,
        },
        backends.at(2),
        backends.at(0),
        nullptr);

    auto extract = g.add<CodeNode>("extract_analysis", [](TaskContext ctx) {
        if (ctx.has("llm_response")) {
            try {
                auto j = nlohmann::json::parse(
                    extractJson(ctx.get("llm_response").get<std::string>()));
                ctx.set("analysis_result", j);
            } catch (...) {
                ctx.set("analysis_result", ctx.get("llm_response"));
            }
        }
        return ctx;
    });

    g.edge(load_results, split_findings);

    g.edge(split_findings, rag_retrieve);
    g.branch(split_findings, "collect", collector);

    g.edge(rag_retrieve, analyze_finding);

    g.edge(collector, final_synthesis);
    g.edge(final_synthesis, extract);

    g.setEntry(load_results);
    g.setOutput(extract);

    return g;
}
}  // namespace area::graph
