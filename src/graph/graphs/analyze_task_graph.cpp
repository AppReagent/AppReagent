#include "graph/graphs/analyze_task_graph.h"
#include "graph/util/json_extract.h"
#include "util/file_io.h"

#include <iostream>
#include <sstream>

#include "graph/nodes/code_node.h"
#include "graph/nodes/llm_call_node.h"
#include "graph/nodes/splitter_node.h"
#include "graph/nodes/supervised_llm_call_node.h"

namespace area::graph {

TaskGraph buildAnalyzeTaskGraph(const TierBackends& backends,
                                Database& db,
                                EmbeddingStore* embeddingStore,
                                const std::string& prompts_dir) {
    TaskGraph g("AnalyzeTask");

    // 1. Load scan results from DB for the given run_id
    auto load_results = g.add<CodeNode>("load_results", [&db](TaskContext ctx) {
        std::string runId = ctx.get("run_id").get<std::string>();

        // Query scan_results + llm_calls for deep_analysis responses
        auto sr = db.execute(
            "SELECT sr.file_path, sr.file_hash, sr.risk_profile, sr.risk_score, "
            "sr.recommendation "
            "FROM scan_results sr "
            "WHERE sr.run_id = '" + runId + "' "
            "AND sr.risk_score > 0 "
            "ORDER BY sr.risk_score DESC");

        if (!sr.ok() || sr.rows.empty()) {
            ctx.discarded = true;
            ctx.discard_reason = "no scan results found for run " + runId;
            return ctx;
        }

        nlohmann::json results = nlohmann::json::array();
        for (auto& row : sr.rows) {
            nlohmann::json entry;
            entry["file_path"] = row[0];
            entry["file_hash"] = row[1];
            try {
                entry["risk_profile"] = nlohmann::json::parse(row[2]);
            } catch (...) {
                entry["risk_profile"] = row[2];
            }
            entry["risk_score"] = std::stoi(row[3]);
            entry["recommendation"] = row[4];
            results.push_back(std::move(entry));
        }

        ctx.set("scan_results", results);
        ctx.set("files_analyzed", (int)results.size());
        return ctx;
    });

    // 2. Split into per-finding contexts (one per file result that has relevant methods)
    auto split_findings = g.add<SplitterNode>("split_findings", [](TaskContext ctx) {
        auto results = ctx.get("scan_results");
        std::string runId = ctx.get("run_id").get<std::string>();
        std::string scanGoal = ctx.has("scan_goal") ? ctx.get("scan_goal").get<std::string>() : "";

        std::vector<TaskContext> items;
        for (auto& result : results) {
            auto& profile = result["risk_profile"];
            auto methods = profile.value("relevant_methods", nlohmann::json::array());

            std::string filePath = result.value("file_path", "");
            std::string className = "";
            // Extract class name from file path (last component minus .smali)
            auto slash = filePath.rfind('/');
            auto dot = filePath.rfind('.');
            if (dot != std::string::npos) {
                className = filePath.substr(slash != std::string::npos ? slash + 1 : 0,
                                            dot - (slash != std::string::npos ? slash + 1 : 0));
            }

            if (methods.empty()) {
                // Create a single finding for the whole file
                TaskContext item;
                item.set("run_id", runId);
                item.set("scan_goal", scanGoal);
                item.set("file_path", filePath);
                item.set("class_name", className);
                item.set("method_name", "");
                item.set("finding", profile.dump(2));
                items.push_back(std::move(item));
            } else {
                // One per relevant method
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
            // Return at least one empty context to avoid graph error
            TaskContext empty;
            empty.set("run_id", runId);
            empty.set("scan_goal", scanGoal);
            empty.discarded = true;
            empty.discard_reason = "no findings to analyze";
            items.push_back(std::move(empty));
        }

        return items;
    });

    // 3. RAG retrieval: embed the finding and search for similar methods
    auto rag_retrieve = g.add<CodeNode>("rag_retrieve", [embeddingStore](TaskContext ctx) {
        std::string finding = ctx.has("finding") ? ctx.get("finding").get<std::string>() : "";
        std::string runId = ctx.has("run_id") ? ctx.get("run_id").get<std::string>() : "";

        std::string ragContext = "(no similar methods found in corpus)";

        if (embeddingStore && embeddingStore->hasBackend() && !finding.empty()) {
            try {
                // Search for similar methods, excluding current run to find cross-run patterns
                auto results = embeddingStore->searchByText(finding, 5, runId);

                if (!results.empty()) {
                    std::ostringstream ss;
                    for (size_t i = 0; i < results.size(); i++) {
                        auto& r = results[i];
                        ss << "--- Similar method " << (i + 1)
                           << " (similarity=" << (int)(r.similarity * 100) << "%, "
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

    // 4. Analyze each finding with RAG context (supervised LLM call)
    std::string analyzePrompt = loadPrompt(prompts_dir + "/analyze.prompt");

    auto analyze_finding = g.add<SupervisedLLMCallNode>("analyze_finding",
        SupervisedLLMCallConfig{
            .tier = 1,
            .prompt_template = analyzePrompt,
            .system_prompt = "You are a senior malware analyst with access to a corpus of previously analyzed applications. "
                           "Use pattern matching from the corpus to produce deeper, more confident assessments. "
                           "Output ONLY valid JSON, no markdown.",
            .supervisor_prompt = "Review this analysis. Is it valid JSON with assessment and confidence? "
                                "Does it meaningfully use the RAG context? Respond PASS or FAIL - reason.",
            .max_retries = 1,
        },
        backends.at(2),
        backends.at(1),
        nullptr);

    // 5. Collect all analyses
    auto collector = g.add<CollectorNode>("collect_analyses", [](std::vector<TaskContext> items) {
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
        // Propagate run_id and scan_goal from first item
        if (!items.empty()) {
            if (items[0].has("run_id")) result.set("run_id", items[0].get("run_id"));
            if (items[0].has("scan_goal")) result.set("scan_goal", items[0].get("scan_goal"));
            if (items[0].has("files_analyzed")) result.set("files_analyzed", items[0].get("files_analyzed"));
        }
        return result;
    });

    // 6. Final synthesis
    std::string synthPrompt = loadPrompt(prompts_dir + "/analyze_synthesis.prompt");

    auto final_synthesis = g.add<SupervisedLLMCallNode>("analyze_synthesis",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = synthPrompt,
            .system_prompt = "You are a senior threat analyst producing a comprehensive RAG-augmented analysis report. "
                           "Synthesize per-method findings with cross-application pattern matches. "
                           "Output ONLY valid JSON, no markdown.",
            .supervisor_prompt = "",
            .max_retries = 1,
        },
        backends.at(2),
        backends.at(0),
        nullptr);

    // 7. Extract analysis result
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

    // Wire the graph
    g.edge(load_results, split_findings);

    // Splitter -> per-finding subgraph -> collector
    g.edge(split_findings, rag_retrieve);
    g.branch(split_findings, "collect", collector);

    g.edge(rag_retrieve, analyze_finding);
    // analyze_finding is terminal in the per-finding subgraph (returns to collector)

    g.edge(collector, final_synthesis);
    g.edge(final_synthesis, extract);

    g.setEntry(load_results);
    g.setOutput(extract);

    return g;
}

} // namespace area::graph
