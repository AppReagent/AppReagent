#include "graph/graphs/scan_task_graph.h"
#include "graph/util/json_extract.h"
#include "util/file_io.h"
#include "Embedding.h"

#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

using area::graph::extractJson;
namespace fs = std::filesystem;

#include "elf/disassembler.h"
#include "graph/nodes/code_node.h"
#include "graph/nodes/llm_call_node.h"
#include "graph/nodes/splitter_node.h"
#include "graph/nodes/supervised_llm_call_node.h"
#include "smali/parser.h"

namespace area::graph {

std::string loadPrompt(const std::string& path) {
    return area::util::readFileOrThrow(path);
}

static bool validateJsonKeys(const std::string& response, const TaskContext&,
                             std::initializer_list<const char*> keys) {
    try {
        auto j = nlohmann::json::parse(extractJson(response));
        for (auto* key : keys) {
            if (!j.contains(key)) return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}

TaskGraph buildScanTaskGraph(const TierBackends& backends,
                             const std::string& prompts_dir,
                             area::EmbeddingStore* embeddingStore) {
    TaskGraph g("ScanTask");

    // 1. Read file (binary-safe for ELF support)
    auto read_file = g.add<CodeNode>("read_file", [](TaskContext ctx) {
        std::string path = ctx.get("file_path").get<std::string>();
        std::string contents = area::util::readFile(path);
        if (contents.empty()) {
            ctx.set("error", "could not open file: " + path);
            ctx.discarded = true;
            return ctx;
        }
        ctx.set("file_contents", contents);

        // Detect format by magic bytes and extension
        if (area::elf::isElf(contents)) {
            ctx.set("file_format", "elf");
        } else if (path.ends_with(".smali")) {
            ctx.set("file_format", "smali");
        } else {
            ctx.set("file_format", "unsupported");
        }
        return ctx;
    });

    // 2. Format routing
    auto detect_format = g.add<DecisionCodeNode>("detect_format", [](const TaskContext& ctx) -> std::string {
        if (ctx.has("file_format")) {
            return ctx.get("file_format").get<std::string>();
        }
        return "unsupported";
    });

    auto unsupported = g.add<ExitNode>("unsupported", [](TaskContext& ctx) {
        ctx.discard_reason = "unsupported_format";
    });

    // 3. Code splitter — handles both smali methods and ELF functions
    auto split_methods = g.add<SplitterNode>("split_methods", [](TaskContext ctx) {
        auto contents = ctx.get("file_contents").get<std::string>();
        auto format = ctx.has("file_format") ? ctx.get("file_format").get<std::string>() : "smali";
        std::string scanGoal = ctx.has("scan_goal") ? ctx.get("scan_goal").get<std::string>() : "";

        std::vector<TaskContext> items;

        if (format == "elf") {
            std::string filePath = ctx.has("file_path") ? ctx.get("file_path").get<std::string>() : "";
            auto info = area::elf::disassemble(contents, fs::path(filePath).filename().string());

            std::string className = info.filename;

            // Build imports summary (analogous to fields_summary)
            std::ostringstream importsSummary;
            importsSummary << "Architecture: " << info.arch << "\n";
            importsSummary << "Type: " << info.type << "\n";
            if (!info.imports.empty()) {
                importsSummary << "Imported functions:\n";
                for (auto& imp : info.imports) {
                    importsSummary << "  " << imp << "\n";
                }
            }
            std::string imports = importsSummary.str();

            std::string formatCtx =
                "You are analyzing a disassembled function from a native ELF binary ("
                + info.arch + " architecture). Focus on system calls, C library functions, "
                "network operations (socket, connect, send, recv), file operations "
                "(open, read, write, mmap), process manipulation (fork, exec, ptrace), "
                "dynamic loading (dlopen, dlsym), and suspicious patterns like encoded "
                "strings or anti-debugging techniques. "
                "The \"api_calls\" field should list any library or system calls found.";

            for (auto& func : info.functions) {
                TaskContext item;
                item.set("class_name", className);
                item.set("source_file", className);
                item.set("scan_goal", scanGoal);
                item.set("method_name", func.name);
                char addrBuf[32];
                snprintf(addrBuf, sizeof(addrBuf), "0x%" PRIx64, func.address);
                item.set("method_signature",
                    std::string(addrBuf) + " (" + std::to_string(func.size) + " bytes)");
                item.set("method_body", func.disassembly);
                item.set("fields_summary", imports);
                item.set("format_context", formatCtx);
                items.push_back(std::move(item));
            }

            if (items.empty()) {
                TaskContext empty;
                empty.discarded = true;
                empty.discard_reason = "no_functions";
                items.push_back(std::move(empty));
            }
        } else {
            // Smali path
            auto parsed = area::smali::parse(contents);

            std::string className = parsed.class_name;
            std::string sourceFile = parsed.source_file;

            std::ostringstream fieldsSummary;
            for (auto& f : parsed.fields) {
                fieldsSummary << f.access << " " << f.name << ":" << f.type << "\n";
            }
            std::string fields = fieldsSummary.str();

            std::string formatCtx =
                "You are analyzing a single method from an Android application's "
                "smali bytecode (Dalvik VM). Focus on Android/Java API calls, intent "
                "handling, content provider access, broadcast receivers, service "
                "communication, reflection, dynamic class loading, and native method "
                "invocation.";

            for (auto& m : parsed.methods) {
                TaskContext item;
                item.set("class_name", className);
                item.set("source_file", sourceFile);
                item.set("scan_goal", scanGoal);
                item.set("method_name", m.name);
                item.set("method_signature", m.signature);
                item.set("method_body", m.body);
                item.set("fields_summary", fields);
                item.set("format_context", formatCtx);

                // Extract call graph edges from this method
                auto calls = area::smali::extractCalls(m.body);
                if (!calls.empty()) {
                    nlohmann::json callsJson = nlohmann::json::array();
                    for (auto& c : calls) {
                        callsJson.push_back({
                            {"invoke_type", c.invoke_type},
                            {"target_class", c.target_class},
                            {"target_method", c.target_method},
                            {"target_signature", c.target_signature}
                        });
                    }
                    item.set("method_calls", callsJson);
                }

                items.push_back(std::move(item));
            }
        }
        return items;
    });

    std::string triagePrompt = loadPrompt(prompts_dir + "/triage.prompt");
    std::string triageSupervisorPrompt = loadPrompt(prompts_dir + "/triage_supervisor.prompt");

    auto triage = g.add<SupervisedLLMCallNode>("triage",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = triagePrompt,
            .system_prompt = "You are a reverse engineering analyst. Analyze code with respect to the given scan goal. Output ONLY valid JSON, no markdown.",
            .supervisor_prompt = triageSupervisorPrompt,
            .max_retries = 1,
        },
        backends.at(1),
        backends.at(0),
        nullptr);

    auto filter = g.add<PredicateCodeNode>("filter_irrelevant", [](const TaskContext& ctx) -> bool {
        if (!ctx.has("llm_response")) return true;
        try {
            auto j = nlohmann::json::parse(extractJson(ctx.get("llm_response").get<std::string>()));
            bool relevant = j.value("relevant", false);
            auto confidence = j.value("confidence", 0.0);

            // Always pass through if marked relevant
            if (relevant) return true;

            // Pass through if triage found a non-trivial threat category
            std::string category = j.value("threat_category", "none");
            if (category != "none" && !category.empty()) return true;

            // Pass through if triage found API calls worth investigating
            if (j.contains("api_calls") && j["api_calls"].is_array() && !j["api_calls"].empty()) {
                // Only discard if confidently irrelevant AND has no interesting API calls
                return confidence < 0.85;
            }

            // Discard only if high confidence in irrelevance
            return confidence < 0.9;
        } catch (...) {
            return true;
        }
    });

    auto discard_irrelevant = g.add<ExitNode>("discard_irrelevant", [](TaskContext& ctx) {
        ctx.discard_reason = "not_relevant";
    });

    // RAG enrichment: query embedding DB for similar methods from past scans
    auto rag_enrich = g.add<CodeNode>("rag_enrich", [embeddingStore](TaskContext ctx) {
        // Build call graph context from extracted method_calls
        if (ctx.has("method_calls")) {
            try {
                auto calls = ctx.get("method_calls");
                if (calls.is_array() && !calls.empty()) {
                    std::ostringstream cg;
                    cg << "Methods called by this function:\n";
                    for (auto& c : calls) {
                        cg << "  " << c.value("invoke_type", "")
                           << " " << c.value("target_class", "")
                           << "->" << c.value("target_method", "")
                           << c.value("target_signature", "") << "\n";
                    }
                    ctx.set("call_graph_context", cg.str());
                } else {
                    ctx.set("call_graph_context", "");
                }
            } catch (...) {
                ctx.set("call_graph_context", "");
            }
        } else {
            ctx.set("call_graph_context", "");
        }

        if (!embeddingStore || !embeddingStore->hasBackend()) return ctx;

        std::string methodBody = ctx.has("method_body") ? ctx.get("method_body").get<std::string>() : "";
        std::string methodName = ctx.has("method_name") ? ctx.get("method_name").get<std::string>() : "";
        if (methodBody.empty()) return ctx;

        // Build query from method body (truncated) + triage findings
        std::string query = methodBody.substr(0, 1000);
        if (ctx.has("llm_response")) {
            try {
                auto j = nlohmann::json::parse(extractJson(ctx.get("llm_response").get<std::string>()));
                if (j.contains("findings")) {
                    for (auto& f : j["findings"]) {
                        query += "\n" + f.get<std::string>();
                    }
                }
            } catch (...) {}
        }

        try {
            auto results = embeddingStore->searchByText(query, 3);
            if (!results.empty()) {
                std::ostringstream rag;
                for (size_t i = 0; i < results.size(); i++) {
                    auto& r = results[i];
                    rag << "--- Similar method " << (i + 1)
                        << " (similarity=" << std::fixed << std::setprecision(2)
                        << r.similarity << ") ---\n"
                        << "Class: " << r.class_name << "\n"
                        << "Method: " << r.method_name << "\n"
                        << r.content.substr(0, 500) << "\n\n";
                }
                ctx.set("rag_context", rag.str());
            }
        } catch (...) {
            // Embedding search failure is non-fatal
        }
        return ctx;
    });

    std::string deepPrompt = loadPrompt(prompts_dir + "/deep_analysis.prompt");
    std::string deepSupervisorPrompt = loadPrompt(prompts_dir + "/deep_analysis_supervisor.prompt");

    auto deep_analysis = g.add<SupervisedLLMCallNode>("deep_analysis",
        SupervisedLLMCallConfig{
            .tier = 1,
            .prompt_template = deepPrompt,
            .system_prompt = "You are a senior reverse engineer. Analyze code with respect to the given scan goal. Be precise and evidence-based.",
            .supervisor_prompt = deepSupervisorPrompt,
            .max_retries = 2,
        },
        backends.at(2),
        backends.at(1),
        nullptr);

    auto collector = g.add<CollectorNode>("collect_results", [](std::vector<TaskContext> items) {
        TaskContext result;
        nlohmann::json collected = nlohmann::json::array();
        for (auto& item : items) {
            nlohmann::json entry;
            entry["method_name"] = item.has("method_name") ? item.get("method_name") : "";
            if (item.has("llm_response")) {
                try {
                    entry["analysis"] = nlohmann::json::parse(extractJson(item.get("llm_response").get<std::string>()));
                } catch (...) {
                    entry["analysis"] = item.get("llm_response");
                }
            }
            collected.push_back(std::move(entry));
        }
        result.set("collected", collected);
        if (!items.empty()) {
            if (items[0].has("class_name")) result.set("class_name", items[0].get("class_name"));
            if (items[0].has("source_file")) result.set("source_file", items[0].get("source_file"));
            if (items[0].has("scan_goal")) result.set("scan_goal", items[0].get("scan_goal"));
            if (items[0].has("format_context")) result.set("format_context", items[0].get("format_context"));
        }
        return result;
    });

    std::string synthesisPrompt = loadPrompt(prompts_dir + "/synthesis.prompt");
    std::string synthesisSupervisorPrompt = loadPrompt(prompts_dir + "/synthesis_supervisor.prompt");

    auto synthesize = g.add<SupervisedLLMCallNode>("synthesize",
        SupervisedLLMCallConfig{
            .tier = 0,
            .prompt_template = synthesisPrompt,
            .system_prompt = "You are a senior analyst producing final answers to scan goal questions. Output ONLY valid JSON, no markdown.",
            .supervisor_prompt = synthesisSupervisorPrompt,
            .max_retries = 1,
        },
        backends.at(2),
        backends.at(0),
        nullptr);

    auto risk_calc = g.add<CodeNode>("compute_risk", [](TaskContext ctx) {
        if (ctx.has("llm_response")) {
            try {
                auto j = nlohmann::json::parse(extractJson(ctx.get("llm_response").get<std::string>()));
                ctx.set("risk_profile", j);
            } catch (...) {
                ctx.set("risk_profile", ctx.get("llm_response"));
            }
        }
        return ctx;
    });

    g.edge(read_file, detect_format);
    g.branch(detect_format, "smali", split_methods);
    g.branch(detect_format, "elf", split_methods);
    g.branch(detect_format, "unsupported", unsupported);

    g.edge(split_methods, triage);
    g.branch(split_methods, "collect", collector);

    g.edge(triage, filter);
    g.branch(filter, "pass", rag_enrich);
    g.branch(filter, "fail", discard_irrelevant);
    g.edge(rag_enrich, deep_analysis);
    g.edge(collector, synthesize);
    g.edge(synthesize, risk_calc);

    g.setEntry(read_file);
    g.setOutput(risk_calc);

    return g;
}

} // namespace area::graph
