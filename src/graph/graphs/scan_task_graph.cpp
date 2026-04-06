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

    // Pre-triage obfuscation analysis: extract indicators the LLM should know about
    auto obfuscation_enrich = g.add<CodeNode>("obfuscation_enrich", [](TaskContext ctx) {
        if (!ctx.has("method_body")) return ctx;
        std::string body = ctx.get("method_body").get<std::string>();

        // Convert to lowercase for matching
        std::string bodyLower = body;
        for (auto& c : bodyLower) c = std::tolower(static_cast<unsigned char>(c));

        std::vector<std::string> indicators;

        // XOR operations — common string decryption pattern
        if (bodyLower.find("xor-int") != std::string::npos) {
            indicators.push_back("XOR arithmetic operations detected — common in string decryption/obfuscation routines");
        }

        // Reflection chain
        bool hasForName = bodyLower.find("class;->forname") != std::string::npos;
        bool hasGetMethod = bodyLower.find("getmethod") != std::string::npos ||
                            bodyLower.find("getdeclaredmethod") != std::string::npos;
        bool hasInvoke = bodyLower.find("method;->invoke") != std::string::npos;
        if (hasForName || hasGetMethod || hasInvoke) {
            std::string detail = "Reflection chain:";
            if (hasForName) detail += " Class.forName()";
            if (hasGetMethod) detail += " getMethod/getDeclaredMethod()";
            if (hasInvoke) detail += " Method.invoke()";
            detail += " — hides actual API being called";
            indicators.push_back(detail);
        }

        // Dynamic class loading
        if (bodyLower.find("dexclassloader") != std::string::npos ||
            bodyLower.find("pathclassloader") != std::string::npos ||
            bodyLower.find("inmemorydexclassloader") != std::string::npos) {
            indicators.push_back("Dynamic class loader usage — can load arbitrary code at runtime");
        }

        // StringBuilder chains (URL/string construction)
        {
            size_t appendCount = 0;
            size_t pos = 0;
            while ((pos = bodyLower.find("append", pos)) != std::string::npos) {
                appendCount++;
                pos += 6;
            }
            if (appendCount >= 3) {
                indicators.push_back("Multiple StringBuilder.append() calls (" +
                    std::to_string(appendCount) + ") — may be constructing URLs, class names, or commands from fragments");
            }
        }

        // Byte array → String conversion (encrypted string pattern)
        if ((bodyLower.find("new-array") != std::string::npos || bodyLower.find("fill-array") != std::string::npos) &&
            bodyLower.find("ljava/lang/string;-><init>") != std::string::npos) {
            indicators.push_back("Byte/char array converted to String — pattern used in string decryption routines");
        }

        // Native method bridge
        if (bodyLower.find("loadlibrary") != std::string::npos) {
            indicators.push_back("System.loadLibrary() — native code bridge, behavior hidden in .so binary");
        }

        // Anti-analysis checks
        {
            std::vector<std::string> antiChecks;
            if (bodyLower.find("build;->fingerprint") != std::string::npos ||
                bodyLower.find("build;->model") != std::string::npos ||
                bodyLower.find("build;->product") != std::string::npos)
                antiChecks.push_back("device fingerprint checks");
            if (bodyLower.find("isdebuggerconnected") != std::string::npos)
                antiChecks.push_back("debugger detection");
            if (bodyLower.find("tracerpid") != std::string::npos)
                antiChecks.push_back("ptrace detection");
            if (!antiChecks.empty()) {
                std::string detail = "Anti-analysis techniques: ";
                for (size_t i = 0; i < antiChecks.size(); i++) {
                    if (i > 0) detail += ", ";
                    detail += antiChecks[i];
                }
                detail += " — code may behave differently under analysis";
                indicators.push_back(detail);
            }
        }

        // setAccessible — bypassing access control
        if (bodyLower.find("setaccessible") != std::string::npos) {
            indicators.push_back("setAccessible(true) — bypassing Java access control to invoke private/hidden APIs");
        }

        // Intent-based data passing with custom actions
        if (bodyLower.find("sendbroadcast") != std::string::npos ||
            bodyLower.find("startservice") != std::string::npos) {
            if (bodyLower.find("putextra") != std::string::npos) {
                indicators.push_back("Data packed into Intent extras and sent via broadcast/service — potential IPC-based exfiltration");
            }
        }

        // Time-delayed execution
        if (bodyLower.find("postdelayed") != std::string::npos ||
            bodyLower.find("alarmmanager") != std::string::npos ||
            bodyLower.find("jobscheduler") != std::string::npos) {
            indicators.push_back("Delayed/scheduled execution — payload may activate after a time delay");
        }

        if (!indicators.empty()) {
            std::ostringstream enrichment;
            enrichment << "\n\n⚠ OBFUSCATION INDICATORS DETECTED in this method:\n";
            for (auto& ind : indicators) {
                enrichment << "• " << ind << "\n";
            }
            enrichment << "\nThese patterns suggest the method is HIDING its true behavior. "
                       << "Analyze the obfuscation carefully and try to determine what the code actually does when executed.\n";

            // Append to method_body so the triage LLM sees it
            std::string existingBody = ctx.get("method_body").get<std::string>();
            ctx.set("method_body", existingBody + enrichment.str());
        }

        return ctx;
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

    g.edge(split_methods, obfuscation_enrich);
    g.branch(split_methods, "collect", collector);
    g.edge(obfuscation_enrich, triage);

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
