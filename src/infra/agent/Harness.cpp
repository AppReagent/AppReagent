#include "infra/agent/Harness.h"

#include <stddef.h>
#include <algorithm>
#include <sstream>
#include <cctype>

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
        "FORMAT — every response must be exactly:\n"
        "\n"
        "THOUGHT: <reasoning>\n"
        "ACTION: <tool call>\n"
        "\n"
        "Or when done:\n"
        "\n"
        "THOUGHT: <evidence summary>\n"
        "ANSWER: <complete answer citing specific methods, classes, and code>\n"
        "\n"
        "APPROACH — think like a reverse engineer:\n"
        "1. Understand the question. Is the user asking about behavior, structure, data flow, or risk?\n"
        "2. Look at the code first. READ the file before scanning it. Scans are expensive; reading is cheap.\n"
        "3. For questions about existing scans, query the database (SQL) before re-scanning.\n"
        "4. Trace call chains. Interesting behavior is often split across classes.\n"
        "5. Build evidence. Cite specific methods, API calls, and string constants.\n"
        "6. Only ANSWER when you have concrete evidence from the code itself.\n"
        "\n"
        "PERSISTENCE — don't stop prematurely:\n"
        "- After a scan, ALWAYS query method_findings and scan_results to examine what was found\n"
        "- After finding a suspicious method, trace its callers and callees with CALLGRAPH/XREFS\n"
        "- DECOMPILE the most interesting methods to read actual code before answering\n"
        "- Cross-reference across multiple files before concluding\n"
        "- If a scan finds nothing, READ the code directly — the scan may have missed context\n"
        "- A good investigation typically takes 5-10 tool calls. If you've only used 1-2, keep going.\n"
        "- When you receive a tool observation, your default should be to use ANOTHER tool, not to ANSWER.\n"
        "\n"
        "CONVERGENCE — know when you have enough evidence:\n"
        "- Once you have 2+ independent evidence sources pointing the same way, you can answer\n"
        "- If 3+ tool calls return no results for a behavior, it likely doesn't exist — say so\n"
        "- Don't repeat the same tool with the same input — try a different approach\n"
        "- Cite specific evidence (class names, method names, API calls) in every answer\n"
    });

    h.addGuide({"tool_strategy",
        "TOOL SELECTION — pick the right tool for the question:\n"
        "\n"
        "  'What does this code do?' → READ the file, then explain\n"
        "  'Is this app malicious?' → SCAN with a specific goal\n"
        "  'What were the results?' → SQL query on scan_results or method_findings\n"
        "  'What calls sendSMS?' → CALLGRAPH to trace callers\n"
        "  'Find network code' → FIND to search method findings by behavior\n"
        "  'Show me similar patterns' → SIMILAR for embedding-based semantic search\n"
        "  'Where is file X?' → FIND_FILES to locate it on disk\n"
        "\n"
        "ITERATIVE DEEPENING — start broad and cheap, then narrow and deepen:\n"
        "  Level 1 (instant): FIND_FILES, READ, STRINGS — understand what you're looking at\n"
        "  Level 2 (fast): GREP, XREFS, MANIFEST, CLASSES — find patterns and connections\n"
        "  Level 3 (medium): DECOMPILE, CALLGRAPH, SQL — understand behavior and data flow\n"
        "  Level 4 (expensive): SCAN with specific goal — LLM-powered deep analysis\n"
        "  Level 5 (synthesis): FIND, SIMILAR, REPORT — cross-reference and synthesize\n"
        "\n"
        "Each level should inform the next. Don't jump to SCAN without first understanding "
        "the code structure (CLASSES), checking permissions (MANIFEST), and extracting "
        "strings (STRINGS). These cheap tools help you write better scan goals.\n"
        "\n"
        "COMBINING TOOLS for maximum insight:\n"
        "  STRINGS → GREP: Find a suspicious string, then search for all code that uses it\n"
        "  MANIFEST → GREP: See dangerous permissions, then find the code that uses them\n"
        "  GREP → XREFS: Find an API call, then trace who invokes it\n"
        "  XREFS → DECOMPILE: Find callers, then read their logic\n"
        "  SCAN → SQL: Run analysis, then query detailed per-method findings\n"
        "  FIND → SIMILAR: Search behavioral findings, then find similar patterns\n"
        "\n"
        "When a tool returns an error:\n"
        "  SQL errors: check the error message, verify table/column names with information_schema\n"
        "  Scan errors: verify path exists (FIND_FILES), check it contains .smali or ELF files\n"
        "  File not found: use FIND_FILES to locate the actual path\n"
        "  No results: try different search terms, broader patterns, or a different tool\n"
    });

    h.addGuide({"investigation_depth",
        "DEEP INVESTIGATION — avoid shallow answers.\n"
        "\n"
        "COMMON MISTAKES TO AVOID:\n"
        "1. Answering after only one tool call. Most questions need 3-5 tool calls minimum.\n"
        "2. Reporting scan summary without querying method_findings for details.\n"
        "3. Saying 'no malicious behavior found' without checking STRINGS, MANIFEST, and GREP.\n"
        "4. Stopping at the first suspicious method without tracing its callers via XREFS.\n"
        "5. Scanning a whole directory when the user asked about one specific behavior — use GREP first.\n"
        "\n"
        "AFTER A SCAN COMPLETES — always do this before answering:\n"
        "  SQL: SELECT class_name, method_name, threat_category, findings, confidence "
        "FROM method_findings WHERE run_id = '<run_id>' AND relevant = true "
        "ORDER BY confidence DESC\n"
        "  SQL: SELECT risk_score, recommendation, risk_profile FROM scan_results WHERE run_id = '<run_id>'\n"
        "  Then: DECOMPILE the top suspicious methods to verify findings with actual code.\n"
        "\n"
        "WHEN STUCK or results are inconclusive:\n"
        "1. Try a different tool (GREP for patterns SCAN might miss, STRINGS for hardcoded data)\n"
        "2. Broaden the search (XREFS on the suspicious class, not just the method)\n"
        "3. Check related files (use FIND_FILES to find other classes in the same package)\n"
        "4. Query past scans (SQL on method_findings for similar threat_category)\n"
        "5. If nothing works, clearly state what was checked and what was NOT found — don't guess.\n"
        "\n"
        "EVIDENCE QUALITY — rank your evidence:\n"
        "- STRONG: Direct API call to malicious sink (SmsManager.sendTextMessage with hardcoded number)\n"
        "- MODERATE: Security-sensitive API in suspicious context (HTTP POST in a Service started at boot)\n"
        "- WEAK: API that could be benign (HttpURLConnection in a class without other suspicious calls)\n"
        "- Report the evidence strength in your answer.\n"
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

    h.addGuide({"autonomous_workflow",
        "AUTONOMOUS OPERATION — you are a self-directed investigator.\n"
        "\n"
        "After every tool observation, ask yourself:\n"
        "- Do I have enough evidence to give a thorough, concrete answer?\n"
        "- What is the most important thing I haven't checked yet?\n"
        "- Are there suspicious patterns that deserve follow-up?\n"
        "\n"
        "If the answer to the first question is NO, keep investigating. Do NOT answer prematurely.\n"
        "\n"
        "SCAN FOLLOW-UP PROTOCOL (always do this after a scan completes):\n"
        "1. SQL: SELECT class_name, method_name, risk_label, threat_category, confidence "
        "FROM method_findings WHERE run_id = '<run_id>' AND risk_label != 'not_relevant' "
        "ORDER BY confidence DESC LIMIT 20\n"
        "2. For the top suspicious methods: DECOMPILE or DISASM to read the actual code\n"
        "3. CALLGRAPH or XREFS to trace how the suspicious code connects to entry points\n"
        "4. Only then synthesize your findings into a comprehensive ANSWER\n"
        "\n"
        "GOAL DECOMPOSITION — for complex questions, break into sub-tasks:\n"
        "- 'Is this app malicious?' → recon (CLASSES, MANIFEST) → triage (STRINGS, GREP) → "
        "deep analysis (SCAN) → verification (SQL, DECOMPILE) → correlation (XREFS, CALLGRAPH)\n"
        "- 'Trace the data flow' → find sources (GREP) → find sinks (GREP) → "
        "connect them (XREFS, CALLGRAPH) → read the code (DECOMPILE)\n"
        "- 'What does this app do?' → structure (CLASSES) → entry points (MANIFEST) → "
        "key methods (DECOMPILE) → strings/resources (STRINGS)\n"
    });

    h.addSensor({"sql_read_only", "sql",
        [](const std::string& action, const std::string&) -> std::string {
            std::string upper;
            for (size_t i = 0; i < std::min(action.size(), static_cast<size_t>(20)); i++)
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
                return "HINT: Table or column not found. Try: "
                       "SELECT table_name FROM information_schema.tables "
                       "WHERE table_schema='public'";
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

    h.addSensor({"answer_evidence", "answer",
        [](const std::string& answer, const std::string&) -> std::string {
            bool mentionsScan = answer.find("scan") != std::string::npos ||
                                answer.find("Scan") != std::string::npos ||
                                answer.find("SCAN") != std::string::npos;
            bool mentionsResults = answer.find("result") != std::string::npos ||
                                  answer.find("found") != std::string::npos ||
                                  answer.find("detected") != std::string::npos;
            bool citesEvidence = answer.find("class") != std::string::npos ||
                                answer.find("method") != std::string::npos ||
                                answer.find("Class") != std::string::npos ||
                                answer.find("Method") != std::string::npos ||
                                answer.find("->") != std::string::npos ||
                                answer.find("invoke") != std::string::npos ||
                                answer.find("Lcom/") != std::string::npos ||
                                answer.find("Ljava/") != std::string::npos ||
                                answer.find("Landroid/") != std::string::npos;
            bool citesScore = answer.find("risk_score") != std::string::npos ||
                              answer.find("risk score") != std::string::npos ||
                              answer.find("confidence") != std::string::npos ||
                              answer.find("relevant") != std::string::npos ||
                              answer.find("not_relevant") != std::string::npos;
            bool isNegative = answer.find("no malicious") != std::string::npos ||
                              answer.find("no suspicious") != std::string::npos ||
                              answer.find("benign") != std::string::npos ||
                              answer.find("not_relevant") != std::string::npos;

            if (mentionsScan && mentionsResults && !citesEvidence && !citesScore && !isNegative) {
                return "Your answer mentions scan results but doesn't cite specific classes, methods, "
                       "or risk scores. Query method_findings and scan_results for the run_id to get "
                       "concrete evidence before answering.";
            }
            return "";
        }
    });

    h.addSensor({"answer_completeness", "answer",
        [](const std::string& answer, const std::string&) -> std::string {
            if (answer.find("Scan ") != std::string::npos &&
                answer.find("complete:") != std::string::npos &&
                answer.find("method_findings") == std::string::npos &&
                answer.find("DECOMPILE") == std::string::npos &&
                answer.find("class_name") == std::string::npos) {
                return "You appear to be reporting a raw scan summary. Follow the "
                       "SCAN FOLLOW-UP PROTOCOL: query method_findings for details, "
                       "DECOMPILE suspicious methods, then give a thorough answer.";
            }
            return "";
        }
    });

    h.addSensor({"scan_followup", "scan",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("complete:") != std::string::npos) {
                auto pos = observation.find("Scan ");
                auto end = observation.find(" complete:");
                if (pos != std::string::npos && end != std::string::npos) {
                    std::string runId = observation.substr(pos + 5, end - pos - 5);
                    return "NEXT STEP: Query the database for detailed findings. Run: "
                           "SQL: SELECT class_name, method_name, risk_label, threat_category, "
                           "confidence FROM method_findings WHERE run_id = '" + runId +
                           "' AND risk_label != 'not_relevant' ORDER BY confidence DESC LIMIT 20";
                }
            }
            return "";
        }
    });

    h.addSensor({"file_not_found", "read",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("No such file") != std::string::npos ||
                observation.find("not found") != std::string::npos ||
                observation.find("does not exist") != std::string::npos) {
                return "HINT: File not found. Use FIND_FILES to locate the correct path. "
                       "Common causes: wrong directory, missing .smali extension, "
                       "path needs expanding (~ → /home/user).";
            }
            return "";
        }
    });

    h.addSensor({"scan_no_findings", "scan",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("Relevant: 0") != std::string::npos &&
                observation.find("Partially relevant: 0") != std::string::npos) {
                return "HINT: Scan found nothing relevant. Consider: "
                       "(1) READ the file directly to inspect the code manually, "
                       "(2) Use STRINGS to check for hardcoded indicators, "
                       "(3) Re-scan with a more specific or different goal, "
                       "(4) Use GREP to search for specific API patterns.";
            }
            return "";
        }
    });

    h.addSensor({"grep_no_results", "grep",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("No matches") != std::string::npos ||
                observation.find("0 matches") != std::string::npos) {
                return "HINT: No matches found. Try: "
                       "(1) Broaden the search pattern (partial class/method name), "
                       "(2) Use FIND_FILES to verify the search directory is correct, "
                       "(3) Try related API names (e.g., OkHttp instead of HttpURLConnection).";
            }
            return "";
        }
    });

    h.addSensor({"xrefs_no_results", "xrefs",
        [](const std::string&, const std::string& observation) -> std::string {
            if (observation.find("No cross-references") != std::string::npos ||
                observation.find("not found") != std::string::npos) {
                return "HINT: No xrefs found. The target may not be referenced in scanned files. "
                       "Try GREP for the class/method name as a string, or CALLGRAPH if scan data exists.";
            }
            return "";
        }
    });

    return h;
}
}  // namespace area
