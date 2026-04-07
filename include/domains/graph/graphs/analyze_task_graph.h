#pragma once

#include <string>

#include "domains/graph/engine/task_graph.h"
#include "domains/graph/graphs/scan_task_graph.h"
#include "infra/db/Database.h"
#include "infra/llm/Embedding.h"
#include "infra/llm/LLMBackend.h"

namespace area::graph {

// Build the analyze task graph. The graph takes scan results for a run_id,
// retrieves similar methods via RAG, and produces a deeper analysis.
//
// Graph: load_results → split_findings → rag_retrieve → analyze_finding
//        → collect_analyses → final_synthesis
TaskGraph buildAnalyzeTaskGraph(const TierBackends& backends,
                                Database& db,
                                EmbeddingStore* embeddingStore,
                                const std::string& prompts_dir = "prompts");

} // namespace area::graph
