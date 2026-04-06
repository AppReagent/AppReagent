#pragma once

#include <string>

#include "graph/engine/task_graph.h"
#include "graph/graphs/scan_task_graph.h"
#include "Database.h"
#include "Embedding.h"
#include "LLMBackend.h"

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
