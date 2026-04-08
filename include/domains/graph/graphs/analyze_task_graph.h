#pragma once

#include <string>

#include "domains/graph/engine/task_graph.h"
#include "domains/graph/graphs/scan_task_graph.h"
#include "infra/db/Database.h"
#include "infra/llm/Embedding.h"

namespace area::graph {

TaskGraph buildAnalyzeTaskGraph(const TierBackends& backends,
                                Database& db,
                                EmbeddingStore* embeddingStore,
                                const std::string& prompts_dir = "prompts");

}
