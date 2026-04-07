#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "infra/db/Database.h"

namespace area {

struct Job {
    int64_t id = 0;
    std::string type;       // e.g. "code_scan"
    std::string payload;    // json blob with prompt/file info
    std::string status;     // pending, in_progress, completed, failed
    std::string output;
    std::string assigned_to; // endpoint id
    int tier = 0;           // 0 = low, 1 = medium, 2 = high
};

class JobQueue {
public:
    explicit JobQueue(Database& db);

    void ensureTable();
    int64_t enqueue(const std::string& type, const std::string& payload, int tier);
    // Dequeue jobs at exactly this tier
    std::vector<Job> dequeue(int tier, int batch_size);
    // Dequeue jobs at this tier or below (for overflow: higher servers take lower work)
    std::vector<Job> dequeueAtOrBelow(int tier, int batch_size);
    void requeue(int64_t job_id);
    void updateOutput(int64_t job_id, const std::string& output_chunk, bool append = true);
    void complete(int64_t job_id, const std::string& final_output);
    void fail(int64_t job_id, const std::string& error);

private:
    Database& db_;
};

} // namespace area
