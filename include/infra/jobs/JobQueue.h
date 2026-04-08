#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "infra/db/Database.h"

namespace area {

struct Job {
    int64_t id = 0;
    std::string type;
    std::string payload;
    std::string status;
    std::string output;
    std::string assigned_to;
    int tier = 0;
};

class JobQueue {
 public:
    explicit JobQueue(Database& db);

    void ensureTable();
    int64_t enqueue(const std::string& type, const std::string& payload, int tier);

    std::vector<Job> dequeue(int tier, int batch_size);

    std::vector<Job> dequeueAtOrBelow(int tier, int batch_size);
    void requeue(int64_t job_id);
    void updateOutput(int64_t job_id, const std::string& output_chunk, bool append = true);
    void complete(int64_t job_id, const std::string& final_output);
    void fail(int64_t job_id, const std::string& error);

 private:
    Database& db_;
};

}  // namespace area
