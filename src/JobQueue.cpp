#include "JobQueue.h"

#include <stdexcept>

namespace area {

JobQueue::JobQueue(Database& db) : db_(db) {}

void JobQueue::ensureTable() {
    db_.execute(R"(
        CREATE TABLE IF NOT EXISTS jobs (
            id          BIGSERIAL PRIMARY KEY,
            type        TEXT NOT NULL DEFAULT 'code_scan',
            tier        INTEGER NOT NULL DEFAULT 0,
            payload     JSONB NOT NULL DEFAULT '{}',
            status      TEXT NOT NULL DEFAULT 'pending',
            output      TEXT NOT NULL DEFAULT '',
            assigned_to TEXT,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    )");
    db_.execute(R"(
        CREATE INDEX IF NOT EXISTS idx_jobs_pending_tier
        ON jobs (tier, created_at) WHERE status = 'pending'
    )");
}

int64_t JobQueue::enqueue(const std::string& type, const std::string& payload, int tier) {
    auto result = db_.executeParams(
        "INSERT INTO jobs (type, tier, payload) VALUES ($1, $2, $3) RETURNING id",
        {type, std::to_string(tier), payload});
    if (!result.ok()) throw std::runtime_error("enqueue failed: " + result.error);
    if (result.rows.empty() || result.rows[0].empty())
        throw std::runtime_error("enqueue failed: no id returned");
    return std::stoll(result.rows[0][0]);
}

std::vector<Job> JobQueue::dequeue(int tier, int batch_size) {
    auto result = db_.executeParams(R"(
        UPDATE jobs
        SET status = 'in_progress', updated_at = now()
        WHERE id IN (
            SELECT id FROM jobs
            WHERE status = 'pending' AND tier = $1
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT $2
        )
        RETURNING id, type, payload, status, output, assigned_to, tier
    )", {std::to_string(tier), std::to_string(batch_size)});
    std::vector<Job> jobs;

    if (!result.ok()) {
        throw std::runtime_error("dequeue failed: " + result.error);
    }

    for (auto& row : result.rows) {
        Job j;
        j.id = std::stoll(row[0]);
        j.type = row[1];
        j.payload = row[2];
        j.status = row[3];
        j.output = row[4];
        j.assigned_to = row[5];
        j.tier = std::stoi(row[6]);
        jobs.push_back(std::move(j));
    }
    return jobs;
}

std::vector<Job> JobQueue::dequeueAtOrBelow(int tier, int batch_size) {
    // Grab pending jobs at this tier or any lower tier, prioritizing
    // the server's own tier first, then lower tiers by descending order
    auto result = db_.executeParams(R"(
        UPDATE jobs
        SET status = 'in_progress', updated_at = now()
        WHERE id IN (
            SELECT id FROM jobs
            WHERE status = 'pending' AND tier <= $1
            ORDER BY tier DESC, created_at
            FOR UPDATE SKIP LOCKED
            LIMIT $2
        )
        RETURNING id, type, payload, status, output, assigned_to, tier
    )", {std::to_string(tier), std::to_string(batch_size)});
    std::vector<Job> jobs;

    if (!result.ok()) {
        throw std::runtime_error("dequeue failed: " + result.error);
    }

    for (auto& row : result.rows) {
        Job j;
        j.id = std::stoll(row[0]);
        j.type = row[1];
        j.payload = row[2];
        j.status = row[3];
        j.output = row[4];
        j.assigned_to = row[5];
        j.tier = std::stoi(row[6]);
        jobs.push_back(std::move(j));
    }
    return jobs;
}

void JobQueue::requeue(int64_t job_id) {
    db_.executeParams("UPDATE jobs SET status = 'pending', assigned_to = NULL, "
                      "updated_at = now() WHERE id = $1",
                      {std::to_string(job_id)});
}

void JobQueue::updateOutput(int64_t job_id, const std::string& chunk, bool append) {
    if (append) {
        db_.executeParams("UPDATE jobs SET output = output || $1, "
                          "updated_at = now() WHERE id = $2",
                          {chunk, std::to_string(job_id)});
    } else {
        db_.executeParams("UPDATE jobs SET output = $1, "
                          "updated_at = now() WHERE id = $2",
                          {chunk, std::to_string(job_id)});
    }
}

void JobQueue::complete(int64_t job_id, const std::string& final_output) {
    db_.executeParams("UPDATE jobs SET status = 'completed', output = $1, "
                      "updated_at = now() WHERE id = $2",
                      {final_output, std::to_string(job_id)});
}

void JobQueue::fail(int64_t job_id, const std::string& error) {
    db_.executeParams("UPDATE jobs SET status = 'failed', output = $1, "
                      "updated_at = now() WHERE id = $2",
                      {error, std::to_string(job_id)});
}

} // namespace area
