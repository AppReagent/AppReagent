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
    std::string escaped_type, escaped_payload;
    for (char c : type) { if (c == '\'') escaped_type += "''"; else escaped_type += c; }
    for (char c : payload) { if (c == '\'') escaped_payload += "''"; else escaped_payload += c; }

    std::string sql = "INSERT INTO jobs (type, tier, payload) VALUES ('" +
                      escaped_type + "', " + std::to_string(tier) + ", '" +
                      escaped_payload + "') RETURNING id";

    auto result = db_.execute(sql);
    if (!result.ok()) throw std::runtime_error("enqueue failed: " + result.error);
    if (result.rows.empty() || result.rows[0].empty())
        throw std::runtime_error("enqueue failed: no id returned");
    return std::stoll(result.rows[0][0]);
}

std::vector<Job> JobQueue::dequeue(int tier, int batch_size) {
    std::string sql = R"(
        UPDATE jobs
        SET status = 'in_progress', updated_at = now()
        WHERE id IN (
            SELECT id FROM jobs
            WHERE status = 'pending' AND tier = )" + std::to_string(tier) + R"(
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT )" + std::to_string(batch_size) + R"(
        )
        RETURNING id, type, payload, status, output, assigned_to, tier
    )";

    auto result = db_.execute(sql);
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
    std::string sql = R"(
        UPDATE jobs
        SET status = 'in_progress', updated_at = now()
        WHERE id IN (
            SELECT id FROM jobs
            WHERE status = 'pending' AND tier <= )" + std::to_string(tier) + R"(
            ORDER BY tier DESC, created_at
            FOR UPDATE SKIP LOCKED
            LIMIT )" + std::to_string(batch_size) + R"(
        )
        RETURNING id, type, payload, status, output, assigned_to, tier
    )";

    auto result = db_.execute(sql);
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
    std::string sql = "UPDATE jobs SET status = 'pending', assigned_to = NULL, "
                      "updated_at = now() WHERE id = " + std::to_string(job_id);
    db_.execute(sql);
}

void JobQueue::updateOutput(int64_t job_id, const std::string& chunk, bool append) {
    std::string escaped;
    for (char c : chunk) {
        if (c == '\'') escaped += "''";
        else escaped += c;
    }

    std::string sql;
    if (append) {
        sql = "UPDATE jobs SET output = output || '" + escaped +
              "', updated_at = now() WHERE id = " + std::to_string(job_id);
    } else {
        sql = "UPDATE jobs SET output = '" + escaped +
              "', updated_at = now() WHERE id = " + std::to_string(job_id);
    }
    db_.execute(sql);
}

void JobQueue::complete(int64_t job_id, const std::string& final_output) {
    std::string escaped;
    for (char c : final_output) {
        if (c == '\'') escaped += "''";
        else escaped += c;
    }

    std::string sql = "UPDATE jobs SET status = 'completed', output = '" + escaped +
                      "', updated_at = now() WHERE id = " + std::to_string(job_id);
    db_.execute(sql);
}

void JobQueue::fail(int64_t job_id, const std::string& error) {
    std::string escaped;
    for (char c : error) {
        if (c == '\'') escaped += "''";
        else escaped += c;
    }

    std::string sql = "UPDATE jobs SET status = 'failed', output = '" + escaped +
                      "', updated_at = now() WHERE id = " + std::to_string(job_id);
    db_.execute(sql);
}

} // namespace area
