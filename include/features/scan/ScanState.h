#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace area {
struct ActiveScan {
    std::string run_id;
    std::string chat_id;
    std::string path;
    std::string goal;
    int files_total = 0;
    int files_scanned = 0;
    std::chrono::steady_clock::time_point started;
    std::shared_ptr<std::atomic<bool>> interrupt;
};

struct PausedScan {
    std::string run_id;
    std::string path;
    std::string goal;
    int files_total = 0;
    int files_scanned = 0;
    std::string jsonl_path;
};

class ScanState {
 public:
    std::shared_ptr<std::atomic<bool>> start(const ActiveScan& scan) {
        std::lock_guard lk(mu_);
        auto flag = std::make_shared<std::atomic<bool>>(false);
        ActiveScan s = scan;
        s.interrupt = flag;
        scans_[scan.run_id] = s;
        return flag;
    }

    void update(const std::string& run_id, int files_scanned, int files_total = -1) {
        std::lock_guard lk(mu_);
        auto it = scans_.find(run_id);
        if (it != scans_.end()) {
            it->second.files_scanned = files_scanned;
            if (files_total >= 0) it->second.files_total = files_total;
        }
    }

    void finish(const std::string& run_id) {
        std::lock_guard lk(mu_);
        scans_.erase(run_id);
    }

    bool pause(const std::string& run_id, const std::string& jsonl_path) {
        std::lock_guard lk(mu_);
        auto it = scans_.find(run_id);
        if (it == scans_.end()) return false;

        if (it->second.interrupt) it->second.interrupt->store(true);

        paused_[run_id] = {
            run_id, it->second.path, it->second.goal,
            it->second.files_total, it->second.files_scanned,
            jsonl_path
        };

        return true;
    }

    bool getPaused(const std::string& run_id, PausedScan& out) const {
        std::lock_guard lk(mu_);
        auto it = paused_.find(run_id);
        if (it == paused_.end()) return false;
        out = it->second;
        return true;
    }

    void removePaused(const std::string& run_id) {
        std::lock_guard lk(mu_);
        paused_.erase(run_id);
    }

    std::vector<ActiveScan> active() const {
        std::lock_guard lk(mu_);
        std::vector<ActiveScan> result;
        for (auto& [_, s] : scans_) result.push_back(s);
        return result;
    }

    std::vector<PausedScan> paused() const {
        std::lock_guard lk(mu_);
        std::vector<PausedScan> result;
        for (auto& [_, s] : paused_) result.push_back(s);
        return result;
    }

    std::string summary() const {
        auto act = active();
        auto pau = paused();
        if (act.empty() && pau.empty()) return "No active or paused scans.";
        std::string out;
        for (auto& s : act) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - s.started).count();
            out += "[running] Scan " + s.run_id + " in chat '" + s.chat_id + "':\n"
                 + "  Path: " + s.path + "\n"
                 + "  Goal: " + s.goal + "\n"
                 + "  Progress: " + std::to_string(s.files_scanned) + "/" + std::to_string(s.files_total) + " files\n"
                 + "  Elapsed: " + std::to_string(elapsed) + "s\n";
        }
        for (auto& s : pau) {
            out += "[paused] Scan " + s.run_id + ":\n"
                 + "  Path: " + s.path + "\n"
                 + "  Goal: " + s.goal + "\n"
                 + "  Progress: " + std::to_string(s.files_scanned) + "/" + std::to_string(s.files_total) + " files\n";
        }
        return out;
    }

 private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, ActiveScan> scans_;
    std::unordered_map<std::string, PausedScan> paused_;
};
}  // namespace area
