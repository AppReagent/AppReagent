#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include "features/scan/ScanOutputFile.h"

namespace fs = std::filesystem;

class ScanOutputFileTest : public ::testing::Test {
protected:
    std::string tmpDir;

    void SetUp() override {
        tmpDir = "/tmp/test_scan_output_" + std::to_string(getpid());
        fs::create_directories(tmpDir);
        // ScanOutputFile::open creates "scan-outputs/" relative to cwd,
        // so we'll test load() with manually created files and open() separately.
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(tmpDir, ec);
        // Clean up scan-outputs dir created by open()
        fs::remove_all("scan-outputs", ec);
    }

    std::string writeTmpFile(const std::string& name, const std::string& content) {
        std::string path = tmpDir + "/" + name;
        std::ofstream f(path);
        f << content;
        return path;
    }
};

TEST_F(ScanOutputFileTest, LoadMetadata) {
    std::string jsonl =
        R"({"type":"metadata","run_id":"run-123","target_path":"/app","goal":"find malware"})" "\n"
        R"({"type":"file_result","file_hash":"abc123","risk":"high"})" "\n"
        R"({"type":"file_result","file_hash":"def456","risk":"low"})" "\n";

    auto path = writeTmpFile("test.jsonl", jsonl);
    auto result = area::ScanOutputFile::load(path);

    EXPECT_EQ(result.run_id, "run-123");
    EXPECT_EQ(result.target_path, "/app");
    EXPECT_EQ(result.goal, "find malware");
    EXPECT_EQ(result.completed_hashes.size(), 2);
    EXPECT_TRUE(result.completed_hashes.count("abc123"));
    EXPECT_TRUE(result.completed_hashes.count("def456"));
}

TEST_F(ScanOutputFileTest, LoadSkipsMalformedLines) {
    std::string jsonl =
        R"({"type":"metadata","run_id":"run-1","target_path":"/x"})" "\n"
        "this is not json\n"
        "\n"
        R"({"type":"file_result","file_hash":"h1"})" "\n";

    auto path = writeTmpFile("bad.jsonl", jsonl);
    auto result = area::ScanOutputFile::load(path);

    EXPECT_EQ(result.run_id, "run-1");
    EXPECT_EQ(result.completed_hashes.size(), 1);
    EXPECT_TRUE(result.completed_hashes.count("h1"));
}

TEST_F(ScanOutputFileTest, LoadEmptyFile) {
    auto path = writeTmpFile("empty.jsonl", "");
    auto result = area::ScanOutputFile::load(path);

    EXPECT_TRUE(result.run_id.empty());
    EXPECT_TRUE(result.target_path.empty());
    EXPECT_TRUE(result.completed_hashes.empty());
}

TEST_F(ScanOutputFileTest, LoadNonExistentFileThrows) {
    EXPECT_THROW(area::ScanOutputFile::load("/tmp/nonexistent_file_xyz.jsonl"), std::runtime_error);
}

TEST_F(ScanOutputFileTest, LoadFileResultWithoutHash) {
    std::string jsonl =
        R"({"type":"file_result","risk":"medium"})" "\n";

    auto path = writeTmpFile("nohash.jsonl", jsonl);
    auto result = area::ScanOutputFile::load(path);
    EXPECT_TRUE(result.completed_hashes.empty());
}

TEST_F(ScanOutputFileTest, OpenAndWriteMetadata) {
    area::ScanOutputFile sof;
    sof.open("test-run-001");

    EXPECT_EQ(sof.path(), "scan-outputs/test-run-001.jsonl");
    EXPECT_TRUE(fs::exists(sof.path()));

    sof.writeMetadata("/some/app", "test-run-001", "security audit");

    // Read back and verify
    auto result = area::ScanOutputFile::load(sof.path());
    EXPECT_EQ(result.run_id, "test-run-001");
    EXPECT_EQ(result.target_path, "/some/app");
    EXPECT_EQ(result.goal, "security audit");
}

TEST_F(ScanOutputFileTest, WriteFileResult) {
    area::ScanOutputFile sof;
    sof.open("test-run-002");

    nlohmann::json profile = {{"network", 8}, {"crypto", 3}};
    sof.writeFileResult("/app/Net.smali", "sha256abc", "high", 85,
                        "Review network calls", profile, 1234.5);

    auto result = area::ScanOutputFile::load(sof.path());
    EXPECT_EQ(result.completed_hashes.size(), 1);
    EXPECT_TRUE(result.completed_hashes.count("sha256abc"));

    // Verify full JSON content
    std::ifstream f(sof.path());
    std::string line;
    std::getline(f, line);
    auto j = nlohmann::json::parse(line);
    EXPECT_EQ(j["type"], "file_result");
    EXPECT_EQ(j["risk"], "high");
    EXPECT_EQ(j["risk_score"], 85);
    EXPECT_EQ(j["recommendation"], "Review network calls");
    EXPECT_DOUBLE_EQ(j["elapsed_ms"].get<double>(), 1234.5);
}

TEST_F(ScanOutputFileTest, WriteLLMCall) {
    area::ScanOutputFile sof;
    sof.open("test-run-003");

    sof.writeLLMCall("/app/Foo.smali", "hashFoo", "triage",
                     "Analyze this method", "Low risk", 567.8);

    std::ifstream f(sof.path());
    std::string line;
    std::getline(f, line);
    auto j = nlohmann::json::parse(line);
    EXPECT_EQ(j["type"], "llm_call");
    EXPECT_EQ(j["node"], "triage");
    EXPECT_EQ(j["prompt"], "Analyze this method");
    EXPECT_EQ(j["response"], "Low risk");
}

TEST_F(ScanOutputFileTest, WriteSynthesis) {
    area::ScanOutputFile sof;
    sof.open("test-run-004");

    nlohmann::json parsed = {{"overall_risk", "medium"}, {"score", 55}};
    sof.writeSynthesis("Raw synthesis text", parsed);

    std::ifstream f(sof.path());
    std::string line;
    std::getline(f, line);
    auto j = nlohmann::json::parse(line);
    EXPECT_EQ(j["type"], "scan_synthesis");
    EXPECT_EQ(j["raw_response"], "Raw synthesis text");
    EXPECT_EQ(j["parsed"]["overall_risk"], "medium");
    EXPECT_EQ(j["parsed"]["score"], 55);
}

TEST_F(ScanOutputFileTest, WriteMetadataWithoutGoal) {
    area::ScanOutputFile sof;
    sof.open("test-run-005");
    sof.writeMetadata("/app", "test-run-005");

    std::ifstream f(sof.path());
    std::string line;
    std::getline(f, line);
    auto j = nlohmann::json::parse(line);
    EXPECT_EQ(j["type"], "metadata");
    EXPECT_EQ(j["run_id"], "test-run-005");
    EXPECT_FALSE(j.contains("goal")); // goal omitted when empty
}

TEST_F(ScanOutputFileTest, MultipleWritesAppend) {
    area::ScanOutputFile sof;
    sof.open("test-run-006");

    sof.writeMetadata("/app", "test-run-006");
    nlohmann::json empty_profile = {};
    sof.writeFileResult("/a.smali", "h1", "low", 10, "ok", empty_profile, 100);
    sof.writeFileResult("/b.smali", "h2", "high", 90, "bad", empty_profile, 200);

    auto result = area::ScanOutputFile::load(sof.path());
    EXPECT_EQ(result.run_id, "test-run-006");
    EXPECT_EQ(result.completed_hashes.size(), 2);

    // Count lines
    std::ifstream f(sof.path());
    int lineCount = 0;
    std::string line;
    while (std::getline(f, line)) lineCount++;
    EXPECT_EQ(lineCount, 3); // metadata + 2 file results
}
