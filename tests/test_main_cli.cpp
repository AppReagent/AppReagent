#include <gtest/gtest.h>

#include <array>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <sys/wait.h>
#include <vector>

#include "util/file_io.h"

namespace fs = std::filesystem;

namespace {
struct CommandResult {
    int exitCode = -1;
    std::string output;
};

CommandResult runShellCommand(const std::string& command) {
    std::array<char, 4096> buffer{};
    std::string output;
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) return {-1, ""};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    int status = pclose(pipe);
    int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : status;
    return {exitCode, output};
}
}  // namespace

TEST(MainCli, GhidraCommandDoesNotRequireDatabaseConnection) {
    auto self = area::util::selfExe();
    if (self.empty()) GTEST_SKIP() << "test binary path unavailable";

    auto binary = fs::path(self).parent_path() / "area";
    if (!fs::exists(binary)) GTEST_SKIP() << "area binary not found";

    std::string dirTemplate = (fs::temp_directory_path() / "area-main-cli-XXXXXX").string();
    std::vector<char> dirBuffer(dirTemplate.begin(), dirTemplate.end());
    dirBuffer.push_back('\0');
    char* dataDirRaw = mkdtemp(dirBuffer.data());
    ASSERT_NE(dataDirRaw, nullptr);
    fs::path dataDir(dataDirRaw);

    std::ofstream(dataDir / "config.json")
        << "{\n"
        << "  \"postgres_url\": \"postgresql://127.0.0.1:1/area\",\n"
        << "  \"postgres_cert\": \"\",\n"
        << "  \"ai_endpoints\": []\n"
        << "}\n";

    auto oldAreaDataDir = std::getenv("AREA_DATA_DIR");
    std::string oldValue = oldAreaDataDir ? oldAreaDataDir : "";
    setenv("AREA_DATA_DIR", dataDir.c_str(), 1);

    auto result = runShellCommand(binary.string() + " ghidra 2>&1");

    if (oldAreaDataDir) setenv("AREA_DATA_DIR", oldValue.c_str(), 1);
    else unsetenv("AREA_DATA_DIR");

    std::error_code ec;
    fs::remove_all(dataDir, ec);

    EXPECT_EQ(result.exitCode, 1);
    EXPECT_NE(result.output.find("Usage: area ghidra"), std::string::npos);
    EXPECT_EQ(result.output.find("Failed to connect to database"), std::string::npos)
        << result.output;
}
