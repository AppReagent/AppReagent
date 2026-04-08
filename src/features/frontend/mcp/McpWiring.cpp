#include "features/frontend/mcp/McpWiring.h"

#include <filesystem>

#include "features/frontend/mcp/McpServer.h"
#include "util/file_io.h"
#include "features/frontend/mcp/BuildFeature.h"
#include "features/frontend/mcp/ChatFeature.h"
#include "features/frontend/mcp/ScanFeature.h"
#include "features/frontend/mcp/ServerFeature.h"
#include "features/frontend/mcp/TestFeature.h"
#include "features/frontend/mcp/TuiFeature.h"

namespace fs = std::filesystem;

namespace area {

static std::string findBin(const std::string& workDir) {
    auto exe = util::selfExe();
    if (!exe.empty() && fs::exists(exe)) return exe;
    auto wb = workDir + "/area";
    if (fs::exists(wb)) return wb;
    return {};
}

int runMcpServer(const std::string& dataDir, const std::string& workDir) {
    auto sockPath = dataDir + "/area.sock";
    auto bin = findBin(workDir);

    mcp::McpServer server;

    features::chat::registerTools(server, sockPath);
    features::build::registerTools(server, workDir);
    features::server::registerTools(server, dataDir, workDir);
    features::test::registerTools(server, workDir);
    if (!bin.empty()) {
        features::scan::registerTools(server, bin, dataDir);
        features::tui::registerTools(server, bin, sockPath);
    }

    return server.run();
}

}  // namespace area
