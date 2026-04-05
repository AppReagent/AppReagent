#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <filesystem>
#include <optional>

#include "ArgParse.h"
#include "Error.h"

namespace fs = std::filesystem;

namespace area {

std::optional<Error> scanCommandHandler(std::optional<std::string> dir) {
    if (!dir) {
        return area::Error::UnknownDirectory;
    }
    if (!fs::exists(*dir) || !fs::is_directory(*dir)) {
        return Error::UnknownDirectory;
    }
    for (const auto& entry : fs::recursive_directory_iterator(*dir)) {
        std::string path = entry.path().string();
        const int pathSuffix = 64;
        auto displayedPath = path.substr(path.length() > pathSuffix ? path.length() - pathSuffix : 0);

        std::cout << "[scan] TODO processing file ... " << displayedPath << std::endl;
    }
    return std::nullopt;
}

std::optional<Error> defaultCommandHandler(std::string programName) {
    std::cout << programName << " <command> <args...> <\"--key val\"...>" << std::endl;
    std::cout << "Valid commands: \"scan\"" << std::endl;
    return std::nullopt;
}

std::optional<Error> handleCommand(const ArgParse& ap) {
    auto cmd = ap.getPositionalArg(1);
    if (cmd == "scan") {
        std::optional<std::string> dir = ap.getNamedArg("dir").or_else([&] {
            return ap.getPositionalArg(2);
        });
        std::cout << "Scanning directory \"" << *dir << "\"..." << std::endl;
        return scanCommandHandler(dir);
    } else {
        std::string argv0 = *ap.getPositionalArg(0);
        return defaultCommandHandler(argv0);
    }
}

} // namespace area

int main(int argc, char *argv[]) {
    area::ArgParse ap(argc, argv);
    if (ap.parse()) {
        std::cerr << "Invalid CLI args. Positional args come before \"--named\" args" << std::endl;
        return 1;
    }
    auto err = handleCommand(ap);
    if (err) {
        std::cerr << "Command failed with error: " << area::toStr(err.value()) << std::endl;
        return 1;
    }
    return 0;
}
