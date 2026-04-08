#include "util/file_io.h"

#include <unistd.h>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace area::util {

std::string selfExe() {
    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    buf[n] = '\0';
    std::string p(buf);

    auto del = p.find(" (deleted)");
    if (del != std::string::npos) p.resize(del);
    return p;
}

std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::string readFileOrThrow(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("could not open file: " + path);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace area::util
