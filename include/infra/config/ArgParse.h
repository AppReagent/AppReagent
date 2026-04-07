#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <optional>

#include "infra/config/Error.h"

namespace area {

class ArgParse {
public:
    ArgParse(int argc, char *argv[]);
    std::optional<Error> parse();
    std::optional<std::string> getPositionalArg(size_t idx) const;
    std::optional<std::string> getNamedArg(const std::string& key) const;

private:
    bool parsed_ = false;

    int argc_;
    char **argv_;

    std::vector<std::string> positionalArgs_;
    std::unordered_map<std::string, std::string> namedArgs_;
};

} // namespace area
